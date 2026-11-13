//! `coldstore tui` — the interactive terminal interface (card D6).
//!
//! ## What the TUI is (and is not)
//!
//! The TUI is a **view over the same data source** as `coldstore plan` and
//! a **front-end over the same execution path** as `coldstore run`:
//!
//! - the plan comes from [`super::plan::build`] — the very function
//!   `coldstore plan --json` serializes. The TUI and the CLI therefore
//!   cannot drift apart (card D6 / B-tui: "CLI --json 与 TUI 出参一致");
//! - the execution goes through [`super::run::plan_run`] +
//!   [`super::run::execute_run`] — the audited sequence functions
//!   (`quarantine::archive_batch`, the NTFS compression batch). **The TUI
//!   itself never touches a user file** — it selects and it reports.
//!
//! ## Reliability over showmanship
//!
//! The CLI's `--json` output is the contract; the TUI is a convenience.
//! That is why the rendering lives in [`render_frame`], which is backend
//! agnostic: the smoke test drives it with ratatui's `TestBackend`
//! (no TTY required), and `--render-once` / `--smoke` expose the same
//! path to scripts.

use std::io;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use coldstore_core::predict::format_bytes;

use super::plan::{self, PlanReport};

pub struct TuiArgs {
    pub path: PathBuf,
    pub config_dir: Option<PathBuf>,
    /// Render one frame to stdout and exit (no TTY needed).
    pub render_once: bool,
    /// Render one frame, then simulate pressing `q` and exit.
    pub smoke: bool,
}

/// The TUI's own state. It holds **no** filesystem handles and performs no
/// mutation — it only carries what the shared plan already computed.
pub struct TuiState {
    pub report: PlanReport,
    /// Index of the highlighted analysis row.
    pub cursor: usize,
    /// Rows the user selected for execution.
    pub selected: Vec<usize>,
    /// Last execution outcome (human text).
    pub status: String,
}

/// Which rows the TUI offers for execution: the rules the plan found —
/// one entry per rule hit, so the user picks a *rule* (which is what
/// `run --rule` takes), not individual files.
pub struct RuleChoice {
    pub rule: String,
    pub action: String,
    pub files: u64,
    pub bytes: u64,
    pub note: Option<String>,
}

/// Build the selectable rule choices from the plan (same source as the CLI).
pub fn rule_choices(report: &PlanReport) -> Vec<RuleChoice> {
    report
        .rule_hits
        .iter()
        .map(|h| RuleChoice {
            rule: h.rule_name.clone(),
            action: h.action.as_display().to_string(),
            files: h.files,
            bytes: h.bytes,
            note: h.note.clone(),
        })
        .collect()
}

pub fn run(args: TuiArgs) -> Result<()> {
    let report = plan::build(&args.path, args.config_dir.as_deref())?;
    let mut state = TuiState {
        report,
        cursor: 0,
        selected: Vec::new(),
        status: "就绪 · ↑/↓ 移动 · 空格勾选 · Enter 执行 · q 退出".to_string(),
    };

    if args.render_once || args.smoke {
        return render_to_stdout(&state);
    }

    interactive(&mut state, &args)
}

/// Render one frame into a buffer and print it — the scriptable path.
///
/// The frame is produced by the very same [`render_frame`] the interactive
/// loop uses, through ratatui's in-memory backend, so the smoke test
/// exercises the real rendering code (no TTY required).
fn render_to_stdout(state: &TuiState) -> Result<()> {
    let mut terminal = ratatui::Terminal::new(TestBackend::new(120, 32))
        .map_err(|e| anyhow::anyhow!("TUI 终端初始化失败: {e}"))?;
    let frame = terminal
        .draw(|f| render_frame(f, state))
        .map_err(|e| anyhow::anyhow!("TUI 渲染失败: {e}"))?;
    print!("{}", buffer_to_text(frame.buffer, frame.area));
    io::stdout().flush()?;
    Ok(())
}

/// Dump a rendered buffer as plain text.
///
/// A wide glyph (CJK) occupies two buffer cells: the second one is a
/// padding cell. A real terminal prints the glyph once; a naive cell dump
/// would print it once *plus* the padding — so the padding cells are
/// dropped here, using the same column arithmetic the terminal uses.
pub fn buffer_to_text(buffer: &ratatui::buffer::Buffer, area: Rect) -> String {
    use unicode_width::UnicodeWidthStr;
    let mut out = String::new();
    for y in 0..area.height {
        let mut column = 0u16;
        let mut line = String::new();
        for x in 0..area.width {
            let Some(cell) = buffer.cell((x, y)) else {
                continue;
            };
            if column > x {
                // Padding cell of a wide glyph — the terminal prints
                // nothing here.
                continue;
            }
            let symbol = cell.symbol();
            line.push_str(symbol);
            column += symbol.width().max(1) as u16;
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// The interactive loop (needs a real terminal).
fn interactive(state: &mut TuiState, args: &TuiArgs) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let res = event_loop(&mut terminal, state, args);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn event_loop(
    terminal: &mut ratatui::Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
    args: &TuiArgs,
) -> Result<()> {
    loop {
        terminal.draw(|f| render_frame(f, state))?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => break,
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                        (KeyCode::Up, _) => state.cursor = state.cursor.saturating_sub(1),
                        (KeyCode::Down, _) => {
                            let max = state.report.analysis.len().saturating_sub(1);
                            if state.cursor < max {
                                state.cursor += 1;
                            }
                        }
                        (KeyCode::Char(' ') | KeyCode::Char('x'), _) => {
                            if !state.selected.contains(&state.cursor) {
                                state.selected.push(state.cursor);
                                state.selected.sort_unstable();
                            } else {
                                state.selected.retain(|i| *i != state.cursor);
                            }
                        }
                        (KeyCode::Enter, _) => {
                            execute_selected(state, args)?;
                        }
                        (KeyCode::Char('r'), _) => {
                            state.report = plan::build(&args.path, args.config_dir.as_deref())?;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

/// Execute the selected analysis rows via the shared run path.
///
/// The selection maps a row back to its governing rule; the actual work
/// is done by `run::execute_run`, i.e. by the audited sequence functions.
fn execute_selected(state: &mut TuiState, args: &TuiArgs) -> Result<()> {
    let mut done = 0usize;
    for idx in state.selected.clone() {
        let Some(row) = state.report.analysis.get(idx) else {
            continue;
        };
        let Some(rule) = row.rule.clone() else {
            state.status = format!("第 {idx} 行不受任何规则约束——没有可执行的动作");
            continue;
        };
        if row.action.as_deref() == Some("skip") {
            state.status = format!("规则 {rule} 的动作是 skip（显式保护）——不执行");
            continue;
        }
        let run_args = super::run::RunArgs {
            path: args.path.clone(),
            rule: rule.clone(),
            execute: true,
            yes: true,
            container: None,
            config_dir: args.config_dir.clone(),
            quarantine_root: None,
            journal_dir: None,
            json: false,
        };
        match super::run::execute_run(&run_args) {
            Ok(outcome) => {
                done += 1;
                state.status = format!("规则 {rule} 执行完成: {}", outcome_summary(&outcome));
            }
            Err(err) => {
                state.status = format!("规则 {rule} 执行失败: {err:#}");
                break;
            }
        }
    }
    if done == 0 && state.status.starts_with("就绪") {
        state.status = "没有勾选任何可执行的行".to_string();
    }
    Ok(())
}

fn outcome_summary(outcome: &super::run::RunOutcome) -> String {
    use super::run::RunOutcome;
    match outcome {
        RunOutcome::Archive { files, bytes, .. } => {
            format!("{files} 个文件已归档（{}）", format_bytes(*bytes))
        }
        RunOutcome::NtfsCompress { stats } => {
            format!(
                "{} 个文件已压缩（{:.2}:1）",
                stats.files_processed,
                stats.ratio()
            )
        }
        RunOutcome::NothingToDo { reason } => reason.clone(),
    }
}

/// The whole frame. Backend agnostic on purpose — the smoke test drives
/// exactly this function.
pub fn render_frame(f: &mut Frame, state: &TuiState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // header
            Constraint::Min(5),    // body
            Constraint::Length(4), // status
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_body(f, chunks[1], state);
    render_status(f, chunks[2], state);
}

fn render_header(f: &mut Frame, area: Rect, state: &TuiState) {
    let r = &state.report;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" coldstore · 规划（只读，与 coldstore plan --json 同源） ");
    let text = vec![
        Line::from(format!("路径: {}", r.root)),
        Line::from(format!(
            "占用: {} / {} 个文件   规则 {} 条（启用 {}）   预计可省 {} – {}",
            format_bytes(r.scanned_bytes),
            r.scanned_files,
            r.rules_total,
            r.rules_enabled,
            format_bytes(r.prediction.est_savings_low),
            format_bytes(r.prediction.est_savings_high)
        )),
    ];
    f.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn render_body(f: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);
    render_analysis(f, chunks[0], state);
    render_side(f, chunks[1], state);
}

fn render_analysis(f: &mut Frame, area: Rect, state: &TuiState) {
    let r = &state.report;
    let items: Vec<ListItem> = r
        .analysis
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let marked = if state.selected.contains(&i) {
                "[x]"
            } else {
                "[ ]"
            };
            let cursor = if i == state.cursor { ">" } else { " " };
            let saving = if row.est_savings_high > 0 {
                format!(
                    "{} – {}",
                    format_bytes(row.est_savings_low),
                    format_bytes(row.est_savings_high)
                )
            } else {
                "—".to_string()
            };
            let rule = row.rule.clone().unwrap_or_else(|| "-".to_string());
            ListItem::new(Line::from(vec![
                Span::raw(format!("{cursor}{marked} ")),
                Span::styled(
                    format!("{:<11}", row.temperature),
                    Style::default().fg(temp_color(&row.temperature)),
                ),
                Span::raw(format!(" {:<9}", row.ext)),
                Span::raw(format!(" {:>5} 个", row.files)),
                Span::raw(format!(" {:>10} ", format_bytes(row.bytes))),
                Span::raw(format!(" 可省 {saving:<20}")),
                Span::styled(
                    format!(" {rule}"),
                    Style::default().add_modifier(Modifier::DIM),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" 分析明细（标签 · 理由 · 预计节省） "),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ratatui::widgets::ListState::default();
    list_state.select(Some(state.cursor));
    f.render_stateful_widget(list, area, &mut list_state);
}

fn render_side(f: &mut Frame, area: Rect, state: &TuiState) {
    let r = &state.report;
    let mut lines: Vec<Line> = Vec::new();

    // Rule hits — what `run --execute` would act on (card D6: the TUI shows
    // the rule hit, not just the files).
    let choices = rule_choices(r);
    if !choices.is_empty() {
        lines.push(Line::from(Span::styled(
            "规则命中",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for c in &choices {
            lines.push(Line::from(vec![
                Span::raw(format!("  {:<20}", c.rule)),
                Span::styled(
                    format!("{:<16}", c.action),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(format!(" {:>6} 个 ", c.files)),
                Span::raw(format!("{:>10}", format_bytes(c.bytes))),
            ]));
            if let Some(note) = &c.note {
                lines.push(Line::from(Span::styled(
                    format!("    ↳ {note}"),
                    Style::default().add_modifier(Modifier::DIM),
                )));
            }
        }
        lines.push(Line::from(""));
    }

    lines.push(Line::from(Span::styled(
        "冷热分布",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    for t in &r.coldness {
        lines.push(Line::from(format!(
            "  {:<12} {:>6} 个  {:>10}",
            t.temperature.as_display(),
            t.files,
            format_bytes(t.bytes)
        )));
    }
    if !r.manual_marks.is_empty() {
        lines.push(Line::from(Span::styled(
            "手动标记",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for m in &r.manual_marks {
            lines.push(Line::from(format!("  [{}] {}", m.mark, m.reason)));
        }
    }
    if !r.rebuildable.is_empty() {
        lines.push(Line::from(Span::styled(
            "可重建目录（重建成本可见；永不自动删）",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for g in &r.rebuildable {
            lines.push(Line::from(format!(
                "  {:<12} {:>10}  重建 ≈ {}",
                g.kind,
                format_bytes(g.bytes),
                coldstore_core::coldness::format_duration(g.rebuild_seconds_estimate)
            )));
        }
    }
    if !r.skip_examples.is_empty() {
        lines.push(Line::from(Span::styled(
            "预测器否决（不进入执行）",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for s in &r.skip_examples {
            lines.push(Line::from(format!("  [SKIP] {}", s.ext)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!("隔离区: {}", r.quarantine_note)));

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" 侧栏 "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_status(f: &mut Frame, area: Rect, state: &TuiState) {
    let r = &state.report;
    let selected_bytes: u64 = state
        .selected
        .iter()
        .filter_map(|i| r.analysis.get(*i))
        .map(|row| row.bytes)
        .sum();
    let gauge_ratio = if r.scanned_bytes == 0 {
        0.0
    } else {
        (selected_bytes as f64 / r.scanned_bytes as f64).clamp(0.0, 1.0)
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(area);
    f.render_widget(Gauge::default().ratio(gauge_ratio), rows[0]);

    let status = Paragraph::new(Line::from(vec![
        Span::raw(state.status.clone()),
        Span::styled(
            format!(
                "   已选 {} 行 / {}",
                state.selected.len(),
                format_bytes(selected_bytes)
            ),
            Style::default().add_modifier(Modifier::DIM),
        ),
    ]))
    .wrap(Wrap { trim: true });
    f.render_widget(status, rows[1]);
}

fn temp_color(t: &str) -> Color {
    match t {
        "COLD" => Color::Blue,
        "WARM" => Color::Yellow,
        "REBUILDABLE" => Color::Magenta,
        _ => Color::DarkGray,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn fixture(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coldstore-p4-tui-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("target/debug")).unwrap();
        std::fs::write(dir.join("target/debug/lib.rlib"), vec![1u8; 4096]).unwrap();
        std::fs::write(dir.join("plain.bin"), vec![2u8; 1024]).unwrap();
        dir
    }

    fn cfg_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "coldstore-p4-tui-cfg-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Render one frame into an in-memory backend and return the text.
    fn render_text(state: &TuiState) -> String {
        let mut terminal =
            ratatui::Terminal::new(TestBackend::new(120, 32)).expect("test terminal");
        let frame = terminal.draw(|f| render_frame(f, state)).expect("draw");
        super::buffer_to_text(frame.buffer, frame.area)
    }

    #[test]
    fn render_frame_shows_labels_reason_and_savings() {
        let dir = fixture("render");
        let cfg = cfg_dir("render-cfg");
        let report = plan::build(&dir, Some(&cfg)).expect("plan");
        let state = TuiState {
            report,
            cursor: 0,
            selected: Vec::new(),
            status: "就绪".to_string(),
        };

        let text = render_text(&state);
        assert!(!text.is_empty(), "frame must not be empty");
        assert!(text.contains("coldstore"), "header missing: {text}");
        assert!(
            text.contains("REBUILDABLE"),
            "temperature label missing: {text}"
        );
        assert!(text.contains("冷热分布"), "side panel missing: {text}");

        // The TUI and the CLI JSON are the same data source: the file count
        // the JSON reports must show up in the rendered header.
        let json = serde_json::to_string(&state.report).expect("json");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let files = v["scanned_files"].as_u64().expect("scanned_files");
        assert!(
            text.contains(&files.to_string()),
            "file count {files} missing from the frame: {text}"
        );

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&cfg).ok();
    }

    #[test]
    fn selecting_rows_tracks_bytes_and_savings() {
        let dir = fixture("select");
        let cfg = cfg_dir("select-cfg");
        let report = plan::build(&dir, Some(&cfg)).expect("plan");
        let mut state = TuiState {
            report,
            cursor: 0,
            selected: Vec::new(),
            status: "就绪".to_string(),
        };
        assert!(!state.report.analysis.is_empty(), "analysis rows expected");

        state.selected.push(0);
        let text = render_text(&state);
        assert!(text.contains("[x]"), "selection marker missing: {text}");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&cfg).ok();
    }
}
