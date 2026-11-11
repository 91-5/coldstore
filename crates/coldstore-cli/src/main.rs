//! ColdStore CLI front-end.
//!
//! Read-only semantics (ADV-N4): every command defaults to read-only;
//! `--execute` (introduced with the execution commands) is the *only*
//! write switch. Error output always carries path + reason.

mod cmd;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "coldstore",
    version,
    about = "ColdStore CLI —— 默认只读；--execute 是唯一写盘开关（ADV-N4）"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 只读扫描：枚举文件元数据，跳过项全部带原因
    Scan {
        path: PathBuf,
        /// 输出完整 JSON（供规则引擎/TUI 消费）
        #[arg(long)]
        json: bool,
        /// 显式允许跟随的 junction 路径前缀（默认不跟随）
        #[arg(long = "follow-junction", value_name = "PATH")]
        follow_junction: Vec<PathBuf>,
    },
    /// 收益预测：先算账再动手，不写任何盘
    Predict {
        path: PathBuf,
        /// 每类抽样预算上限（默认 8）
        #[arg(long)]
        sample: Option<usize>,
        /// 候选文件最小体积（KB，默认 256）
        #[arg(long, default_value_t = 256)]
        min_candidate_kb: u64,
        /// 输出完整 JSON（逐字节可复现）
        #[arg(long)]
        json: bool,
    },
    /// 去重识别：大小分桶 + SHA-256，只出计划、绝不执行（执行属执行层）
    Dedupe {
        path: PathBuf,
        /// 兼容 CLI 形态；dedupe 本就永远 plan-only
        #[arg(long)]
        plan_only: bool,
        /// 入桶最小体积（KB，默认 4）
        #[arg(long, default_value_t = 4)]
        min_size_kb: u64,
        /// 保留策略：oldest（默认）/ newest / 指定保留路径
        #[arg(long)]
        keep: Option<String>,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 归档：写入 .coldstore 容器（独立 zstd 帧 + 内嵌索引；不动源文件）
    Archive {
        path: PathBuf,
        /// 容器输出路径
        #[arg(short, long = "output")]
        output: PathBuf,
        /// 只归档这些扩展名（逗号分隔，如 rlib,pdb）
        #[arg(long = "include-ext", value_delimiter = ',')]
        include_ext: Vec<String>,
        /// 最小体积（KB，0=不限）
        #[arg(long, default_value_t = 0)]
        min_size_kb: u64,
        /// 同时写派生 sidecar .idx 缓存（内嵌索引仍为唯一事实源）
        #[arg(long)]
        sidecar: bool,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 单文件取回：只解压目标帧，SHA-256 校验后落盘
    Extract {
        container: PathBuf,
        /// 序号（数字）或路径（大小写不敏感）
        #[arg(long)]
        key: String,
        /// 显式目标路径（任意卷均可）
        #[arg(short = 'd', long = "dest")]
        dest: Option<PathBuf>,
        /// 还原到记录的原路径（跨卷将被拒绝——AV-5）
        #[arg(long)]
        to_original: bool,
    },
    /// 列出容器内容（索引 fail-closed）
    List {
        container: PathBuf,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 全量校验：逐帧解码 + SHA-256 比对
    Verify {
        container: PathBuf,
        /// 并行校验线程数（默认 = 全局线程池）
        #[arg(long)]
        threads: Option<usize>,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
    /// 规则引擎：list / enable / disable / test
    Rule {
        #[command(subcommand)]
        cmd: RuleCmd,
    },
    /// 一屏规划：占用归因 + 规则命中 + 预计节省 + 冷热分布（只读）
    Plan {
        path: PathBuf,
        /// 输出完整 JSON（逐字节可复现）
        #[arg(long)]
        json: bool,
    },
    /// 手动标记为冷（持久化，重启仍生效）
    /// 执行规则（默认 dry-run！--execute 才写盘——ADV-N4；ADV-N7 超阈需 --yes）
    Run {
        /// 扫描根目录
        path: PathBuf,
        /// 规则名
        #[arg(long)]
        rule: String,
        /// 真正执行（唯一写盘开关）
        #[arg(long)]
        execute: bool,
        /// ADV-N7 二次确认（命中量超阈值时必需）
        #[arg(long)]
        yes: bool,
        /// 归档容器路径（默认 %USERPROFILE%\.coldstorerchive\）
        #[arg(long)]
        container: Option<PathBuf>,
        /// 配置目录覆盖
        #[arg(long)]
        config_dir: Option<PathBuf>,
        /// 隔离区根目录覆盖
        #[arg(long = "quarantine-root")]
        quarantine_root: Option<PathBuf>,
        /// journal 目录覆盖
        #[arg(long = "journal-dir")]
        journal_dir: Option<PathBuf>,
    },
    /// 隔离区：list / delete（需 --confirm）/ recover（--continue|--abort）
    Quarantine {
        #[command(subcommand)]
        cmd: QuarantineCmd,
    },
    /// 撤销一个批次（还原到原路径；隔离期内被改的文件不覆盖——ADV-N3）
    Undo {
        batch: String,
    },
    MarkCold {
        path: PathBuf,
    },
    /// 手动标记为热（持久化，重启仍生效）
    MarkHot {
        path: PathBuf,
    },
    /// 清除手动标记
    MarkClear {
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum RuleCmd {
    /// 列出规则表
    List,
    /// 启用一条规则（写配置文件）
    Enable { name: String },
    /// 停用一条规则（写配置文件）
    Disable { name: String },
    /// 试算：每条规则会命中什么（只展示，不执行——B16）
    Test {
        path: PathBuf,
        /// 输出完整 JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// 列出批次（批次/来源/占用/保留期到期日——B11）
    List,
    /// 立即释放（真删；硬约束 3：必须 --confirm）
    Delete {
        batch: String,
        #[arg(long)]
        confirm: bool,
    },
    /// 恢复中断批次（B13）：--continue 续跑 / --abort 回滚
    Recover {
        batch: String,
        #[arg(long = "continue")]
        cont: bool,
        #[arg(long)]
        abort: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("错误: {err:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Scan {
            path,
            json,
            follow_junction,
        } => cmd::scan::run(cmd::scan::ScanArgs {
            path,
            json,
            follow_junction,
        }),
        Cmd::Predict {
            path,
            sample,
            min_candidate_kb,
            json,
        } => cmd::predict::run(cmd::predict::PredictArgs {
            path,
            sample,
            min_candidate_kb,
            json,
        }),
        Cmd::Dedupe {
            path,
            plan_only,
            min_size_kb,
            keep,
            json,
        } => cmd::dedupe::run(cmd::dedupe::DedupeArgs {
            path,
            plan_only,
            min_size_kb,
            keep,
            json,
        }),
        Cmd::Archive {
            path,
            output,
            include_ext,
            min_size_kb,
            sidecar,
            json,
        } => cmd::archive::run(cmd::archive::ArchiveArgs {
            path,
            output,
            include_ext,
            min_size_kb,
            sidecar,
            json,
        }),
        Cmd::Extract {
            container,
            key,
            dest,
            to_original,
        } => cmd::extract::run(cmd::extract::ExtractArgs {
            container,
            key,
            dest,
            to_original,
        }),
        Cmd::List { container, json } => cmd::list::run(cmd::list::ListArgs { container, json }),
        Cmd::Verify {
            container,
            threads,
            json,
        } => cmd::verify::run(cmd::verify::VerifyArgs {
            container,
            threads,
            json,
        }),
        Cmd::Rule { cmd } => cmd::rule::run(match cmd {
            RuleCmd::List => cmd::rule::RuleCmd::List,
            RuleCmd::Enable { name } => cmd::rule::RuleCmd::Enable { name },
            RuleCmd::Disable { name } => cmd::rule::RuleCmd::Disable { name },
            RuleCmd::Test { path, json } => cmd::rule::RuleCmd::Test { path, json },
        }),
        Cmd::Plan { path, json } => cmd::plan::run(cmd::plan::PlanArgs { path, json }),
        Cmd::Run {
            path,
            rule,
            execute,
            yes,
            container,
            config_dir,
            quarantine_root,
            journal_dir,
        } => cmd::run::run(cmd::run::RunArgs {
            path,
            rule,
            execute,
            yes,
            container,
            config_dir,
            quarantine_root,
            journal_dir,
        }),
        Cmd::Quarantine { cmd } => cmd::quarantine::run(match cmd {
            QuarantineCmd::List => cmd::quarantine::QuarantineCmd::List,
            QuarantineCmd::Delete { batch, confirm } => {
                cmd::quarantine::QuarantineCmd::Delete { batch, confirm }
            }
            QuarantineCmd::Recover { batch, cont, abort } => {
                cmd::quarantine::QuarantineCmd::Recover { batch, cont, abort }
            }
        }),
        Cmd::Undo { batch } => cmd::undo::run(cmd::undo::UndoArgs { batch }),
        Cmd::MarkCold { path } => cmd::mark::mark_cold(cmd::mark::MarkArgs { path }),
        Cmd::MarkHot { path } => cmd::mark::mark_hot(cmd::mark::MarkArgs { path }),
        Cmd::MarkClear { path } => cmd::mark::mark_clear(cmd::mark::MarkArgs { path }),
    }
}
