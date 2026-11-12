# coldstore

**预测 → 规则 → 可逆执行。** 一个 Windows NTFS 上的省空间流水线：
先算出**哪些文件真的值得压**（实测，不猜），再按你写的规则动手，
每一步都可撤销、可回滚。

> **状态：0.1.0**，引擎层（001）+ 执行层（002，P1–P4）已落地。
> 工具**默认只读**；`--execute` 是唯一写盘开关。

---

## 目录

- [它做什么](#它做什么)
- [实测数据](#实测数据)
- [安装](#安装)
- [命令面](#命令面)
- [规则](#规则)
- [容器格式](#容器格式)
- [边界声明](#边界声明)
- [安全声明](#安全声明)
- [Windows 专属说明](#windows-专属说明)
- [开发](#开发)
- [许可证](#许可证)

---

## 它做什么

ColdStore 回答四个问题，然后**才**碰你的文件：

1. **哪些文件值得压缩？** —— 收益预测器在分层样本上**实测** zstd 压缩比，
   不相信扩展名（png 的真实压缩比是 100.0%，压完还大了 486 B）。
2. **哪些文件是重复的？** —— 大小分桶 + SHA-256 精确识别。
3. **现在什么该动、什么不该动？** —— 规则引擎（TOML）+ 冷热判定
   （`COLD` / `WARM` / `REBUILDABLE` / `UNKNOWN`，每个标签都带理由）。
4. **怎么保证能反悔？** —— 归档走**六步序列**（写容器 → 取回校验 SHA-256 →
   才移入隔离区 → 写 journal → 显式确认才真删），每一步都可重放、可撤销。

四件事之外，它什么都不做：**不删除、不改名、不整理**。

---

## 实测数据

> 全部为本机（Windows 11 / NTFS）**真实语料实测**，标注了日期与来源。
> 语料目录均为 `%TEMP%` 副本；玻璃三仓（glasssuite / glassdesk / glasspill）
> 只被读取，从未被写入或压缩。

### 归档容器（引擎层，2026-11-10）

| 语料 | 文件数 | 体积 | 实测 |
|---|---|---|---|
| `glasspill/src` | 27 | 36.4 MB | 独立帧 vs 固实 `tar.zst`：**−0.23%**（独立帧略小） |
| `glasspill` 归档 | 7 帧 | 136 MB | 取回**中间**一帧 19 MB：**58 ms**，SHA-256 逐字节一致 |

### 收益预测（zstd level 3，2026-11-10）

| 格式 | 实测压缩比 | 判定 |
|---|---|---|
| `.log` | 4.3% | 值得归档 |
| `.rlib` | 10.3% | 值得归档 |
| `.pdb` | 17.7% | 值得归档 |
| `.exe` | 30.6% | 值得归档 |
| `.mp3` | 92.9% | 不值得 |
| `.png` | **100.0%**（还大了 486 B） | **SKIP** —— 已压缩格式 |

### NTFS 透明压缩（2026-11-10 基线 / 2026-11-12 复测）

| 语料 | 文件数 | 逻辑体积 | 实测压缩比 | 耗时 |
|---|---|---|---|---|
| rust 构建产物（`compact` 基线，2026-11-10） | 120 | 5,474.62 MB | **2.3:1** | 114,670 ms（≈48 MB/s） |
| `rust-target` 规则命中集（2026-11-12，`FSCTL_SET_COMPRESSION`） | 18 | 653.6 MB | **2.50:1** | 2,474 ms |
| 整棵 debug 产物树（2026-11-12，同上） | 6,600 | 2.36 GB | **2.07:1** | 14,340 ms |

压缩比是**量出来的**：`GetCompressedFileSizeW` 取真实磁盘占用，不是估算。
可逆性实测：解除压缩后 `Compressed=False`，抽样 18 个文件 SHA-256 与压缩前
**逐字节一致**。

---

## 安装

从源码（0.1 唯一的发布渠道）：

```bash
git clone https://github.com/91-5/coldstore
cd coldstore
cargo build --release
# 可执行文件: target/release/coldstore.exe
```

需要 stable Rust 工具链。目标平台是 Windows 10/11（NTFS）。
引擎层在任何能编译 Rust 的地方都能编译，但卷/盘符逻辑是 Windows 专属的。

> **未签名提示**：本项目不提供代码签名。Windows SmartScreen 可能对
> 首次运行弹出未知发布者警告。请自行从源码构建，或核对发布页的校验和。

---

## 命令面

```bash
# ── 只读（默认）──────────────────────────────────────────
coldstore scan <path> [--json]              # 扫描，跳过项全部带原因
coldstore predict <path> [--sample N]       # 收益预测，不写任何盘
coldstore dedupe <path>                     # 重复检测，只出计划
coldstore plan <path> [--json]              # 一屏规划：归因+规则+冷热+节省
coldstore rule list|enable|disable|test     # 规则表 / 开关 / 试算
coldstore list <container> [--json]         # 列出容器内容
coldstore verify <container> [--threads N]  # 全量完整性校验

# ── 执行（--execute 是唯一写盘开关）────────────────────────
coldstore run --rule <name> [--execute] [--yes]
coldstore compress <path> [--execute]       # NTFS 透明压缩（可逆）
coldstore decompress <path> [--execute]     # 解除 NTFS 压缩
coldstore archive <path> -o <container>     # 写 .coldstore 容器
coldstore extract <container> --key <k> -d <dest>

# ── 隔离区与撤销──────────────────────────────────────────
coldstore quarantine list [--json]
coldstore quarantine restore <batch> [--remove-container]
coldstore quarantine delete <batch> --confirm   # 真删，硬约束 3 必须显式确认
coldstore quarantine recover <batch> --continue|--abort
coldstore undo <batch> [--keep-container]

# ── 手动标记──────────────────────────────────────────────
coldstore mark-cold <path> | mark-hot <path> | mark-clear <path>

# ── 交互界面──────────────────────────────────────────────
coldstore tui <path>                         # 扫描 → 分析 → 勾选 → 执行
```

**每个子命令都支持 `--json`** —— TUI 不可用时（无 TTY、CI、脚本），
JSON 是完整的出参面。TUI 与 CLI `--json` 读的是**同一个 plan 数据源**，
数字不会不一致。

`run` 与 `compress` / `decompress` **默认 dry-run**，`--execute` 才写盘。
批次超过 `confirm_threshold_gb`（默认 10 GB）还需 `--yes` 二次确认。

---

## 规则

规则是 TOML（`%APPDATA%\coldstore\config.toml`），四种动作：

```toml
[[rule]]
name = "rust-target"
priority = 10
match_path = ["**/target/debug/**", "**/target/release/**"]
match_ext = ["rlib", "rmeta", "pdb", "o", "exe", "dll"]
min_size_mb = 10
action = "ntfs_compress"      # ntfs_compress | archive | dedupe_hardlink | skip
enabled = false
```

- **动作只有四种**，刻意收窄，保证可预测。
- **优先级高者先匹配，先匹配先赢**（同优先级按名称排序，确定性）。
- **预测器持有最终否决权**：实测为 SKIP 的格式，即使命中 `archive` 规则也不执行。
- **内置规则全部 `enabled = false`** —— 默认什么都不做，你要什么自己开。

### 中文 Windows 生态规则包（内置）

通用磁盘分析工具认不出、但确实占地方的目录。**动作一律是 `skip`** ——
本工具只**识别 + 建议**，绝不代替你清理：

| 规则 | 识别什么 |
|---|---|
| `im-cache` | 微信 / QQ / WeChat 的聊天附件与图片缓存目录 |
| `game-platform-cache` | Steam / WeGame / Epic 的平台缓存与下载残留 |
| `netdisk-conflict` | 网盘同步冲突副本（`* - 冲突`）与临时文件（`*.tmp` 等） |

识别靠**路径模式**，不读取这些软件的内容。

### 冷热判定

| 标签 | 含义 |
|---|---|
| `COLD` | 超过阈值天数未修改（mtime 主信号） |
| `WARM` | 阈值内修改过 |
| `REBUILDABLE` | 位于已知可重建目录（`target/`、`node_modules/`、`.venv/`…） |
| `UNKNOWN` | 没有可用的 mtime |

**`LastAccessTime` 永不参与判定**（本机 `DisableLastAccess = 2`，
系统可能根本不更新它）。手动标记（`mark-cold` / `mark-hot`）优先级最高。

`REBUILDABLE` **只标记提示、绝不自动删** —— 工具会把**重建成本**（体积 +
重建命令 + 重建耗时估算）摆在你面前，删不删由你决定。

---

## 容器格式

`.coldstore` = 头部 + **每个文件一个独立 zstd 帧** + 自描述索引
（嵌在 zstd skippable frame 里）。索引是唯一事实来源；`.idx` sidecar 只是
派生缓存，两者不一致时**直接报错**，绝不静默取一个。

每个索引条目都存原文件的 **SHA-256**（0.1 起强制），取回时逐字节校验。
字段级规范见 [docs/format.md](docs/format.md)。

```bash
# 不装 coldstore 也能解出任意一帧（独立可验证）
zstd -D none -c archive.coldstore
```

---

## 边界声明

**它不做什么 —— 这比它做什么更重要：**

1. **不是通用磁盘分析器。** 找"谁占了空间"用 [WizTree](https://diskanalyzer.com/)、
   [gdu](https://github.com/dundeemt/gdu)、[czkawka](https://github.com/qarmin/czkawka)。
   ColdStore 的扫描只服务于"这个文件值不值得处理"这一个判断。
2. **不是文件内容整理器。** 它的 `skip` 动作**从不**移动、重命名或分类你的文件；
   按内容/用途整理文件用 [organize](https://github.com/tomersbdorganize/organize) 这类工具。
3. **不做 LLM / 语义分类。** 没有模型、没有猜测、没有云端推理。
   每一个"值得压"都来自**实测压缩比**和**字节级哈希**。
4. **只做「预测 + 可逆执行」。** 它的全部价值就是：动手前先算账，
   动手后能反悔。不做别的。

---

## 安全声明

- **默认只读。** 绝大多数命令不写盘；`--execute` 是**唯一**写盘开关。
- **绝不静默删除。** 任何删除都要 journal 记录 + 可撤销 + 显式确认。
  隔离区到期也**不会**自动删除（硬约束 3）。
- **归档 ≠ 释放空间。** 文件进了隔离区**仍然占着盘**；CLI 和 TUI 都会
  明说"隔离区仍占用 X GB"，只有 `quarantine delete --confirm` 之后
  空间才真正下降。
- **撤销是真的撤销。** 隔离期内被改过的源文件**绝不覆盖** —— 保留隔离区副本
  并报冲突（ADV-N3）。
- **完全本地。** 没有网络访问、没有遥测、没有更新检查、没有后台常驻。
  全流程离线可用。

---

## Windows 专属说明

- **依赖 NTFS 压缩。** `compress` / `decompress` 走
  `FSCTL_SET_COMPRESSION`，在 FAT32/exFAT/网络盘上会明确报错而不是假装成功。
- **`DisableLastAccess = 2`** 时 Windows 可能不更新 `LastAccessTime`，
  所以本工具**不用 atime** 做冷热判定（改用 mtime + 可重建目录 + 手动标记）。
- **不支持跨卷硬链接。** 去重执行跨卷必然失败，会明确报错跳过，
  **不做拷贝回退**（回退会变成"复制"，语义不同）。
- **压缩是有代价的。** NTFS 压缩吞吐约 48 MB/s，13.93 GB 约需 5 分钟。
  因此 `compress` 是**异步 + 可中断**的：Ctrl-C 会在文件边界安全停下，
  重新运行同一命令即可**续做**（已压缩的文件会被跳过）。
- **系统目录永不压缩。** `Program Files` / `Windows` / `System32` 等
  是硬编码排除项，`--force` 也覆盖不了。

---

## 开发

见 [CONTRIBUTING.md](CONTRIBUTING.md)。架构说明见
[docs/architecture.md](docs/architecture.md)，变更历史见
[CHANGELOG.md](CHANGELOG.md)。

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

---

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
