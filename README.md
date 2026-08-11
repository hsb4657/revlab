# REVLab — Windows PE 逆向工作流

> 面向 Windows PE 文件的全自动深度逆向分析平台(实验室合规测试用途)

REVLab 是一个针对 Windows PE 文件的可视化逆向工程工作流平台,覆盖**静态分析 → 壳检测 → 脱壳 → 反汇编 → 反编译 → 动态沙箱 → 网络抓包 → 聚合报告**的全流程,支持**自定义工作流编排**,并内置 **MCP Server** 可接入 Codex / Claude Code / Cursor 等 AI 智能体,以及 **OpenAI 兼容 AI 模型**用于智能报告解读与分析问答。

> ⚠️ **免责声明(重要,请务必阅读)**
>
> 1. 本工具仅供**网络安全研究人员、软件工程师**在**实验室环境**中,对**自己合规开发/合法拥有的软件**进行功能测试、安全研究与漏洞分析。
> 2. 严禁使用本工具分析、逆向、破解任何**未经授权的软件**、商业软件、恶意程序或受版权保护的作品。
> 3. 使用者须遵守所在地法律法规及软件许可协议。因滥用本工具导致的任何法律后果,均由使用者自行承担,项目作者及贡献者不承担任何责任。
> 4. 本工具的动态分析(沙箱运行样本、网络抓包)请在**完全隔离的受控环境**中执行,谨防运行恶意代码造成损失。
> 5. 项目默认**全程本地处理,无任何外部网络请求**(工具下载与 AI 调用除外,均由使用者显式触发)。

## 功能特性

| 模块 | 说明 |
| --- | --- |
| 🔍 指纹识别 | MD5 / SHA1 / SHA256 / SHA512 / **imphash** / ssdeep |
| 🧩 PE 静态解析 | DOS/NT/Optional 头、数据目录、节区表(含 **Shannon 熵**)、导入/导出表、延迟导入、TLS 回调、资源树、Rich Header、PDB 线索、数字签名验证 |
| 🔐 安全特性 | ASLR / DEP / SEH / CFG / 高熵 VA 等 |
| 📦 壳检测 | 30+ 特征库:UPX/ASPack/PECompact/Petite/MPRESS/VMProtect/Themida/Armadillo 等(节区名+熵+导入异常+签名字符串) |
| 📦 脱壳 | 已知壳自动解压(UPX 等)、通用内存转储(PE-sieve 集成)、IAT 修复、原始/脱壳双视图对比 |
| 🔬 反汇编 | Capstone x86/x64,入口/任意地址反汇编,Call/Jmp 交叉引用 Xref,函数启发式识别 |
| 🧩 反编译 | Ghidra Headless 集成,导出函数级 C 伪代码 |
| ⚡ 动态沙箱 | VMware 快照回滚 / 本机受控运行,进程树、文件、注册表、DNS 行为监控 |
| 🌐 网络抓包 | pktmon 采集 + **自研 pcap 解析**(连接聚合 / DNS / HTTP / TLS-SNI) |
| 📄 聚合报告 | JSON / HTML / Markdown 多维报告,原始 vs 脱壳对比 |
| ⚙️ 自定义工作流 | 阶段启停、排序、参数配置,**流水线实时可视化**(状态/耗时/日志),断点续跑 |
| 🤖 AI 解读 | 接入任意 OpenAI 兼容模型,智能报告解读、逆向问答 |
| 🔌 MCP Server | 15+ 分析工具,一键接入 Codex / Claude Code / Cursor / 自定义智能体 |

## 技术栈

- **后端**: Python 3.11 + FastAPI + SQLite(SQLAlchemy)
- **PE 解析**: pefile + lief(双引擎交叉校验)
- **反汇编**: Capstone(x86/x64)
- **反编译**: Ghidra Headless(需 Java 21)
- **脱壳**: UPX + PE-sieve(内存转储/IAT 修复)
- **抓包**: pktmon(Windows 自带)+ 自研 pcap 解析
- **前端**: 纯静态 HTML/CSS/JS(无构建步骤)
- **MCP**: mcp Python SDK(FastMCP)

## 快速开始

### 环境要求

- Windows 10/11(x64)
- Python 3.10+(需 `pip`)
- 可选:Java 21(Ghidra 反编译)、VMware Workstation(沙箱)、管理员权限(pktmon 抓包)

### 安装与启动

```bat
cd revlab
python -m pip install -r backend\requirements.txt

:: 启动后端 + MCP(首次会自动初始化数据库与默认工作流)
scripts\start.bat
```

打开浏览器访问 **http://127.0.0.1:8000**

### 使用流程

1. 在「样本库」上传自己的 PE 文件(或使用内置演示样本 `samples\revlab_sample.exe`)
2. 选择工作流(默认 `full-auto` 全自动),点击「全自动分析」
3. 观察顶部**流水线实时可视化**(识别 → 脱壳 → 反汇编 → 反编译 → 动态 → 报告)
4. 查看节区/导入/字符串/安全特性/壳判定,点击「反汇编」查看汇编,「报告」查看聚合报告
5. 「AI 解读」生成智能分析(需先配置 AI 模型)

### 生成演示样本

```bat
python samples\make_sample.py samples\revlab_sample.exe
```

### 下载外部工具(可选)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\download_tools.ps1 -SkipGhidra   # UPX + PE-sieve
powershell -ExecutionPolicy Bypass -File scripts\download_tools.ps1               # 含 Ghidra(~500MB)
```

## 自定义工作流

「工作流」页面支持:
- 勾选启用/禁用各分析阶段
- 上下移动调整执行顺序
- 配置每阶段参数(字符串最小长度、指令上限、动态超时、抓包时长等)
- 创建/保存/删除自定义工作流

流水线在「样本库」详情页**实时可视化**:每个阶段显示状态(待执行/执行中/完成/失败/跳过)、耗时与日志,支持断点续跑。

## AI 模型接入

「AI 模型」页面配置任意 **OpenAI 兼容**接口(Base URL / API Key / Model / Temperature),支持:
- 智能解读当前样本(基于全量分析上下文生成中文逆向报告)
- 逆向分析问答

## MCP 智能体接入

启动 MCP Server:

```bat
scripts\start-mcp.bat        :: HTTP 模式,端口 8765
python -m mcp_server.server  :: stdio 模式
```

### Codex

在 `~/.codex/config.toml` 或项目 `config.toml` 添加:

```toml
[mcp_servers.revlab]
command = "python"
args = ["-m", "mcp_server.server", "--port", "8765"]
```

### Claude Code

在项目根创建 `.mcp.json`:

```json
{
  "mcpServers": {
    "revlab": {
      "command": "python",
      "args": ["-m", "mcp_server.server", "--port", "8765"]
    }
  }
}
```

### Cursor

`Settings → MCP → Add`,类型选 Command,粘贴 `python -m mcp_server.server --port 8765`,或编辑 `.cursor/mcp.json`。

### MCP 工具清单(15 个)

`analyze_pe` · `get_pe_info` · `list_sections` · `disassemble` · `get_imports_exports` · `extract_strings` · `detect_packer` · `unpack_known` · `decompile_ghidra` · `run_dynamic` · `capture_network` · `generate_report` · `run_pipeline` · `list_samples` · `register_sample`

## 目录结构

```
revlab/
├── backend/            # FastAPI 后端 + 分析引擎
│   └── app/
│       ├── api/        # REST API
│       ├── core/       # 配置/数据库
│       ├── models/     # SQLAlchemy 模型
│       ├── services/   # 分析引擎(PE/壳/反汇编/沙箱/pcap/Ghidra/AI/报告)
│       └── orchestrator/  # 流水线状态机编排
├── mcp_server/         # MCP Server(FastMCP)
├── frontend/           # Web UI(纯静态)
├── ghidra/scripts/     # Ghidra 反编译导出脚本
├── samples/            # 演示样本 + 构造器
├── scripts/            # 启动/工具下载脚本
├── data/               # SQLite 数据库(运行时生成,git 忽略)
├── reports/            # 分析报告(运行时生成,git 忽略)
└── captures/           # 抓包 pcap(运行时生成,git 忽略)
```

## API 概览

| 端点 | 说明 |
| --- | --- |
| `POST /api/samples/upload` | 上传样本 |
| `POST /api/samples/{id}/analyze?workflow=xx` | 触发工作流分析 |
| `GET /api/samples/{id}/pipeline` | 流水线状态/阶段历史 |
| `GET /api/samples/{id}/disassembly` | 反汇编 |
| `GET /api/samples/{id}/report` | 报告(html/json/markdown) |
| `GET/POST /api/workflows` | 工作流 CRUD |
| `GET/POST /api/ai/config` · `/api/ai/summarize/{id}` | AI 配置与解读 |

完整 API 文档见启动后 **http://127.0.0.1:8000/docs**

## 合规与安全提示

- **仅限实验室环境 + 自研/合法授权软件**,禁止分析未授权软件或恶意程序。
- 动态分析与抓包请在**隔离 VM / 沙箱**中执行,运行结束后快照回滚。
- pktmon 抓包与沙箱运行需要管理员权限。
- 本项目本地化处理,不产生任何主动外联(工具下载、AI 调用由用户显式触发)。

## License

[MIT](LICENSE)

---

## 交流群

💬 **QQ 交流群: 835775657**(REVLab 逆向工作流)

欢迎进群交流 PE 逆向、脱壳、沙箱分析、AI 辅助逆向等话题。反馈问题、提需求、一起改进项目!

> 温馨提示:群内交流请遵守法律法规,仅讨论合规合法的安全研究与软件测试内容。
