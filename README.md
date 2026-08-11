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

### 工作流① 通用 PE 逆向(完整)
- 🔍 指纹识别:MD5 / SHA1 / SHA256 / SHA512 / **imphash** / ssdeep
- 🧩 PE 静态解析:DOS/NT/Optional 头、数据目录、节区表(含 **Shannon 熵**)、导入/导出表、延迟导入、TLS 回调、资源树、Rich Header、PDB 线索、数字签名验证
- 🔐 安全特性:ASLR / DEP / SEH / CFG / 高熵 VA 等
- 📦 壳检测:30+ 特征库(UPX/ASPack/PECompact/Petite/MPRESS/VMProtect/Themida/Armadillo 等)
- 📦 脱壳:已知壳自动解压(UPX)、通用内存转储(PE-sieve)、IAT 修复
- 🔬 反汇编:Capstone x86/x64 + Call/Jmp 交叉引用 Xref + 函数启发式识别
- 🧩 反编译:Ghidra Headless 集成,导出函数级 C 伪代码
- ⚡ 动态沙箱:VMware 快照回滚 / 本机受控运行,进程树/文件/注册表/DNS 监控
- 🌐 网络抓包:pktmon 采集 + 自研 pcap 解析(连接聚合/DNS/HTTP/TLS-SNI)
- ⚙️ 自定义工作流:阶段启停/排序/参数配置,流水线实时可视化,断点续跑

### 工作流② UE 虚幻引擎专项(独立)
- 🎮 输入 dump 后的 exe,自动/手动识别引擎版本(知识库 4.27 / 5.0~5.5)
- 📥 源码轻量拉取:按版本在 GitHub 镜像定位分支,raw 拉取少量关键头文件(几 KB,本地缓存,不克隆大仓库)
- 🗿 **三大件定位**:GNames / GObjects / GWorld / GEngine(特征字节签名扫描 12+ 内置 + 自定义签名 + 源码结构交叉校验)
- 🔍 **反射系统分析**:UObject/UClass/UFunction/FProperty 反射结构检测、混淆判定、运行时遍历方案
- 🔐 加密解密:先检测 FName/AES/高熵/壳;**未检测到加密则跳过解密**,检测到才输出 FNamePool 等解密方案
- 📄 UE 专项报告(HTML/MD/JSON)

### 工作流③ Unity 引擎专项(独立)
- 📂 输入**游戏文件夹绝对路径**,自主分析
- 🏗️ 目录扫描 / 版本识别(globalgamemanagers / UnityPlayer.dll / 版本串)/ 构建类型判定(Mono / IL2CPP)
- 📦 **DLL 程序集分析**:Data/Managed 各 dll(dnfile 解析命名空间/类型/方法,含 Assembly-CSharp.dll 等)+ GameAssembly.dll 分析
- 🧬 **IL2CPP metadata 分析**:global-metadata.dat(magic 0xFAB11BAF、版本、字符串表)
- 🔐 **Metadata 自动解密**:魔数恢复 / 常见 XOR / 内存 dump 辅助;检测到加密才解密,未加密直接解析
- 🛠️ **SDK Dump**(对齐 Il2CppDumper):生成 `Dump.cs` + `script.json` + C++ 头文件(`sdk_cpp/`)+ `sdk.json`
- 🎨 资源分析(UnityFS/UnityRaw/UnityWeb)+ 关键 API 字符串 + Unity 专项报告

### 通用能力
- 🗺️ **图化工作流 v3**(Vue Flow 画布):节点拖拽连线、**条件分支**、**审批节点**、**失败策略**(重试/跳过/终止)、单节点重跑/跳过、变量系统({{var}} 引用)、任务历史;预置模板(PE 全自动 / UE 专项 / Unity 专项)
- 🤖 AI 解读:接入任意 OpenAI 兼容模型,智能报告解读、逆向问答
- 🔌 MCP Server:23+ 分析工具,一键接入 Codex / Claude Code / Cursor / 自定义智能体
- 📂 **输出目录可配置**:报告/抓包/脱壳产物/SDK 可指定输出根目录(设置页)
- 📄 聚合报告:JSON / HTML / Markdown 多维报告

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

**① 通用 PE 分析**
1. 在「样本库」上传自己的 PE 文件(或使用内置演示样本 `samples\revlab_sample.exe`)
2. 选择工作流(默认 `full-auto` 全自动),点击「全自动分析」
3. 观察顶部**流水线实时可视化**(识别 → 脱壳 → 反汇编 → 反编译 → 动态 → 报告)
4. 查看节区/导入/字符串/安全特性/壳判定,点击「反汇编」查看汇编,「报告」查看聚合报告

**② UE 虚幻引擎专项**
1. 进入「UE 引擎」页,选择引擎版本(或自动识别)
2. 上传/选择 dump 后的 exe,点击「▶ 分析」
3. 观察阶段进度(版本→源码→三大件→反射→加密解密→报告)
4. 查看三大件地址、反射系统检测、加密/解密结果

**③ Unity 引擎专项**
1. 进入「Unity 引擎」页,输入游戏文件夹绝对路径
2. 点击「▶ 分析」,观察 9 阶段进度
3. 查看版本/构建类型/DLL 程序集/资源/metadata 解密/SDK dump(Dump.cs + C++ 头文件 + JSON)

**通用**
- 「AI 解读」生成智能分析(需先配置 AI 模型)
- 「设置」页可指定分析产物输出目录

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

### 图化工作流画布 v3(推荐,浏览器打开 **http://127.0.0.1:8000/wf/**)
参考 **DeterminFlow / n8n / Temporal / Airflow / LangGraph** 设计的图化引擎:

- **节点拖拽连线**:分析节点(PE识别/壳检测/脱壳/反汇编/字符串/UE分析/Unity分析/SDK dump)+ 控制节点(条件分支/审批/脚本/报告)
- **条件分支**:如「{{packer_detect.packed}} == true」→ 脱壳,否则走默认分支
- **审批节点**:运行样本等危险操作前人工确认,可驳回
- **失败策略**:每节点 `on_fail`(abort/skip/retry)+ `retry_count`
- **变量系统**:节点输出写入变量池,参数用 `{{var}}` 引用;支持 `AND/OR/NOT` 与比较运算
- **执行控制**:单节点重跑 / 跳过 / 停止任务,节点状态实时着色
- **预置模板**:`pe-auto`(识别→壳检测→条件脱壳→反汇编→报告)、`ue-special`、`unity-special`

### 线性工作流(兼容,原「工作流」页)
- 阶段启停/排序/参数,流水线实时可视化,断点续跑

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

### MCP 工具清单(23 个)

**PE 通用**:`analyze_pe` · `get_pe_info` · `list_sections` · `disassemble` · `get_imports_exports` · `extract_strings` · `detect_packer` · `unpack_known` · `decompile_ghidra` · `run_dynamic` · `capture_network` · `generate_report` · `run_pipeline` · `list_samples` · `register_sample`

**UE 引擎**:`ue_versions` · `ue_analyze` · `ue_fetch_source` · `ue_report`

**Unity 引擎**:`unity_analyze` · `unity_status` · `unity_dump_sdk` · `engine_analyses`

## 使用的开源项目 / 参考项目

REVLab 深度使用了以下开源项目,并向其作者致敬:

### 核心依赖(直接使用)
| 项目 | 用途 |
| --- | --- |
| [FastAPI](https://github.com/fastapi/fastapi) + [Uvicorn](https://github.com/encode/uvicorn) | Web 后端框架 |
| [pefile](https://github.com/erocarrera/pefile) | PE 文件解析(导入表/imphash 等) |
| [LIEF](https://github.com/lief-project/LIEF) | PE 交叉解析与重建 |
| [Capstone](https://github.com/capstone-engine/capstone) | x86/x64 反汇编引擎 |
| [SQLAlchemy](https://github.com/sqlalchemy/sqlalchemy) | ORM + SQLite 持久化 |
| [mcp (Python SDK)](https://github.com/modelcontextprotocol/python-sdk) / FastMCP | MCP Server 实现 |
| [psutil](https://github.com/giampaolo/psutil) | 进程树/行为监控 |
| [dnfile](https://github.com/malcharl/dnfile) | .NET 程序集(Unity Mono 模式)元数据解析 |

### 外部工具(可选,脚本自动下载)
| 项目 | 用途 |
| --- | --- |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Headless 反编译(需 Java 21) |
| [PE-sieve](https://github.com/hasherezade/pe-sieve) | 进程内存转储 + IAT 修复(通用脱壳) |
| [UPX](https://github.com/upx/upx) | UPX 壳解压 |

### 参考项目(功能/签名/输出格式参考,致敬其工作)
| 项目 | 参考内容 |
| --- | --- |
| [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) | Unity SDK dump 输出格式(Dump.cs / script.json)对齐参考 |
| [UnrealDumper](https://github.com/nneonneo/UnrealDumper) | UE 三大件(GNames/GObjects/GWorld)定位思路参考 |
| [UE4Dumper](https://github.com/kp7742/UE4Dumper) | UE 三大件特征签名与结构偏移参考 |
| [Wireshark](https://www.wireshark.org/) | pcap 格式规范参考(本项目为自研解析,不依赖) |

> 注:UE/Unity 引擎本身的源码与二进制为 Epic Games / Unity Technologies 版权所有。本项目仅基于公开的逆向工程社区知识与合规测试目的进行交互分析,不包含引擎源码。

## 目录结构

```
revlab/
├── backend/            # FastAPI 后端 + 分析引擎
│   └── app/
│       ├── api/        # REST API(PE / UE / Unity / 工作流 / AI / 设置)
│       ├── core/       # 配置/数据库(输出目录可配置)
│       ├── models/     # SQLAlchemy 模型(含 EngineAnalysis 引擎分析记录)
│       ├── services/   # 分析引擎
│       │   ├── ue/         # UE 虚幻引擎专项(版本/签名/源码轻量拉取/分析器)
│       │   ├── unity/      # Unity 专项(检测/程序集/il2cpp/metadata解密/SDK dump)
│       │   └── ...         # PE/壳/反汇编/沙箱/pcap/Ghidra/AI/报告/引擎执行器
│       └── orchestrator/   # 通用 PE 流水线状态机编排
├── mcp_server/         # MCP Server(FastMCP,23 工具)
├── frontend/           # Web UI(纯静态:样本库/UE/Unity/工作流/反汇编/AI/MCP/设置)
├── ghidra/scripts/     # Ghidra 反编译导出脚本
├── samples/            # 演示样本 + 构造器(PE/UE/Unity)
├── scripts/            # 启动/工具下载脚本
├── data/               # SQLite 数据库/设置(运行时生成,git 忽略)
├── reports/            # 分析报告(pe/ue/unity,运行时生成,git 忽略)
├── captures/           # 抓包 pcap(运行时生成,git 忽略)
└── sdk/                # Unity SDK dump(运行时生成,git 忽略)
```

## API 概览

| 端点 | 说明 |
| --- | --- |
| `POST /api/samples/upload` | 上传样本 |
| `POST /api/samples/{id}/analyze?workflow=xx` | 触发通用 PE 工作流分析 |
| `GET /api/samples/{id}/pipeline` | 流水线状态/阶段历史 |
| `GET /api/samples/{id}/disassembly` | 反汇编 |
| `GET /api/samples/{id}/report` | 报告(html/json/markdown) |
| `GET/POST /api/workflows` | 工作流 CRUD |
| `GET/POST /api/wf2` · `/api/wf2/spec` | 图化工作流 CRUD / 节点注册表 |
| `POST /api/wf2/{id}/tasks` · `.../tasks/{tid}/run` | 图工作流任务运行 |
| `POST /api/wf2/tasks/{tid}/nodes/{nid}/retry` · `/skip` | 单节点重跑/跳过 |
| `POST /api/wf2/tasks/{tid}/nodes/{nid}/resolve-approval` | 审批决策 |
| `POST /api/engine/{engine}/analyze` | 引擎专项分析(engine=ue/unity,传 path 或 sample_id) |
| `GET /api/engine/{engine}/analyses` · `.../analyses/{id}` | 引擎分析历史/详情(含阶段进度) |
| `GET /api/ue/versions` · `/api/ue/signatures` | UE 版本知识库 / 签名库 |
| `GET/POST /api/ai/config` · `/api/ai/summarize/{id}` | AI 配置与解读 |
| `GET/POST /api/settings` | 全局设置(输出目录) |

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
