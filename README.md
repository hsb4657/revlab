# REVLab — Windows PE 逆向工作流

> 面向 Windows PE 文件的全自动深度逆向分析平台(实验室合规测试用途)

REVLab 是一个针对 Windows PE、UE 与 Unity 样本的可视化分析工作台,覆盖**静态分析 → 壳检测 → 脱壳 → 反汇编 → 反编译 → 动态沙箱 → 网络抓包 → 聚合报告**的全流程。所有主要操作都在主站 `http://127.0.0.1:8000/` 内完成:内嵌图工作流画布、实时节点状态、产物中心、AI 对话和模型设置共享同一入口。平台支持**无限自定义工作流与节点组合**,并内置 **MCP Server** 可接入 Codex / Claude Code / Cursor 等 AI 智能体。

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
- 🤖 **AI 辅助分析**:工作流内置 `pe_ai_assist` 节点,AI 综合壳/保护/可疑点判定并给出逆向建议;**可联网搜索壳特征、DLL/函数功能、可疑行为模式**
- 📄 PE 专项报告(HTML/MD/JSON,含 AI 辅助分析章节)
- ⚙️ 自定义工作流:阶段启停/排序/参数配置,流水线实时可视化,断点续跑

### 工作流② UE 虚幻引擎专项(独立)
- 🎮 输入 dump 后的 exe,自动/手动识别引擎版本(知识库 4.27 / 5.0~5.8)
- 📥 源码轻量拉取:按版本在 GitHub 镜像定位分支,raw 拉取少量关键头文件(几 KB,本地缓存,不克隆大仓库)
- 🗿 **三大件定位**:GNames / GObjects / GWorld / GEngine(特征字节签名扫描 + **字符串交叉引用分析** + 地址、置信度、静态证据、运行时复核清单)
- 🔤 **字符串交叉引用**:通过 GWorld/GEngine/UEngine 等关键字符串找到引用代码,提取全局变量地址;自动检测关键字符串可用性(报告哪些被剥离)
- 🏷️ **FName / GNames 算法候选**:FNamePool 与直数组模型、分块索引/条目头/宽字符/长度位的候选公式和验证状态
- 🔍 **反射系统分析**:UObject / UClass / UFunction / FProperty 反射结构、字段偏移、布局候选、混淆判定和运行时遍历计划
- 🔐 保护与解密证据:先检测壳、节熵、加密线索与 FName 线索;输出明确的 `confirmed` / `candidate` / `unconfirmed` 状态，不把静态候选伪装成已验证地址
- 🤖 **AI 辅助分析**:工作流内置 `ue_ai_assist` 节点,AI 综合静态证据判定三大件精确地址、GetName 算法、解密算法;支持外部 AI 通过 MCP 驱动(无需配置内部 LLM)
- 📄 UE 专项报告(HTML/MD/JSON,含 AI 辅助分析章节)

### 工作流③ Unity 引擎专项(独立)
- 📂 输入**游戏文件夹绝对路径**,自主分析
- 🏗️ 目录扫描 / 版本识别(globalgamemanagers / UnityPlayer.dll / 版本串)/ 构建类型判定(Mono / IL2CPP)
- 📦 **DLL 程序集分析**:Data/Managed 各 dll(dnfile 解析命名空间/类型/方法,含 Assembly-CSharp.dll 等)+ GameAssembly.dll 分析
- 🧬 **IL2CPP metadata 分析**:global-metadata.dat(magic 0xFAB11BAF、版本、字符串表)
- 🔐 **Metadata 状态与恢复**:区分 `plain`、`decrypted`、`header_repaired`、损坏/未知;XOR 等真实恢复必须通过二次结构校验，单纯头部修复不会被标为解密
- 🛠️ **SDK Dump**(对齐 Il2CppDumper):仅在已验证的明文或真实解密 Metadata 上生成 `Dump.cs` + `script.json` + C++ 头文件(`sdk_cpp/`)+ `sdk.json` + 输入 DLL/Metadata + manifest
- 🤖 **AI 辅助分析**:工作流内置 `unity_ai_assist` 节点,AI 综合构建类型/Metadata 状态/SDK 完整性给出风险提示;**可联网搜索 Unity 版本的 IL2CPP metadata 格式、global-metadata.dat 结构、已知保护方案**
- 🎨 资源分析(UnityFS/UnityRaw/UnityWeb)+ 关键 API 字符串 + Unity 专项报告(含 AI 辅助分析章节)

### 通用能力
- 🗺️ **图化工作流 v3**(主站内嵌 Vue Flow 画布):节点拖拽连线、**多条件分支**、**审批节点**、**失败策略**(重试/跳过/终止)、单节点重跑/跳过、变量系统({{var}} 引用)、任务历史;预置模板(PE 全自动 / UE 专项 / Unity 专项)
- 🤖 **AI 辅助分析节点**:三个工作流均内置专项 AI 节点(`pe_ai_assist` / `ue_ai_assist` / `unity_ai_assist`),综合前序节点证据由 AI 给出结论;**AI 可联网搜索 UE/Unity 源码结构、壳特征、保护方案等信息**;通用 `ai_analyze` 节点可拖入任意工作流(引用 {{变量}} 让 AI 分析前序结果);支持外部 AI 通过 MCP 驱动(无需配置内部 LLM);AI 结论自动写入报告
- 🤖 **AI 工作台**:多会话持久化、新建/重命名/删除、上下文压缩、会话级模型与思考强度;可根据自然语言生成可编辑、可校验的 PE / UE / Unity 工作流草稿
- 🧠 **模型预设**:OpenAI、DeepSeek、通义、智谱、Kimi、SiliconFlow、Gemini、OpenRouter、Groq、Together、Mistral、Perplexity、Azure OpenAI、Anthropic 兼容代理、Ollama、LM Studio
- 🔌 MCP Server:37 个工具(含完整工作流控制),一键接入 Codex / Claude Code / Cursor / 自定义智能体;**外部 AI 可通过 MCP 完全驱动工作流**(创建任务→运行→读取证据→提交结论→重试节点→生成报告)
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

首次克隆后执行一键配置。它会创建项目专用 `.venv`、安装后端和 MCP 依赖、构建内嵌工作流编辑器，并在启动前输出 Python / Node / Ghidra / UPX / PE-sieve 的状态：

```powershell
cd revlab
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

完整环境（自动补齐缺失的 Python、Node.js、Java 21，下载 Ghidra 与可选 PE 工具，并运行验证）使用：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -All -PersistEnv
```

`-All` 包含较大的 Ghidra 下载；只需要反编译能力时也可稍后单独执行 `-InstallGhidra -PersistEnv`。详细选项和离线/排错说明见 [docs/SETUP.md](docs/SETUP.md)。

配置完成后启动后端与 MCP：

```bat
scripts\start.bat
```

打开浏览器访问 **http://127.0.0.1:8000**

### 安全默认值与可选能力

服务默认只允许本机访问 API，CORS 仅包含本地 UI；远程绑定时必须在请求头
中提供 `X-REVLab-Token`，并设置 `REVLAB_API_TOKEN`。服务启动不会自动下载工具或
Python 依赖，`REVLAB_AUTO_SETUP=1` 只会在显式启用后由环境页面触发安装。

动态样本执行和自定义 Python/Bat/命令节点默认关闭：

```text
REVLAB_SANDBOX_VM=1                 # 推荐：配置 VMware 快照隔离
REVLAB_VM_VMX=C:\Lab\revlab.vmx
REVLAB_VM_SNAPSHOT=clean
REVLAB_ALLOW_HOST_EXECUTION=1       # 仅隔离实验机，改为本机执行
REVLAB_ENABLE_UNSAFE_NODES=1        # 仅需要脚本/命令节点时开启
```

Ghidra、UPX、PE-sieve、Il2CppDumper、pktmon 和 Node.js 都是按功能启用的可选能力。
缺失时核心静态分析仍可运行，具体节点会返回明确的 `available`、`blocked_by_policy`
或能力缺失状态，不会把候选地址、未执行的脱壳或未抓到的网络流量伪装成已验证结果。
首次升级旧版 `data/revlab.db` 时，应用会自动执行只增加字段的兼容迁移。

项目按 MIT 许可证开源；本地构建、测试和贡献约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。

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
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -InstallTools
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -InstallGhidra -PersistEnv
```

## 自定义工作流

### 图化工作流画布 v3(推荐:主站「工作流」页)
参考 **DeterminFlow / n8n / Temporal / Airflow / LangGraph** 设计的图化引擎:

- **节点拖拽连线**:分析节点(PE识别/壳检测/脱壳/反汇编/字符串/UE分析/Unity分析/SDK dump)+ 控制节点(条件分支/审批/脚本/报告)+ **AI 辅助节点**(通用 `ai_analyze`、UE 专项 `ue_ai_assist`)
- **条件分支**:如「{{packer_detect.packed}} == true」→ 脱壳,否则走默认分支
- **审批节点**:运行样本等危险操作前人工确认,可驳回
- **失败策略**:每节点 `on_fail`(abort/skip/retry)+ `retry_count`
- **变量系统**:节点输出写入变量池,参数用 `{{var}}` 引用;支持 `AND/OR/NOT` 与比较运算
- **执行控制**:单节点重跑 / 跳过 / 停止任务,节点状态实时着色
- **预置模板**:`pe-auto`(识别→壳检测→条件脱壳→反汇编→报告)、`ue-special`、`unity-special`; 三者可在主站中一键切换
- **自由扩展**:从节点库创建任意数量的工作流，添加多个条件分支、变量、审批、脚本、命令和报告节点；AI 草稿载入后仍可在同一画布继续编辑

### 线性工作流(兼容,原「工作流」页)
- 阶段启停/排序/参数,流水线实时可视化,断点续跑

## AI 模型接入

「AI 模型」页面与「对话」页面分开管理。模型设置支持厂商预设和任意 **OpenAI 兼容**接口(Base URL / API Key / Model / Temperature); 对话页面支持:
- 多会话历史、新建、重命名、删除和上下文压缩
- 会话级模型选择与快速 / 平衡 / 深度三档思考强度
- 智能解读当前样本(基于可用分析上下文生成报告)、分析问答和生成可编辑工作流草稿
- **工作流内 AI 辅助**:在「工作流」画布拖入「AI 分析节点」或「UE AI 辅助分析」节点,引用前序节点输出(如 `{{packer_detect}}`),让模型辅助判定结论;UE 模板已内置 AI 节点用于判定三大件精确地址、GetName 与解密算法(未配置模型时节点自动跳过)

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

### MCP 工具清单(37 个)

**PE 通用**:`analyze_pe` · `get_pe_info` · `list_sections` · `disassemble` · `get_imports_exports` · `extract_strings` · `detect_packer` · `unpack_known` · `decompile_ghidra` · `run_dynamic` · `capture_network` · `generate_report` · `run_pipeline` · `list_samples` · `register_sample`

**UE 引擎**:`ue_versions` · `ue_analyze` · `ue_fetch_source` · `ue_report`

**Unity 引擎**:`unity_analyze` · `unity_status` · `unity_dump_sdk` · `engine_analyses`

**工作流控制**:`wf_workflows` · `wf_get` · `wf_node_types` · `wf_create_task` · `wf_run_task` · `wf_task` · `wf_task_outputs` · `wf_retry_node` · `wf_skip_node` · `wf_stop_task` · `wf_list_tasks`

**AI 辅助**:`wf_resolve_ai`(外部 AI 提交分析结论) · `wf_regen_report`(重生成报告) · `wf_ai_inject`(注入 AI 结论) · `wf_ue_assist`(UE AI 证据包)

### 外部 AI 驱动工作流(完整流程)

外部 AI(如 opencode / Codex / Claude Code)通过 MCP 完全驱动工作流,**无需配置内部 LLM**:

```
wf_create_task → wf_run_task → wf_task(轮询) → wf_task_outputs(读证据)
    ↓
AI 分析证据(模型推理)
    ↓
wf_resolve_ai(提交结论) → wf_retry_node(重跑节点) → wf_task(等待完成)
    ↓
报告自动渲染 AI 结论
```

AI 节点三层决策链:
1. 变量池中是否有外部 AI 已提交的结论(`_ai_decision_{node_id}`) → 直接使用
2. 内部 AI 是否已配置(base_url/api_key/model) → 调用内部模型
3. 都没有 → 构建证据并返回 `AI_WAITING`,外部 AI 通过 MCP 提交结论后重试

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
| [Dumper-7](https://github.com/Encryqed/Dumper-7) | UE 字符串交叉引用定位三大件方法参考 |
| [UE4SS](https://github.com/UE4SS-RE/RE-UE4SS) | UE 内存扫描与结构解析参考 |
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
│       │   ├── ue/         # UE 虚幻引擎专项(版本/签名/源码轻量拉取/分析器/AI辅助/字符串交叉引用)
│       │   ├── unity/      # Unity 专项(检测/程序集/il2cpp/metadata解密/SDK dump)
│       │   └── ...         # PE/壳/反汇编/沙箱/pcap/Ghidra/AI/报告/引擎执行器
│       ├── workflow_engine/ # 图化工作流引擎 v3(节点/条件/变量/执行器)
│       │   └── nodes/      # 节点实现(分析/控制/AI辅助)
│       └── orchestrator/   # 通用 PE 流水线状态机编排
├── mcp_server/         # MCP Server(FastMCP,37 工具)
├── frontend/           # Web UI(纯静态:样本库/UE/Unity/工作流/反汇编/AI/MCP/设置)
├── ghidra/scripts/     # Ghidra 反编译导出脚本(Java)
├── samples/            # 演示样本 + 构造器(PE/UE/Unity)
├── scripts/            # 启动/设置/工具下载脚本
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
