# REVLab

REVLab 是一个在 Windows 本机运行的 PE 分析工作台。它把样本登记、静态解析、可选的反编译和动态分析拆成阶段，并把每个阶段的结果保存到样本记录中。这样做的目的很实际：同一个文件可以重复分析、比较不同工作流，也能从报告和产物目录回到原始证据。

项目面向逆向工程学习、内部软件排查和实验室样本整理。它不是云端杀毒服务，不会替你判断文件是否安全，也不会把静态猜测包装成运行时结论。

## 能做什么

### 1. PE 静态分析

上传或登记一个 PE 文件后，`identify` 阶段会计算哈希并读取 PE 结构：

- MD5、SHA1、SHA256、imphash、ssdeep
- DOS Header、NT Header、Optional Header 和 ImageBase
- 架构、子系统、入口点、镜像大小、编译时间和校验和
- ASLR、DEP/NX、SEH、CFG、高熵 VA 等安全特性
- 数据目录，包括 Import、Export、Resource、TLS、Debug、Delay Import、COM 等
- 节区的虚拟大小、原始大小、权限、熵和可疑标记
- 导入表、延迟导入、导出表和 TLS 回调
- 资源树、Rich Header、PDB 路径线索和 Authenticode 签名状态
- ANSI/Unicode 字符串及按规则筛出的兴趣字符串

`pefile` 负责主要解析。结果会先转换成可写入 JSON 的普通值，再保存到 SQLite，避免某些 PE 中的包装对象破坏整条流水线。

### 2. 壳检测和脱壳

`unpack` 阶段根据节区、入口点、导入表和内置特征判断常见壳或保护器。UPX 解压是可选能力，其他保护器不会被假定为“已脱壳”。需要通用内存转储时使用 PE-sieve；工具不存在、样本没有进程或策略禁止执行时，阶段会留下原因，而不是生成一个看起来成功的空文件。

### 3. 反汇编与反编译

`disassemble` 使用 Capstone 从入口点开始反汇编，并整理基础 call/jump 目标，方便快速定位函数线索。它不是完整的 IDA/Ghidra 数据库，也不会声称已经恢复了所有函数边界。

`decompile` 调用 Ghidra Headless，导出有限数量的函数伪代码。Ghidra 和 Java 21 未安装时，该阶段会标记为跳过；大型文件的反编译时间取决于机器和文件本身。导出的 JSON 与报告会写入配置的输出目录。

### 4. 动态分析和网络记录

`dynamic` 阶段可以在受控环境中运行样本，收集进程树、子进程、文件变化、注册表变化和 DNS 线索；网络部分使用 Windows `pktmon` 转换为 pcap，再由项目内的解析器整理 DNS、HTTP、TLS SNI 和连接信息。

默认策略是禁止执行。只有配置了有效的 VMware VMX 与快照，或者明确设置 `REVLAB_ALLOW_HOST_EXECUTION=1`，才会尝试运行。没有隔离 VM 时接口返回 `execution_status=blocked_by_policy`，这不是失败，也不是成功，而是一次没有发生的执行。抓包需要管理员权限；没有权限时样本仍可完成静态分析。

### 5. UE 和 Unity 页面

UE 页面针对 dump 后的 exe，阶段包括版本识别、关键源码资料、GNames/GObjects/GWorld/GEngine 候选、反射结构和加密线索。结果里会区分 `confirmed`、`candidate` 和 `unconfirmed`，静态签名命中的地址不会直接当作运行时地址。

Unity 页面接收游戏目录绝对路径，扫描 `globalgamemanagers`、`UnityPlayer.dll`、`GameAssembly.dll`、Managed 程序集和 `global-metadata.dat`。它会识别 Mono/IL2CPP，检查 Metadata 头和表边界，并在输入通过校验后才尝试 SDK 输出。无法确认的 Metadata 会阻止 SDK 交付，避免产生不可用的 `Dump.cs`。

这两类专项分析都有独立的历史记录、阶段状态和产物清单，可以从“设置 → 统一产物中心”查看。

## 工作流

### 线性工作流

仓库自带两个常用定义：

| 名称 | 阶段 | 用途 |
| --- | --- | --- |
| `static-only` | identify → unpack → disassemble → decompile → report | 不运行样本，适合初筛和报告 |
| `full-auto` | identify → unpack → disassemble → decompile → dynamic → report | 在执行策略允许时增加动态阶段 |

每个阶段都会记录 `pending`、`running`、`done`、`error` 或 `skipped`，并保存开始时间、结束时间、耗时和错误文本。任务中途失败后，可以用同一个工作流继续运行，已经完成的阶段会被复用。

### 图工作流

`frontend/workflow` 是 Vue Flow 编辑器，后端图引擎负责真正执行。可以拖拽分析节点、条件分支、审批、报告和 AI 节点，并为变量设置默认值。任务会保存工作流定义快照和版本，避免工作流被修改后历史运行失去上下文。

图任务支持：

- 条件分支和默认分支
- 节点失败策略：终止、跳过或重试
- 单节点重试、跳过和停止任务
- `{{variable}}` 变量引用
- 审批节点，用于把需要人工确认的步骤挡在执行前
- 每次运行的 manifest 和产物来源节点

图编辑器只负责编辑和展示，样本执行、路径检查和策略控制仍由后端完成。

## AI 和 MCP

这里的 AI 不只是把固定报告换一种说法。图工作流里的 `ai_analyze`、`pe_ai_assist`、`ue_ai_assist` 和 `unity_ai_assist` 都可以作为分析操作员运行：模型先看到当前任务已经采集的证据，再决定还缺什么，然后调用后端注册的分析工具。工具结果会返回给模型，模型可以继续调用下一项，或者结束并给出结论。

一次典型的 PE AI 节点会是这样：

1. 读取当前样本的 PE 头和哈希，确认架构与入口点。
2. 根据节区和入口特征决定是否继续查壳、导入表或字符串。
3. 需要代码证据时调用入口反汇编，而不是只根据 API 名称猜行为。
4. 如果模型认为静态证据不够，可以请求动态运行；后端仍会检查 VMware 策略。
5. 最终输出结论、引用过的工具、未确认项和下一步，并保留完整 `tool_trace`。

不同目标会得到不同的工具集合：

| 节点 | AI 可以调用的工具 | 主要用途 |
| --- | --- | --- |
| `pe_ai_assist` | PE 信息、节区、导入/导出、壳检测、字符串、入口反汇编、VM 动态运行 | 判断保护形态、行为线索和下一步逆向入口 |
| `ue_ai_assist` | 全部 PE 工具、UE 版本/三大件/FName 专项分析、VM 动态运行 | 在当前 dump 中重新定位候选，比较反汇编证据，列出运行时校验要求 |
| `unity_ai_assist` | Unity 目录扫描、程序集分析、Metadata 检查与验证 | 区分 Mono/IL2CPP，判断 Metadata 是否可用，以及 SDK 为什么完成或被阻止 |
| `ai_analyze` | 根据当前任务类型开放上述工具 | 处理自定义问题和用户自己搭建的工作流 |

模型每轮可以调用一个或多个工具，默认最多 6 轮，可在节点参数 `max_tool_rounds` 中调整。目标路径由工作流锁定，模型不能把工具切换到另一个文件或目录。支持 OpenAI function calling 的接口会进入完整工具循环；某些兼容网关不支持 `tools` 参数时，节点会退回“只读已有证据”模式，并在 `tool_mode=unsupported_fallback` 和 `warning` 中写明原因，不会假装已经调用过工具。

### 证据怎么交给 AI

每次分析都会按当前样本重新构建 `revlab.ai-evidence/v1` 证据包，不复用其他文件的绝对地址或结论。为了避免大型程序把模型上下文占满，列表和代码会限量，但不会再整块删除节区、导入表或函数信息：

- PE 保留节区名称、大小、权限、熵、导入 DLL/API、导出、TLS、兴趣字符串、入口指令和有限的反编译函数。
- UE 保留版本证据、每组三大件候选 RVA、命中位置附近的反汇编、FName 算法候选、XOR 线索和运行时验证清单。
- Unity 保留目录与关键文件、Mono/IL2CPP 判定证据、GameAssembly 信息、Metadata 候选、Loader 线索、结构校验和 SDK 交付状态。
- 动态阶段始终保留 `executed`、`execution_status` 和阻止原因。没有执行就是没有运行时证据。

证据和结论使用四种边界：`static` 是工具从文件中读取的事实，`runtime` 是受控运行得到的观测，`inferred` 是规则或模型推断，`blocked` 表示没有执行或证据被策略挡住。AI 输出统一标记为 `ai_inferred`。即使模型返回了 `confirmed`，UE 地址规范化也会降回 AI 推断；只有独立的运行时验证节点才能把候选升级为确认结果。

### 内部模型和外部 AI

配置页面使用 OpenAI 兼容接口，需要同时填写 `base_url`、`api_key` 和 `model` 并启用。内部模型配置完成后，AI 节点会直接运行工具循环。`on_fail` 有三种处理方式：

- `external_wait`：保存证据并停在 `AI_WAITING`，等待外部 AI 处理。
- `skip`：明确跳过 AI，后续节点可以继续运行。
- `abort`：把模型缺失视为任务错误并终止。

MCP Server 适合 Codex、Claude Code、Cursor 等外部智能体。外部 AI 可以调用 `wf_task_outputs` 读取节点证据，自行调用 PE/UE/Unity 工具分析，再用 `wf_resolve_ai` 提交结论，最后用 `wf_retry_node` 继续原任务。外部 AI 和网页工作流共用数据库、样本路径检查、产物目录和动态执行策略。

AI 自动请求 `dynamic_run` 时只允许已经配置快照的 VMware 环境。即使手工打开了 `REVLAB_ALLOW_HOST_EXECUTION=1`，AI 也不能自动在宿主机启动样本；宿主机执行仍需由用户走普通动态节点或接口明确触发。

HTTP 模式：

```powershell
python -m mcp_server.server --port 8765
```

stdio 模式：

```powershell
python -m mcp_server.server --stdio
```

工具名称和参数以运行中的 `tools/list` 为准。MCP 调用和网页调用共享同一个本地数据库与安全策略。

## 安装与启动

核心静态分析需要：

- Windows 10/11 x64
- Python 3.10 或更高版本
- `pip`

安装并启动：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
scripts\start.bat
```

打开 <http://127.0.0.1:8000>。首次启动会创建数据库和运行目录，但不会自动下载外部工具。需要时在设置页面执行环境检查，或单独运行安装脚本。

可选依赖：

| 组件 | 用途 |
| --- | --- |
| Java 21 + Ghidra | 函数级伪代码 |
| UPX | 已知 UPX 壳解压 |
| PE-sieve | 进程内存转储和 IAT 修复 |
| Windows pktmon | 网络采集 |
| VMware Workstation | 快照隔离运行 |
| Node.js + npm | 构建 Vue Flow 编辑器 |

## 配置文件

复制模板：

```powershell
Copy-Item .env.example .env
```

常用设置：

```text
# 报告、抓包、脱壳和 SDK 的根目录；留空表示项目目录
REVLAB_OUTPUT_DIR=D:\revlab-output

# VMware 动态分析
REVLAB_SANDBOX_VM=1
REVLAB_VM_VMX=D:\Lab\revlab.vmx
REVLAB_VM_SNAPSHOT=clean
REVLAB_VM_GUEST_PATH=C:\RevLab\sample.exe

# 只在隔离实验机上显式打开宿主机执行
REVLAB_ALLOW_HOST_EXECUTION=0

# 远程 API（本机访问不需要令牌）
REVLAB_API_TOKEN=
REVLAB_CORS_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
```

脚本节点和命令节点由 `REVLAB_ENABLE_UNSAFE_NODES` 控制。自动准备依赖需要显式设置 `REVLAB_AUTO_SETUP=1`，否则环境页只做检查。

## 目录结构

```text
backend/app/              FastAPI、数据库模型和分析服务
backend/tests/            后端契约与行为测试
frontend/                 主界面（原生 HTML/CSS/JS）
frontend/workflow/        Vue Flow 编辑器源码
frontend/wf-dist/         编辑器构建产物
mcp_server/               MCP Server
ghidra/scripts/           Ghidra Headless 导出脚本
scripts/                  安装、启动和工具准备脚本
samples/                  小型演示样本和生成脚本
data/                     SQLite 数据库（运行时创建）
reports/                  HTML/JSON/Markdown 报告
captures/                 pcap 和抓包中间文件
unpacked/                 脱壳和内存转储结果
sdk/                      Unity SDK 输出
runs/                     图工作流运行目录
```

运行时目录已加入 `.gitignore`，不要把真实样本、数据库、报告或凭据提交到仓库。

## API 入口

服务启动后，完整 OpenAPI 文档在 <http://127.0.0.1:8000/docs>。常用接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/api/samples/upload` | 上传样本并按 SHA-256 去重 |
| `GET` | `/api/samples` | 列出最近样本 |
| `GET` | `/api/samples/{id}` | 查看样本和汇总结果 |
| `POST` | `/api/samples/{id}/analyze` | 启动线性工作流 |
| `GET` | `/api/samples/{id}/pipeline` | 读取阶段和历史记录 |
| `GET` | `/api/samples/{id}/disassembly` | 读取入口反汇编 |
| `GET` | `/api/samples/{id}/report` | 下载 HTML、JSON 或 Markdown 报告 |
| `GET` | `/api/status` | 查看工具、环境和动态执行策略 |
| `GET/POST` | `/api/workflows` | 管理线性工作流 |
| `GET/POST` | `/api/wf2` | 管理图工作流和任务 |
| `POST` | `/api/engine/{engine}/analyze` | 启动 UE/Unity 专项分析 |
| `GET` | `/api/artifacts` | 查看已登记的运行产物 |

## 已知限制

- PE 结构正确不代表文件没有恶意行为；静态结果需要人工解释。
- 高熵节区、导入函数和字符串只能提供线索，不能单独证明加壳、加密或联网行为。
- 反汇编从入口点开始，不能替代完整反编译工程。
- Ghidra、pktmon、VMware 等外部工具的可用性取决于本机配置和权限。
- 动态分析若没有隔离环境会被策略阻止；项目不会自动替用户放宽策略。
- UE 地址、Unity Metadata 和 AI 输出都可能是候选结果，报告会保留证据等级和前置条件。
- 输入路径、输出路径和产物打开操作会做边界检查，路径不存在或不在允许目录内时请求会失败。

## 验证

后端测试、Python 编译和前端构建：

```powershell
python -m unittest discover -s backend/tests -p "test*.py"
python -m compileall -q backend mcp_server
cd frontend\workflow
npm run build
```

## 许可证

MIT。请确认样本来源、软件许可和当地法律允许你的分析行为。项目只适用于自有或明确获授权的文件。
