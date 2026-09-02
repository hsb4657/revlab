# 安装、配置和排错

REVLab 的核心是“证据阶段 + 可选的 AI 操作员”。PE、UE 和 Unity 使用不同的分析器，但都通过同一个任务系统保存阶段状态、产物和 AI 工具轨迹。先把项目跑起来，再按手里的样本类型选择工作流；不要为了让界面显示“完成”而安装用不到的工具。使用前请阅读仓库根目录的 [免责声明与使用边界](../DISCLAIMER.md)。

不要在生产机或日常办公机上运行未知样本。动态分析前准备专用 VMware 快照、隔离网络、可恢复备份和最小权限账号；没有这些条件时保持默认的 `blocked_by_policy`。报告、抓包和 AI 请求可能包含敏感信息，分享前请脱敏。

## 先运行起来

在 Windows 10/11 上准备 Python 3.10+：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
scripts\start.bat
```

然后访问 <http://127.0.0.1:8000>。如果端口被占用，修改启动命令里的端口即可。

只做 PE 静态分析时，不需要 Java、Ghidra、VMware 或管理员权限。设置页会列出本机已经找到的可选组件。

### 按样本类型选择入口

| 手里的文件 | 入口 | 第一轮会做什么 |
| --- | --- | --- |
| 单个 `.exe`/`.dll` | PE 分析 | 哈希、PE 头、节区、导入、字符串、壳线索 |
| Unreal dump 后的 exe | UE 专项分析 | UE 家族/版本候选、三大件、FName、反射和加密线索 |
| Unity 游戏目录 | Unity 专项分析 | Mono/IL2CPP 判定、GameAssembly、Metadata、资源和 SDK 门禁 |

UE 和 Unity 不要求把文件复制到项目目录，使用绝对路径即可。分析结果会保存到配置的输出目录；原始样本保持不变。

## 可选工具

| 功能 | 需要什么 | 没有时会怎样 |
| --- | --- | --- |
| Ghidra 反编译 | Java 21、Ghidra | 反编译阶段跳过，其他阶段继续 |
| UPX 解压 | `tools/upx/upx.exe` | 只保留壳检测结果 |
| PE-sieve 转储 | `tools/pe-sieve/pe-sieve64.exe` | 转储步骤报告工具缺失 |
| 网络抓包 | Windows `pktmon`、管理员权限 | 没有网络产物，静态分析不受影响 |
| 动态分析 | VMware、VMX 文件、快照 | 直接返回 `blocked_by_policy` |

安装脚本可以准备部分工具，但不会在服务启动时自动下载。大文件工具也可以手动安装后，在 `.env` 中填写路径。

## `.env` 配置

复制模板：

```powershell
Copy-Item .env.example .env
```

常用配置：

```text
# 报告和运行产物的根目录。留空表示项目目录。
REVLAB_OUTPUT_DIR=D:\revlab-output

# VMware 动态分析。三个值需要和实际虚拟机一致。
REVLAB_SANDBOX_VM=1
REVLAB_VM_VMX=D:\Lab\revlab.vmx
REVLAB_VM_SNAPSHOT=clean
REVLAB_VM_GUEST_PATH=C:\RevLab\sample.exe

# 宿主机执行只用于隔离实验机，默认关闭。
REVLAB_ALLOW_HOST_EXECUTION=0
```

没有准备好快照时，不要把 `REVLAB_SANDBOX_VM` 改成 1。宿主机执行也不要用来替代快照沙箱。

远程 API 还需要 `REVLAB_API_TOKEN`，允许的浏览器来源写在 `REVLAB_CORS_ORIGINS`。脚本节点和命令节点分别由 `REVLAB_ENABLE_UNSAFE_NODES` 控制。

## 配置 AI 工具调用

AI 节点不是离线规则库。启用后，模型可以在当前工作流里请求 PE、UE 或 Unity 工具，后端执行后再把结果交回模型。配置页面中的“测试连接”只验证普通对话接口；要让模型真正调用工具，还需要服务商接受 OpenAI 兼容的 `tools`/function-calling 参数。

最小配置示例：

```text
enabled = true
base_url = https://api.openai.com/v1
api_key = <your-key>
model = gpt-4o-mini
```

每个 AI 节点都有 `max_tool_rounds`，默认 6。节点输出会包含 `tool_trace`，记录工具名、参数和有界结果；完整反编译、SDK 和报告仍保存在运行产物目录。若网关不支持工具参数，节点会自动退回只读证据模式，并把 `tool_mode=unsupported_fallback` 写入输出。

没有配置模型时，建议保留 `on_fail=external_wait`。工作流会把当前证据保存为 `revlab.ai-evidence/v1`，然后等待 MCP 智能体通过 `wf_task_outputs` 读取、调用工具并用 `wf_resolve_ai` 提交结论。`skip` 适合只想跑静态阶段的任务，`abort` 适合把 AI 设为硬性门禁。

AI 自动请求动态工具时必须有有效 VMware 快照。没有隔离 VM 时返回 `blocked_by_policy`，这表示没有发生执行；不要把这个状态解读成样本没有行为。

## 常见问题

### AI 没有调用工具

先确认 AI 配置中的 `enabled`、`base_url`、`api_key` 和 `model` 都已填写。然后检查节点输出：

- `tool_trace` 有记录：模型已经进入工具循环，按记录查看它查过什么。
- `tool_mode=unsupported_fallback`：当前兼容网关不接受 OpenAI `tools` 参数，节点只能根据已有证据回答。
- `AI_WAITING`：没有可用的内部模型，需要用 MCP 读取证据并提交结论。

有些模型会先给出一段解释再请求工具，这是正常的；后端只把真正执行成功的工具结果写入轨迹。模型没有调用 `pe_get_imports`，不代表导入表为空，只代表这一轮没有查它。

### AI 给出的地址或行为能直接使用吗

不能直接当作事实。UE 地址默认是 `candidate`/`ai_inferred`，要经过同构建运行时指针和 FName 解码验证。PE 导入 API、字符串和高熵节区只是线索。动态状态必须是实际执行返回的 `execution_status=completed`；`blocked_by_policy` 和 `not_collected` 都表示没有运行时观测。

### Unity 为什么没有生成 SDK

先看 `metadata_status`、`metadata_validation` 和 `delivery_complete`。Metadata 候选、文件名被改写或只修复了头部，都不会满足 SDK 门禁；需要结构解析通过，必要时还要提供构建匹配的运行时恢复证据。

### 点了分析但没有结果

先看样本状态和流水线阶段。`analyzing` 表示后台线程仍在工作；`error` 会在详情页显示错误文本。Ghidra 对大型文件可能需要一段时间。

### 动态阶段显示 `blocked_by_policy`

这是安全策略的正常结果，表示当前没有可用的隔离执行环境。配置有效的 VMware VMX 和快照后重新提交工作流即可。

### 报告生成了但打不开

确认输出目录有写权限，然后在“设置 → 统一产物中心”刷新。报告只能从当前运行登记的路径打开，手动改路径不会被接受。

### 页面显示组件缺失

设置页展示检测到的版本和路径。先按该卡片给出的路径安装或修正环境变量，再点“刷新”。核心静态分析不依赖所有可选项。

## 本地验证

```powershell
python -m unittest discover -s backend/tests -p "test*.py"
python -m compileall -q backend mcp_server
cd frontend\workflow
npm run build
```
