# REVLab

REVLab 是一个面向 Windows PE 的本地分析工作台。它把文件指纹、PE 结构、字符串、壳线索、反汇编、可选反编译、网络记录和报告放在同一条工作流里，也提供 UE、Unity 和图形化工作流入口。

项目定位是实验室工具，不是在线扫描服务。默认情况下样本只写入本机目录，动态执行默认关闭。

## 当前可用能力

### PE 工作流

- MD5、SHA1、SHA256、imphash 和 ssdeep
- PE 头、数据目录、节区、熵、导入/导出、延迟导入、TLS、资源、Rich Header、PDB 线索和签名状态
- 常见壳特征检测；UPX 解压和 PE-sieve 内存转储属于可选工具能力
- Capstone 入口反汇编与基础跳转/调用线索
- Ghidra Headless 函数导出，前提是本机安装并启用 Ghidra
- pktmon 抓包和内置 pcap 解析，前提是系统权限与工具可用
- HTML、Markdown、JSON 报告

### UE / Unity

UE 和 Unity 页面使用独立的阶段记录。它们输出版本、文件结构、关键证据和候选结果；静态候选不会被标成“已验证地址”。Unity 的 Metadata 恢复和 SDK 导出只有在输入通过结构校验后才会继续。

### 工作流和 AI

项目包含线性工作流和 Vue Flow 图工作流。节点状态、重试、跳过、审批和产物登记由后端保存。

AI 是可选的外部模型接入。未配置模型时，AI 节点会返回等待或跳过状态，不会生成伪造结论。MCP Server 提供同一组本地能力，工具数量和具体接口以启动后的 `/docs` 与 MCP `tools/list` 为准。

## 安全边界

- 动态分析优先使用 VMware 快照。没有配置 VMX 和快照时，动态节点会返回 `blocked_by_policy`，不会在宿主机启动样本。
- 宿主机执行必须显式设置 `REVLAB_ALLOW_HOST_EXECUTION=1`，仅适用于隔离的实验机。
- 脚本、命令和自动下载默认关闭，需要时分别设置对应环境变量并理解风险。
- 只分析自有或明确获授权的样本。项目不提供绕过第三方授权、反作弊或许可校验的功能。

## 安装与启动

要求 Windows 10/11、Python 3.10+。可选能力还需要 Java 21、Node.js、VMware Workstation、UPX 或 PE-sieve。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
scripts\start.bat
```

浏览器访问 <http://127.0.0.1:8000>。启动不会自动下载依赖；环境页的“检查并配置”只在用户明确触发时执行。

复制 `.env.example` 为 `.env` 后，可以配置输出目录和隔离策略：

```text
REVLAB_OUTPUT_DIR=D:\revlab-output
REVLAB_SANDBOX_VM=1
REVLAB_VM_VMX=D:\Lab\revlab.vmx
REVLAB_VM_SNAPSHOT=clean
```

不使用 VM 时保持 `REVLAB_SANDBOX_VM=0`。不要为了让界面显示“动态成功”而打开宿主机执行。

## 使用流程

1. 在“样本库”上传 PE，或通过 MCP `register_sample` 登记本地文件。
2. 选择样本并启动工作流，观察真实阶段状态。
3. 在详情页查看证据，在“反汇编/网络”页查看入口指令和抓包结果。
4. 在“设置”页查看环境检查和本次运行登记的产物。

UE 页面接收样本 ID 或 dump exe；Unity 页面接收游戏目录的绝对路径。

## API 与开发

FastAPI 文档在 <http://127.0.0.1:8000/docs>。后端测试：

```powershell
python -m unittest discover -s backend/tests -p "test*.py"
python -m compileall -q backend mcp_server
```

主界面是原生 HTML/CSS/JS，图工作流编辑器位于 `frontend/workflow`，构建后由 `frontend/wf-dist` 提供。

## 目录

`backend/app` 是 FastAPI 与分析服务，`frontend` 是主界面，`frontend/workflow` 是图编辑器，`mcp_server` 是 MCP 入口，`reports`、`captures`、`unpacked`、`sdk` 和 `workspace` 是运行时产物目录。

## 许可证

MIT。使用前请确认样本来源和分析行为符合当地法律、软件许可和组织规定。
