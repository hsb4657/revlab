# 设置与排错

## 最小安装

Windows 10/11、Python 3.10+ 和 `pip` 即可运行核心静态分析。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1
scripts\start.bat
```

打开 <http://127.0.0.1:8000>。如果 8000 端口已被占用，请在启动脚本中改用其他端口。

## 可选能力

| 能力 | 依赖 | 缺失时的行为 |
| --- | --- | --- |
| 反编译 | Java 21、Ghidra | 反编译阶段标记跳过，静态分析仍可用 |
| UPX 解压 | `tools/upx/upx.exe` | 保留壳检测结果，不执行解压 |
| 通用内存转储 | PE-sieve | 脱壳阶段返回工具缺失 |
| 网络抓包 | Windows `pktmon`、管理员权限 | 样本可继续分析，但没有抓包产物 |
| 动态分析 | VMware Workstation、可用快照 | 未配置时返回 `blocked_by_policy` |

启动不会自动下载依赖。安装脚本或设置页的环境操作必须由用户显式触发。

## 环境变量

复制 `.env.example` 为 `.env`。核心设置如下：

```text
REVLAB_OUTPUT_DIR=D:\revlab-output
REVLAB_SANDBOX_VM=1
REVLAB_VM_VMX=D:\Lab\revlab.vmx
REVLAB_VM_SNAPSHOT=clean
REVLAB_VM_GUEST_PATH=C:\RevLab\sample.exe
```

没有 VMX 和快照时，保持 `REVLAB_SANDBOX_VM=0`。宿主机执行只有在明确设置 `REVLAB_ALLOW_HOST_EXECUTION=1` 后才会启用，这只适合隔离的实验机。

远程 API 还需要 `REVLAB_API_TOKEN`，浏览器来源由 `REVLAB_CORS_ORIGINS` 控制。脚本节点和自定义命令同样默认关闭。

## 常见问题

### 页面能打开，但分析无法启动

进入“设置”查看环境卡片。缺失能力会列出路径和补救方式；环境准备完成后重新提交工作流。

### 动态阶段显示未执行

这是预期的安全状态。只有 `REVLAB_SANDBOX_VM=1` 且 VMX、快照均有效时才会运行样本。界面不会把被策略阻止的执行显示为成功。

### 报告或产物打不开

确认输出目录可写，并在“统一产物中心”刷新运行清单。每个文件只能从本次运行登记的 manifest 打开或下载。

## 验证

```powershell
python -m unittest discover -s backend/tests -p "test*.py"
python -m compileall -q backend mcp_server
```

前端是静态文件；图工作流编辑器修改后，在 `frontend/workflow` 执行 `npm run build`。
