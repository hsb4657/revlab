# 11111.exe 分析范围

## 授权

- 授权来源：用户在本次任务中明确回复“确认运行 11111.exe”。
- 目标：`C:\Users\Administrator\Desktop\哒哒哒DMA公益\CFHD公益DMA\11111.exe`
- 样本 SHA-256：`a7c073b8a9d5b5c508002a503aed7a6778c609379519a4e1511a234ce73ea347`
- 样本 MD5：`c7609c59ce80feb8de60928cd08689d7`

## 允许操作

- 使用 REVLab 的 PE 静态工具、MCP 工具和 Ghidra Headless 读取样本。
- 在当前 Windows 主机上运行一次，最长 60 秒，由 REVLab 终止进程树。
- 记录进程树、样本目录文件变化、Run/RunOnce 注册表变化和可用的网络元数据。
- 生成本地报告；原始样本不修改、不删除。

## 网络与执行边界

- 执行后端：REVLab `LocalSandbox`，宿主机网络（`host_network`）。
- 未使用 Sandboxie、Windows Sandbox 或 VMware。
- `pktmon` 驱动在本次用户会话不可通信，因此没有运行时 pcap 证据。
- 本文件不授权向样本静态提取到的域名发起探测或登录请求。
