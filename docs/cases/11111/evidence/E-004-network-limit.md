# E-004 网络观测边界

- observed_at: 2026-09-03
- source_type: command
- source_ref: `pktmon list` 与动态结果中的 `admin_required=true`
- content_hash: n/a
- repro_command: `pktmon list`
- raw_excerpt:

  ```text
  无法与 PktMon 驱动程序通信。系统找不到指定的文件。
  exit=2
  ```

- 结论：本次没有运行时 DNS、HTTP、TLS 或连接级证据；静态字符串中的域名和 URL 只能作为待验证 IOC，不能写成“运行时已连接”。
- linked_workitem: WI-11111-dynamic

