# E-005 嵌入式配置线索

- observed_at: 2026-09-03
- source_type: file
- source_ref: MCP `extract_strings(4, interesting_only=false)`，偏移约 `0x8CA00`（十进制 `576192`）
- content_hash: `a7c073b8a9d5b5c508002a503aed7a6778c609379519a4e1511a234ce73ea347`（样本）
- repro_command: `python -c "from mcp_server import server; print(server.extract_strings(4, 4, False))"`
- raw_excerpt（敏感值已脱敏）:

  ```text
  {"api_host":"www.dadadadanb.top","api_port":443,
   "api_path":"/api/v1/session","use_ssl":true,
   "api_key":"<redacted>","master_key":"<redacted>","xor_key":"<redacted>",
   "payload_hash":"<sha256>","enable_integrity_check":true,
   "enable_security_report":true,"enable_rate_limit":true}
  /api/v1/program_info
  /api/v1/version_check
  /api/v1/security/report
  /api/auth/admin/login
  /api/admin/programs/pack-config
  X-Encrypt: aes-gcm; X-API-Key: <redacted>
  ```

- 说明：样本含有疑似服务配置和凭据字段。报告、聊天和提交内容不回显真实密钥；不要使用这些字段向外部服务发起请求。
- linked_workitem: WI-11111-static
