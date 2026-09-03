# E-001 执行策略

- observed_at: 2026-09-03
- source_type: command
- source_ref: `GET http://127.0.0.1:8000/api/status`
- content_hash: n/a
- repro_command: `Invoke-RestMethod http://127.0.0.1:8000/api/status`
- raw_excerpt:

  ```text
  sandbox_mode=local
  dynamic_execution.allowed=true
  dynamic_execution.requires_confirmation=true
  local.network=host_network
  sandboxie/windows_sandbox/vmware.available=false
  ```

- linked_workitem: WI-11111-dynamic

