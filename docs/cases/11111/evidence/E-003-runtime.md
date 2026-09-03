# E-003 本机动态运行

- observed_at: 2026-09-03 08:12:16 至 08:13:16
- source_type: file + command
- source_ref: `reports/11111.json` 的 `analysis.dynamic.run`
- content_hash: `a7c073b8a9d5b5c508002a503aed7a6778c609379519a4e1511a234ce73ea347`（样本）
- repro_command: `Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/samples/4/analyze?workflow=full-auto&sync=true&confirm_local_execution=true'`
- raw_excerpt:

  ```text
  executed=true
  execution_status=timeout
  runner=local
  pid=32016
  returncode=timeout
  ran_seconds=60
  network_policy=host_network
  target_process=11111.exe
  target_child_processes=none observed
  sample_directory_file_changes=none observed
  HKCU...\Run and HKCU...\RunOnce changes=none observed
  ```

- 运行结束后复查：`Get-CimInstance Win32_Process -Filter "Name='11111.exe'"` 无结果。
- linked_workitem: WI-11111-dynamic

