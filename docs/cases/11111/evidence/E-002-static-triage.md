# E-002 静态分诊与导入表

- observed_at: 2026-09-03
- source_type: file + command
- source_ref: `reports/11111.json`；项目 MCP `get_pe_info`、`get_imports_exports`、`detect_packer`、`extract_strings`、`disassemble`
- content_hash: `a7c073b8a9d5b5c508002a503aed7a6778c609379519a4e1511a234ce73ea347`（样本）
- repro_command: `python -c "from mcp_server import server; print(server.get_imports_exports(4))"`
- raw_excerpt:

  ```text
  PE: x64, Windows GUI, 7 sections, entry=0x14003f104, image_base=0x140000000
  packer: Not packed (likely), confidence=0%
  .rsrc: raw_size=14414848, entropy=7.9739, suspicious=true
  imports: WINHTTP.dll, bcrypt.dll, CRYPT32.dll, ADVAPI32.dll, KERNEL32.dll,
           USER32.dll, GDI32.dll, gdiplus.dll, SHELL32.dll, ole32.dll
  exports=0, TLS callbacks=0, Authenticode signature=absent
  ```

- linked_workitem: WI-11111-static

