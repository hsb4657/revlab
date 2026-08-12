# Contributing to REVLab

感谢参与 REVLab。提交前请先在 Windows 环境完成项目配置：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Verify
```

## 提交范围

- 一个提交聚焦一个可验证的行为变化，并在 PR 描述中写明影响的工作流或 API。
- 保持内置模板、节点规格、后端执行器和工作流前端的数据契约一致。
- 新增节点、条件或失败策略时，补充 `backend/tests/` 中覆盖成功与失败分支的测试。
- UI 调整需要在 `frontend/workflow/` 源码中完成，并重新构建 `frontend/wf-dist`。

## 本地检查

```powershell
.\.venv\Scripts\python.exe -m compileall -q backend
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -v
cd frontend\workflow
npm run build
```

不要提交 `.venv/`、`node_modules/`、`ghidra/runtime/`、样本分析产物、数据库或本地 AI 配置。它们均由 `.gitignore` 排除，并可通过 `scripts/setup.ps1` 重新生成。

## 问题反馈

请提供复现步骤、Windows/Python/Node 版本、工作流定义或节点日志的最小片段。不要在公开 issue 中上传私密样本、凭据、API Key 或受限二进制文件。
