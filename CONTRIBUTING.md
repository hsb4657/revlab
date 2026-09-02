# 参与开发

REVLab 目前主要在 Windows 上开发和测试。提交代码前，先完成一次本地配置：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Verify
```

## 改动范围

尽量让一个提交只解决一个问题，并在提交说明或 PR 中写清楚影响了哪个页面、接口、分析阶段或节点。

后端分析节点、线性工作流和 Vue Flow 图工作流共享一部分数据结构。修改节点输入或输出时，要同时检查：

- `backend/app/workflow_engine/nodes/` 中的节点实现
- `backend/app/services/` 中的执行器和报告代码
- `frontend/workflow/src/` 中的节点参数与状态展示
- `frontend/js/app.js` 中的主界面请求和渲染

新增节点、条件或失败策略时，请至少覆盖一个成功分支和一个失败分支。涉及文件路径、动态执行、外部工具或数据库迁移的改动，需要补充边界测试。

## 前端改动

主界面是原生 HTML/CSS/JS，入口文件位于 `frontend/`。图编辑器使用 Vue Flow，源码在 `frontend/workflow`。修改图编辑器后，在该目录执行：

```powershell
npm run build
```

构建结果会写入 `frontend/wf-dist`。不要直接编辑构建后的压缩文件。

页面上的耗时操作需要有加载、成功、失败和空状态。动态执行、抓包、反编译和 AI 都必须显示后端真实状态，不能为了好看写死“已完成”。

## AI 节点改动

AI 节点是工具调用入口，不只是一个文本框。新增或修改工具时，要同时检查：

- 工具是否限制在当前任务的样本路径，是否只返回有界、可序列化的结果；
- 工具调用失败、网关不支持 function-calling、动态策略阻止时，是否分别保留原因；
- 输出是否带有 `source`、`evidence_level`、`validation_state`，并且没有把模型推断升级成 `confirmed`；
- PE、UE、Unity 的证据是否仍然能在 `wf_task_outputs` 中被外部 AI 读取；
- 是否添加一个工具循环成功和一个工具不可用的测试。

不要在提示词里承诺模型一定能联网。外部资料只能作为补充，样本文件、运行时观测和工具产物才是报告的主要证据。

## 提交前检查

```powershell
.\.venv\Scripts\python.exe -m compileall -q backend mcp_server
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -v
cd frontend\workflow
npm run build
```

如果没有安装可选工具，至少运行核心静态测试。需要验证动态分析时，使用专门的隔离 VM，不要在开发机上直接启动未知样本。

## 不要提交的内容

以下内容由 `.gitignore` 排除，也不应手动加入提交：

- `.venv/`、`node_modules/`、`ghidra/runtime/`
- `data/` 下的数据库
- `reports/`、`captures/`、`unpacked/`、`sdk/`、`runs/` 下的运行产物
- 真实样本、私密日志、API Key、密码和本地 AI 配置

## 报告问题

请写出复现步骤、系统版本、Python/Node 版本、使用的工作流名称，以及相关阶段的日志片段。公开 issue 中不要上传受限二进制或包含凭据的完整日志；可以先用演示样本复现，再提供脱敏后的最小输入。
