# REVLab 界面说明

这份文件记录当前界面的取舍，给后续改 UI 时作参考。REVLab 是分析工具，页面应该先让人看见样本、证据和失败原因，装饰放在后面。

## Genre

深色、紧凑的桌面工作台。信息密度可以高，但不能牺牲可读性。

## Macrostructure

- 主界面：固定导航、简短的运行概览、证据面板和明确的状态提示。
- 工作流页面：Vue Flow 画布和运行面板是图任务的真实状态来源。

## Theme

- Paper: `oklch(17% 0.018 250)`
- Panel: `oklch(22% 0.022 250)`
- Ink: `oklch(93% 0.018 220)`
- Muted ink: `oklch(70% 0.025 230)`
- Accent: `oklch(78% 0.14 205)`
- Success: `oklch(73% 0.16 145)`
- Warning: `oklch(78% 0.15 85)`
- Danger: `oklch(70% 0.18 25)`

## Typography and spacing

静态界面使用 Segoe UI；哈希、地址、路径和机器输出使用 Cascadia Code。间距使用 `tokens.css` 中的 4 点刻度。卡片和控件保持 5–7px 圆角，表格更容易连续阅读。

## Interaction contract

所有调用 API 的操作都要显示加载、成功、失败和空状态。耗时任务直接展示后端返回的流水线或引擎阶段。没有隔离 VM 时，动态执行显示为“策略阻止”，不能改成假的成功状态。

## Content voice

文案尽量短而具体：有什么、缺什么、收集到了什么证据，都直接写出来。AI 辅助区域要显示当前模型是否调用了工具、调用了哪些工具、证据来自哪个阶段，以及哪些结论仍是 `candidate`/`ai_inferred`。可选工具、AI、抓包和动态运行只有在后端确认后才能写成成功；`blocked_by_policy`、`not_collected` 和模型推断不能用成功色或“已完成”代替。

AI 不是固定脚本：它在每个样本上从当前证据开始，按需请求 PE、UE 或 Unity 工具，再决定是否继续取证。界面应把工具轨迹和最终结论分开，允许用户展开原始证据、重试单个节点或提交人工确认。没有 function-calling 能力的模型要显示“只读证据模式”，不能展示成“AI 已自动分析全部阶段”。
