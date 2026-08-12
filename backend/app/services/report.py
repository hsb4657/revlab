"""报告生成:JSON 主报告 + 可读 HTML/Markdown"""
import json
import re
import shutil
import time
from pathlib import Path


_REPORT_INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_REPORT_WHITESPACE = re.compile(r"\s+")
_WINDOWS_RESERVED_STEMS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_MAX_REPORT_STEM_LENGTH = 180

_HTML_TPL = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>REVLab 分析报告 - {name}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;margin:24px;background:#0f1420;color:#dbe2f0}}
h1{{color:#58a6ff}} h2{{color:#8b949e;border-bottom:1px solid #30363d;padding-bottom:4px;margin-top:32px}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}
th,td{{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:13px}}
th{{background:#161b27;color:#8b949e}} tr:nth-child(even){{background:#161b27}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;margin:2px}}
.packed{{background:#3d1d1d;color:#f85149}} .clean{{background:#143a20;color:#3fb950}}
.warn{{color:#d29922}} .ok{{color:#3fb950}} .bad{{color:#f85149}}
code{{background:#161b27;padding:1px 5px;border-radius:3px;color:#ffa657}}
pre{{background:#161b27;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px}}
.meta td:first-child{{width:200px;color:#8b949e}}
</style>
</head>
<body>
<h1>REVLab 逆向分析报告</h1>
<p>样本: <code>{name}</code> · 生成时间: {ts}</p>
{body}
<div style="margin-top:40px;font-size:12px;color:#6e7681">
REVLab — 实验室自研软件合规逆向测试工具。全程本地处理,不产生任何外部网络请求。
</div>
</body>
</html>"""


def _esc(s):
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _hex(value):
    if isinstance(value, int):
        return hex(value)
    if value in (None, ""):
        return ""
    return str(value)


def analysis_report_name(sample_name: str, kind: str = "") -> str:
    """Build a deterministic, filesystem-safe report stem from the sample.

    Report paths should identify the file or game directory being analyzed,
    rather than an internal workflow/task id.  Windows and POSIX path forms
    are both normalized because callers may submit either form through the UI.
    """
    raw = str(sample_name or "analysis").strip()
    parts = [part for part in re.split(r"[\\/]", raw) if part not in ("", ".", "..")]
    base = parts[-1] if parts else "analysis"
    # A trailing separator is an explicit directory signal. Callers that pass
    # a directory name with dots should pass the directory itself as the
    # identity; common executable/library suffixes are the only ones stripped.
    suffix = Path(base).suffix.lower()
    stem = Path(base).stem if suffix in {".exe", ".dll", ".bin", ".apk", ".so"} else base
    stem = stem or base
    stem = _REPORT_INVALID_CHARS.sub("_", stem)
    stem = _REPORT_WHITESPACE.sub("_", stem).strip("._ ") or "analysis"
    # Device names remain reserved even when an extension was removed by
    # Path.stem (for example, "CON.txt"). Prefixing keeps the source name
    # recognizable while making every report writable on Windows.
    if stem.split(".", 1)[0].upper() in _WINDOWS_RESERVED_STEMS:
        stem = f"_{stem}"
    if kind:
        suffix = _REPORT_INVALID_CHARS.sub("_", str(kind)).strip("._ ")
        if suffix:
            stem = f"{stem}_{suffix}"
    stem = stem[:_MAX_REPORT_STEM_LENGTH].rstrip("._ ")
    return stem or "analysis"


def build_report(sample: dict, analysis: dict) -> dict:
    """聚合样本与分析结果为一份报告结构。"""
    return {
        "sample": sample,
        "analysis": analysis,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _section(title, rows, cols=None):
    if not rows:
        return f"<h2>{title}</h2><p class='ok'>无数据</p>"
    head = ""
    if cols:
        head = "<tr>" + "".join(f"<th>{_esc(c)}</th>" for c in cols) + "</tr>"
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(v)}</td>" for v in row) + "</tr>"
        for row in rows
    )
    return f"<h2>{title}</h2><table>{head}{body}</table>"


def _ai_assist_html(ue: dict) -> str:
    """UE AI 辅助结论(三大件精确地址 / GetName 算法 / 解密算法)HTML 段。"""
    ai_assist = (ue or {}).get("ai_assist") or {}
    if not isinstance(ai_assist, dict) or not ai_assist.get("ai_output"):
        return ""
    if not ai_assist.get("configured"):
        return f"<h2>UE AI 辅助分析</h2><p class='bad'>AI 模型未配置,辅助分析未执行: {_esc(ai_assist.get('error', ''))}</p>"
    if ai_assist.get("error"):
        return f"<h2>UE AI 辅助分析</h2><p class='bad'>AI 请求失败: {_esc(str(ai_assist.get('error')))}</p>"
    body = [f"<h2>UE AI 辅助分析</h2><p class='ok'>模型: {_esc(ai_assist.get('model', ''))}</p>"]
    three = (ai_assist.get("three_majors") or {}) if isinstance(ai_assist.get("three_majors"), dict) else {}
    rows = []
    for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"),
                       ("gworld", "GWorld"), ("gengine", "GEngine")):
        item = three.get(key) or {}
        if not isinstance(item, dict):
            item = {}
        rows.append([
            label,
            item.get("rva_hex") or "未给出",
            item.get("absolute_va_hex") or "未计算",
            item.get("confidence", "-"),
            (item.get("reason") or "")[:300],
        ])
    body.append(_section("AI 判定的三大件精确地址", rows, ["对象", "RVA", "绝对 VA(ImageBase+RVA)", "置信度", "依据"]))
    gna = (ai_assist.get("getname_algorithm") or {}) if isinstance(ai_assist.get("getname_algorithm"), dict) else {}
    body.append(_section("AI 给出的 GetName / FName 算法", [
        ["模型", gna.get("model", "-")],
        ["Key", gna.get("key_hex") or "无"],
        ["Block 位", gna.get("block_bits", "-")],
        ["Entry 步长", gna.get("entry_stride", "-")],
        ["Header Info 偏移", gna.get("header_info_offset", "-")],
        ["WideBit", gna.get("wide_bit", "-")],
        ["LengthShift", gna.get("length_shift", "-")],
        ["算法描述", (gna.get("description") or "")[:2000]],
    ], ["字段", "值"]))
    if gna.get("steps"):
        body.append("<h3>GetName 解码步骤</h3><pre>" + _esc("\n".join(str(item) for item in gna["steps"])) + "</pre>")
    da = (ai_assist.get("decryption_algorithm") or {}) if isinstance(ai_assist.get("decryption_algorithm"), dict) else {}
    body.append(_section("AI 给出的解密算法", [
        ["是否检测到解密", "是" if da.get("detected") else "否(无需解密)"],
        ["算法", da.get("algorithm") or "-"],
        ["Key", da.get("key_hex") or "无"],
        ["描述", (da.get("description") or "")[:2000]],
    ], ["字段", "值"]))
    if da.get("steps"):
        body.append("<h3>解密步骤</h3><pre>" + _esc("\n".join(str(item) for item in da["steps"])) + "</pre>")
    notes = ai_assist.get("notes") or []
    if notes:
        body.append("<h3>AI 备注</h3><pre>" + _esc("\n".join(str(item) for item in notes)) + "</pre>")
    return "".join(body)


def _generic_ai_html(analysis: dict) -> str:
    """通用 AI 节点输出(ai_outputs)HTML 段。"""
    outputs = dict(((analysis.get("workflow") or {}).get("ai_outputs") or {}))
    unity = analysis.get("unity") or {}
    if isinstance(unity, dict):
        if unity.get("ai_review"):
            outputs["unity_ai_review"] = unity["ai_review"]
        if unity.get("ai_assist"):
            outputs["unity_ai_assist"] = unity["ai_assist"]
    if not isinstance(outputs, dict) or not outputs:
        return ""
    body = ['<h2>AI 辅助分析输出</h2>']
    for key, value in outputs.items():
        if not isinstance(value, dict):
            body.append(f"<h3>{_esc(key)}</h3><pre>{_esc(json.dumps(value, ensure_ascii=False)[:8000])}</pre>")
            continue
        response = value.get("response") or ""
        body.append(f"<h3>{_esc(key)}</h3>")
        if value.get("configured") is False:
            body.append(f"<p class='bad'>AI 未配置/请求失败: {_esc(value.get('error', ''))}</p>")
            continue
        if response:
            body.append(f"<pre>{_esc(response[:10000])}</pre>")
        payload = {k: v for k, v in value.items() if k not in ("response", "ai_output", "raw_response")}
        if payload:
            body.append(f"<pre>{_esc(json.dumps(payload, ensure_ascii=False, indent=2)[:10000])}</pre>")
    return "".join(body)


def _ai_assist_markdown(ue: dict) -> list:
    """UE AI 辅助结论 Markdown 段。"""
    ai_assist = (ue or {}).get("ai_assist") or {}
    if not isinstance(ai_assist, dict) or not ai_assist.get("ai_output"):
        return []
    out = ["\n## UE AI 辅助分析\n"]
    if not ai_assist.get("configured") or ai_assist.get("error"):
        out.append(f"- AI 不可用: {_esc(ai_assist.get('error', 'AI 模型未配置'))}")
        return out
    out.append(f"- 模型: `{ai_assist.get('model', '')}`")
    three = ai_assist.get("three_majors") or {}
    out.append("\n### AI 判定的三大件精确地址\n")
    out.append("| 对象 | RVA | 绝对 VA | 置信度 | 依据 |\n|---|---:|---:|---:|---|")
    for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"),
                       ("gworld", "GWorld"), ("gengine", "GEngine")):
        item = (three or {}).get(key) or {}
        if not isinstance(item, dict):
            item = {}
        out.append(f"| {label} | `{item.get('rva_hex') or '未给出'}` | `{item.get('absolute_va_hex') or '未计算'}` | {item.get('confidence', '-')} | {(item.get('reason') or '')[:200]} |")
    gna = ai_assist.get("getname_algorithm") or {}
    out.append("\n### AI 给出的 GetName / FName 算法\n")
    out.append(f"- 模型: `{gna.get('model', '-')}`; Key: `{gna.get('key_hex') or '无'}`")
    out.append(f"- Block 位: {gna.get('block_bits', '-')}; Entry 步长: {gna.get('entry_stride', '-')}; "
               f"HeaderInfo: {gna.get('header_info_offset', '-')}; WideBit: {gna.get('wide_bit', '-')}; "
               f"LengthShift: {gna.get('length_shift', '-')}")
    if gna.get("description"):
        out.append(f"- 算法描述: {gna.get('description')}")
    for item in (gna.get("steps") or []):
        out.append(f"  - {item}")
    da = ai_assist.get("decryption_algorithm") or {}
    out.append("\n### AI 给出的解密算法\n")
    if da.get("detected"):
        out.append(f"- 算法: `{da.get('algorithm', '-')}`; Key: `{da.get('key_hex') or '无'}`")
        if da.get("description"):
            out.append(f"- 描述: {da.get('description')}")
        for item in (da.get("steps") or []):
            out.append(f"  - {item}")
    else:
        out.append("- 未检测到需要解密的算法")
    for item in (ai_assist.get("notes") or []):
        out.append(f"- 备注: {item}")
    return out


def _generic_ai_markdown(analysis: dict) -> list:
    outputs = dict(((analysis.get("workflow") or {}).get("ai_outputs") or {}))
    unity = analysis.get("unity") or {}
    if isinstance(unity, dict):
        if unity.get("ai_review"):
            outputs["unity_ai_review"] = unity["ai_review"]
        if unity.get("ai_assist"):
            outputs["unity_ai_assist"] = unity["ai_assist"]
    if not isinstance(outputs, dict) or not outputs:
        return []
    out = ["\n## AI 辅助分析输出\n"]
    for key, value in outputs.items():
        if not isinstance(value, dict):
            out.append(f"- **{key}**: `{(str(value))[:500]}`")
            continue
        if value.get("configured") is False or value.get("error"):
            out.append(f"- **{key}**: AI 不可用 — {value.get('error', 'AI 模型未配置')}")
            continue
        response = value.get("response") or ""
        if response:
            out.append(f"\n### {key}\n")
            out.append("```\n" + response[:4000] + "\n```")
        payload = {k: v for k, v in value.items() if k not in ("response", "ai_output", "raw_response")}
        if payload:
            out.append("```json\n" + json.dumps(payload, ensure_ascii=False, indent=2)[:6000] + "\n```")
    return out


def to_html(report: dict) -> str:
    a = report.get("analysis", {})
    s = report.get("sample", {})
    body = []

    # 元数据
    meta = [
        ("文件名", s.get("file_name", "")),
        ("SHA256", s.get("sha256", "")),
        ("MD5", s.get("md5", "")),
        ("大小", f'{s.get("file_size", 0):,} bytes'),
    ]
    body.append(_section("样本元数据", [[k, v] for k, v in meta], ["字段", "值"]))

    # PE 概览
    pe = a.get("pe", {})
    if pe.get("is_pe"):
        pk = pe.get("packer", {})
        badge = "<span class='badge packed'>PACKED</span>" if pk.get("packed") else "<span class='badge clean'>CLEAN</span>"
        rows = [
            ["架构", f"{pe.get('machine','')} ({'64-bit' if pe.get('is_64bit') else '32-bit'}) {badge}"],
            ["子系统", pe.get("subsystem", "")],
            ["入口点", pe.get("entry_point", "")],
            ["ImageBase", pe.get("image_base", "")],
            ["编译时间", pe.get("timestamp", "")],
            ["PDB", (pe.get("debug") or {}).get("pdb", "")],
            ["节区数", pe.get("number_of_sections", 0)],
            ["包壳判定", f"{pk.get('verdict','')} (confidence {pk.get('confidence',0)}%)" if pk else ""],
        ]
        sec_rows = pe.get("sections", [])
        if sec_rows:
            body.append(_section("节区(含熵)", sec_rows, ["名称", "VA", "原始大小", "熵", "标志"]))
        body.append(_section("PE 概览", [[k, v] for k, v in rows], ["字段", "值"]))

        imp = pe.get("imports", [])
        imp_rows = [(d, ", ".join(f["name"] for f in d.get("functions", [])[:40])) for d in imp]
        body.append(_section(f"导入表({len(imp)} DLL)", imp_rows, ["DLL", "函数"]))

        exp = pe.get("exports", [])
        body.append(_section(f"导出表({len(exp)})", [[e.get("name", e.get("ordinal")), e.get("address", "")] for e in exp], ["名称", "地址"]))

        res = pe.get("resources", {})
        body.append(f"<h2>资源</h2><p>资源条目数: {res.get('count', 0)}</p>")

        sec = pe.get("security", {})
        body.append(_section("安全特性", [[k, ("<span class='ok'>启用</span>" if v else "<span class='bad'>未启用</span>")] for k, v in sec.items()], ["特性", "状态"]))
    else:
        body.append("<h2>PE 概览</h2><p class='bad'>不是有效的 PE 文件</p>")

    # 字符串(兴趣)
    strs = a.get("strings", [])
    body.append(_section(f"字符串(共{len(strs)}条, 兴趣前100)", [[s.get("offset", 0), s.get("type", ""), s.get("value", "")] for s in strs[:100]], ["偏移", "类型", "内容"]))

    # 反汇编统计
    dis = a.get("disassembly", {})
    body.append(f"<h2>反汇编</h2><p>入口反汇编指令数: {dis.get('count', 0)}</p>")

    # 反编译
    dec = a.get("decompile", {})
    funcs = dec.get("functions", [])
    body.append(f"<h2>反编译</h2><p>导出函数数: {len(funcs)}</p>")

    # UE 专项结构化结论。所有地址和布局都是 evidence-bearing static
    # candidates until their validation_state becomes confirmed.
    ue = a.get("ue", {})
    if isinstance(ue, dict) and ue:
        version = ue.get("engine_version") or ue.get("engine_family") or "未确认"
        body.append(_section("UE 引擎识别", [
            ["版本/家族", version],
            ["识别方式", ue.get("version_method", "static") or "static"],
            ["FName 模型", ue.get("fname") or (ue.get("fname_analysis") or {}).get("model", "unknown")],
            ["解密状态", (ue.get("decryption") or {}).get("status", "unconfirmed")],
        ], ["字段", "值"]))

        majors = ue.get("three_majors", {}) or {}
        global_rows = []
        for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"), ("gworld", "GWorld"), ("gengine", "GEngine")):
            item = majors.get(key) or {}
            value = item.get("target_va")
            rendered = hex(value) if isinstance(value, int) else (value or "未发现静态候选")
            global_rows.append([
                label,
                rendered,
                item.get("validation_state", "unconfirmed"),
                item.get("score", item.get("confidence", 0)),
                item.get("evidence_status", "not_found"),
            ])
        body.append(_section("UE 全局对象候选", global_rows, ["对象", "静态地址候选", "状态", "评分", "证据状态"]))
        candidate_rows = []
        for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"), ("gworld", "GWorld"), ("gengine", "GEngine")):
            for idx, item in enumerate((ue.get("major_candidates", {}) or {}).get(key, [])[:12]):
                candidate_rows.append([label, idx, _hex(item.get("target_va")), _hex(item.get("target_raw")),
                                       _hex(item.get("match_va")), item.get("confidence", 0),
                                       item.get("status", "candidate"), item.get("heuristic_role", "")])
        body.append(_section("UE 三大件/全局候选明细", candidate_rows,
                             ["对象", "序号", "RVA/VA", "文件偏移", "引用 RVA", "置信度", "状态", "启发式角色"]))

        version_layout = ue.get("version_layout") or {}
        fname_layout = version_layout.get("fname") or {}
        object_layout = version_layout.get("gobjects") or {}
        body.append(_section("UE5 版本布局候选", [
            ["版本", version_layout.get("version") or version],
            ["FName 类型", fname_layout.get("model", ue.get("fname") or "unknown")],
            ["FName 索引", fname_layout.get("index_type", "unknown")],
            ["FName 步长", fname_layout.get("stride", "")],
            ["FName Block 位数", fname_layout.get("block_offset_bits", "")],
            ["GObjects 数组", object_layout.get("array_type", "unknown")],
            ["GObjects Chunk", object_layout.get("chunk_size", "")],
            ["FUObjectItem", object_layout.get("fuobject_item_size", "")],
            ["布局状态", version_layout.get("validation_state", "unconfirmed")],
        ], ["字段", "值"]))

        baseline = reflection_baseline = ue.get("reflection", {}) or {}
        baseline_profile = reflection_baseline.get("version_baseline_profile") or {}
        baseline_structures = baseline_profile.get("structures") or {}
        baseline_rows = [
            ["基线 Profile", baseline_profile.get("name", "Default")],
            ["选择状态", reflection_baseline.get("profile_selection_state", "version_baseline_candidate")],
            ["选择原因", baseline_profile.get("selection_reason", "")],
            ["FName Stride", _hex((baseline_profile.get("fname") or {}).get("stride"))],
            ["FName Number", _hex(((baseline_profile.get("fname") or {}).get("number") or {}).get("value"))],
            ["FUObjectItem.Size", _hex(((baseline_profile.get("fuobject_item") or {}).get("size") or {}).get("value"))],
        ]
        for structure_name, fields in baseline_structures.items():
            for field_name, offset in (fields or {}).items():
                baseline_rows.append([f"{structure_name}.{field_name}", _hex((offset or {}).get("value"))])
        body.append(_section("UE 版本基线反射布局（静态候选）", baseline_rows, ["字段", "值"]))

        fname = ue.get("fname_analysis", {}) or {}
        algorithm = fname.get("algorithm", {}) or {}
        body.append(_section("FName / GNames 算法候选", [
            ["模型", fname.get("model", "unknown")],
            ["算法", algorithm.get("name", "未确认")],
            ["状态", fname.get("validation_state", "unconfirmed")],
            ["算法候选数", len(fname.get("algorithm_candidates", []) or [])],
            ["布局候选数", len(fname.get("entry_layout_candidates", []) or [])],
        ], ["字段", "值"]))
        algo_rows = []
        for item in (fname.get("algorithm_candidates") or []):
            algo_rows.append([item.get("id", ""), item.get("name", ""), item.get("model", ""),
                              item.get("confidence", 0), item.get("validation_state", "unconfirmed"),
                              json.dumps(item.get("formula", {}), ensure_ascii=False)])
        body.append(_section("FName 算法候选明细", algo_rows,
                             ["ID", "算法", "模型", "置信度", "状态", "公式"]))

        get_name_xor = fname.get("get_name_xor") or ue.get("get_name_xor") or {}
        body.append(_section("GetName XOR / 明文候选", [
            ["状态", get_name_xor.get("validation_state", "unconfirmed")],
            ["函数标记数", len(get_name_xor.get("function_markers", []) or [])],
            ["XOR 指令候选数", len(get_name_xor.get("xor_candidates", []) or [])],
            ["候选密钥", ", ".join(str(item) for item in (get_name_xor.get("key_candidates") or [])[:16])],
            ["明文候选数", len(get_name_xor.get("plaintext_candidates", []) or [])],
            ["需要运行时验证", "是" if get_name_xor.get("runtime_validation_required", True) else "否"],
        ], ["字段", "值"]))
        xor_rows = [[_hex(x.get("offset")), x.get("opcode", ""), x.get("key_hex", ""),
                     x.get("width", ""), x.get("encoding", ""), x.get("confidence", 0),
                     x.get("validation_state", "candidate")]
                    for x in (get_name_xor.get("xor_candidates") or [])[:40]]
        body.append(_section("GetName XOR 指令/密钥候选明细", xor_rows,
                             ["文件偏移", "Opcode", "候选 Key", "宽度", "编码", "置信度", "状态"]))

        reflection = ue.get("reflection", {}) or {}
        selected = reflection.get("selected_profile", {}) or {}
        body.append(_section("UE 反射结构与字段偏移", [
            ["反射标记", "检测到" if reflection.get("detected") else "未检测到"],
            ["状态", reflection.get("validation_state", "unconfirmed")],
            ["首选候选布局", selected.get("name", "未确认")],
            ["布局置信度", selected.get("confidence", 0)],
            ["字段偏移候选数", len(reflection.get("field_offset_candidates", []) or [])],
        ], ["字段", "值"]))
        offset_rows = []
        for item in (reflection.get("field_offset_candidates") or [])[:160]:
            off = item.get("offset") or {}
            offset_rows.append([item.get("profile", ""), item.get("structure", ""), item.get("field", ""),
                                off.get("hex", _hex(off.get("value"))), item.get("confidence", 0),
                                item.get("validation_state", "candidate")])
        body.append(_section("UE 反射字段偏移明细", offset_rows,
                             ["Profile", "结构", "字段", "偏移", "置信度", "状态"]))

        signals = ue.get("encryption", []) or []
        body.append(_section("保护与加密信号", [
            [item.get("name", ""), item.get("risk", ""), item.get("detail", "")]
            for item in signals if isinstance(item, dict)
        ], ["信号", "风险", "证据"]))
        validation = list((ue.get("decryption") or {}).get("validation_plan") or [])
        validation.extend(reflection.get("validation_plan") or [])
        validation.extend(fname.get("validation_plan") or [])
        if validation:
            body.append("<h2>运行时验证清单</h2><pre>" + _esc("\n".join(dict.fromkeys(validation))) + "</pre>")

        # A dump has no live process. Keep the boundary and the missing
        # evidence visible in every UE report instead of implying execution.
        workflow = a.get("workflow", {}) or {}
        runtime = ue.get("runtime_validation") or workflow.get("runtime_validation") or {}
        if runtime or workflow.get("runtime_evidence_required"):
            execution_available = bool(runtime.get("execution_available", False))
            body.append(_section("运行时证据边界", [
                ["分析模式", runtime.get("analysis_mode", workflow.get("analysis_mode", "static_dump_only"))],
                ["本次是否执行目标", "已执行" if execution_available else "未执行（Dump 仅静态分析）"],
                ["证据状态", runtime.get("evidence_status", "not_collected")],
                ["证据来源", runtime.get("evidence_source", "none")],
                ["是否需要运行时验证", "是" if runtime.get("requires_runtime_execution", True) else "否"],
                ["边界说明", runtime.get("reason", "Dump 文件不能观察进程内存、对象遍历或运行时解密")],
            ], ["字段", "值"]))
            plan = runtime.get("collection_plan") or []
            if plan:
                body.append(_section("运行时采集计划", [
                    [item.get("id", ""), item.get("item", ""),
                     item.get("evidence", ""), item.get("acceptance", "")]
                    for item in plan if isinstance(item, dict)
                ], ["编号", "采集项", "需要记录的证据", "通过标准"]))
            limitations = runtime.get("static_limitations") or []
            if limitations:
                body.append("<h2>静态分析限制</h2><pre>" + _esc("\n".join(str(item) for item in limitations)) + "</pre>")

        # UE AI 辅助结论(优先展示 AI 判定的精确地址与算法)
        ai_assist_html = _ai_assist_html(ue)
        if ai_assist_html:
            body.append(ai_assist_html)

    # Unity 专项结果。Metadata 的状态必须区分明文、已验证解密、仅头修复、
    # 损坏以及尚待运行时证据，避免报告把结构检查误写成解密完成。
    unity = a.get("unity", {})
    if isinstance(unity, dict) and unity:
        scan = unity.get("scan", {}) or {}
        validation = (
            scan.get("validation")
            or (scan.get("detect", {}) or {}).get("structure_validation", {})
            or {}
        )
        version_info = unity.get("version", {}) or {}
        build = unity.get("buildtype", {}) or {}
        assembly = unity.get("assembly", {}) or {}
        decrypt = unity.get("decrypt", {}) or {}
        sdk = unity.get("sdk", {}) or {}
        unity_version = (
            version_info.get("version") or unity.get("unity_version") or "未识别"
        )
        build_type = build.get("build_type") or unity.get("build_type") or assembly.get("mode") or "Other"
        body.append(_section("Unity 构建识别", [
            ["版本", unity_version],
            ["构建类型", build_type],
            ["构建置信度", build.get("confidence", "")],
            ["GameAssembly", assembly.get("gameassembly_path") or unity.get("gameassembly_path", "")],
            ["Metadata", decrypt.get("source_metadata_path") or decrypt.get("metadata") or assembly.get("metadata_path") or unity.get("metadata_path", "")],
        ], ["字段", "值"]))

        if validation:
            body.append(_section("Unity 目录结构认证", [
                ["认证结果", "通过" if validation.get("valid") else "未通过"],
                ["认证状态", validation.get("status", "not_checked")],
                ["认证置信度", validation.get("confidence", "none")],
                ["SDK 输入可用", "是" if validation.get("sdk_eligible") else "否"],
                ["判定说明", validation.get("reason", "")],
            ], ["字段", "值"]))
            evidence = validation.get("evidence", []) or []
            if evidence:
                body.append(_section("Unity 结构证据", [
                    [item.get("kind", ""), item.get("path", ""), item.get("size", 0)]
                    for item in evidence if isinstance(item, dict)
                ], ["类型", "路径", "大小"] ))
            missing = validation.get("missing", []) or []
            if missing:
                body.append("<h3>缺失的结构证据</h3><pre>" + _esc("\n".join(str(item) for item in missing)) + "</pre>")

        if decrypt or build_type == "IL2CPP":
            body.append(_section("IL2CPP Metadata 与解密决策", [
                ["Metadata 状态", decrypt.get("status", unity.get("metadata_status", "not_checked"))],
                ["发现加密证据", "是" if decrypt.get("encrypted") else "否"],
                ["是否需要解密", "是" if decrypt.get("decryption_required") else "否"],
                ["是否实际执行解密", "是" if decrypt.get("decryption_attempted") else "否"],
                ["解密状态", decrypt.get("decryption_status", unity.get("decryption_status", "not_checked"))],
                ["验证通过", "是" if decrypt.get("verified") else "否"],
                ["恢复 Recipe", decrypt.get("recipe", "")],
                ["恢复 Manifest", decrypt.get("recovery_manifest", "")],
                ["解密产物", decrypt.get("decrypted_path", "")],
                ["说明", decrypt.get("note", decrypt.get("reason", ""))],
            ], ["字段", "值"]))
            diagnostics = decrypt.get("diagnostics") or decrypt.get("decryption_diagnostics") or []
            if diagnostics:
                body.append("<h2>Metadata 诊断</h2><pre>" + _esc("\n".join(str(item) for item in diagnostics)) + "</pre>")

        # Candidates are evidence-only: the report must expose why SDK export
        # remains blocked instead of hiding renamed/encrypted metadata blobs.
        candidates = decrypt.get("metadata_candidates") or assembly.get("metadata_candidates") or {}
        candidate_items = candidates.get("candidates", []) if isinstance(candidates, dict) else []
        if candidates:
            body.append(_section("IL2CPP Metadata Candidate Scan", [
                ["Scan status", candidates.get("status", "not_checked")],
                ["Candidate count", candidates.get("candidate_count", len(candidate_items))],
                ["Conclusion", candidates.get("candidate_summary", "")],
                ["SDK input eligible", "No - candidate bytes are not structurally/decryption verified"],
            ], ["Field", "Value"]))
        if candidate_items:
            body.append(_section("Candidate Metadata Evidence", [
                [
                    item.get("relative_path", item.get("path", "")),
                    item.get("size", 0),
                    item.get("entropy", ""),
                    item.get("head_hex", ""),
                    "yes" if item.get("magic_found") else "no",
                    "; ".join(str(part) for part in item.get("candidate_reason", []) or []),
                ]
                for item in candidate_items if isinstance(item, dict)
            ], ["Path", "Size", "Entropy", "First 16 bytes", "Valid magic", "Evidence"]))

        loader_hints = decrypt.get("gameassembly_loader_hints") or assembly.get("gameassembly_metadata_hints") or {}
        if loader_hints:
            body.append(_section("GameAssembly Metadata Loader Clues (static)", [
                ["Inspected file", loader_hints.get("path", "")],
                ["Loader signal", loader_hints.get("loader_signal", "none")],
                ["Standard metadata path string", "yes" if loader_hints.get("standard_metadata_path_found") else "no"],
            ], ["Field", "Value"]))
            hints = list(loader_hints.get("marker_hits", []) or []) + list(loader_hints.get("api_hits", []) or [])
            if hints:
                body.append(_section("GameAssembly String Hits", [
                    [item.get("marker", ""), item.get("count", 0), ", ".join(hex(value) for value in item.get("offsets", []) or [])]
                    for item in hints if isinstance(item, dict)
                ], ["String", "Count", "File offsets (first 8)"]))
            limitations = loader_hints.get("limitations", []) or []
            if limitations:
                body.append("<h3>Static Clue Limitations</h3><pre>" + _esc("\n".join(str(item) for item in limitations)) + "</pre>")

        if sdk:
            body.append(_section("Unity SDK 交付", [
                ["状态", sdk.get("status", "not_started")],
                ["交付完整", "是" if sdk.get("delivery_complete") else "否"],
                ["Dump.cs", sdk.get("dump_cs", "")],
                ["脚本 JSON", sdk.get("script_json", "")],
                ["C++ 结构头", sdk.get("il2cpp_h", sdk.get("cpp_dir", ""))],
                ["DummyDll 目录", sdk.get("dummy_dir", "")],
                ["DummyDll 数量", len(sdk.get("dummy_dlls", []) or [])],
                ["SDK JSON", sdk.get("sdk_json", "")],
                ["关联 DLL", sdk.get("dll", sdk.get("dll_source", ""))],
                ["Manifest", sdk.get("manifest", "")],
            ], ["字段", "值"]))

        dynamic = decrypt.get("runtime_validation") or unity.get("runtime_validation") or {}
        if dynamic and dynamic.get("required"):
            body.append(_section("Unity 运行时解密验证要求", [
                ["状态", dynamic.get("status", "pending")],
                ["原因", dynamic.get("reason", "")],
                ["Metadata", (dynamic.get("inputs") or {}).get("metadata", "")],
                ["GameAssembly", (dynamic.get("inputs") or {}).get("gameassembly", "")],
                ["同构建要求", "是" if (dynamic.get("inputs") or {}).get("same_build_required") else "否"],
            ], ["字段", "值"]))
            for heading, key in (("采集步骤", "steps"), ("需保留的证据", "evidence"), ("验收标准", "acceptance")):
                items = dynamic.get(key) or []
                if items:
                    body.append(f"<h3>{heading}</h3><pre>" + _esc("\n".join(str(item) for item in items)) + "</pre>")

    # 网络
    net = a.get("network", {})
    if net:
        conns = net.get("connections", [])
        body.append(_section("网络连接", [[c["client"]["ip"], c["client"]["port"], c["server"]["ip"], c["server"]["port"], c.get("server_name", ""), c["packets"], c["bytes"]] for c in conns], ["源IP", "源端口", "目标IP", "目标端口", "SNI/域名", "包数", "字节"]))
        body.append(_section("DNS 查询", [[q["query"] for q in net.get("dns_queries", [])] and dns_rows(net.get("dns_queries", []))]))
        body.append(_section("HTTP 请求", [[h.get("src"), h.get("dst"), h.get("request") or h.get("response", "")] for h in net.get("http_requests", [])[:100]], ["源", "目标", "请求/响应"]))

    # 动态行为
    beh = a.get("behavior", {})
    if beh:
        np = beh.get("new_processes", [])
        body.append(_section("新增进程", [[p.get("pid"), p.get("name"), p.get("cmdline", "")[:100]] for p in np[:100]], ["PID", "进程", "命令行"]))
        body.append(_section("文件变更", [[f.get("path")] for f in beh.get("files", [])[:100]], ["路径"]))
        body.append(_section("注册表变更", [[r.get("key")] for r in beh.get("registry", [])[:50]], ["键"]))

    # 通用 AI 节点输出
    generic_ai = _generic_ai_html(a)
    if generic_ai:
        body.append(generic_ai)

    return _HTML_TPL.format(name=_esc(s.get("file_name", "")), ts=report.get("generated_at", ""), body="".join(body))


def dns_rows(qs):
    return [q.get("query", "") for q in qs]


def to_markdown(report: dict) -> str:
    a = report.get("analysis", {})
    s = report.get("sample", {})
    pe = a.get("pe", {})
    out = []
    out.append(f"# REVLab 分析报告: {s.get('file_name','')}\n")
    out.append(f"- SHA256: `{s.get('sha256','')}`")
    out.append(f"- MD5: `{s.get('md5','')}`")
    if pe.get("is_pe"):
        pk = pe.get("packer", {})
        out.append(f"- 架构: {pe.get('machine','')} / {pe.get('subsystem','')}")
        out.append(f"- ImageBase: `{pe.get('image_base','')}`")
        out.append(f"- 入口点: `{pe.get('entry_point','')}`")
        out.append(f"- 节区数量: `{pe.get('number_of_sections', len(pe.get('sections', []) or []))}`")
        out.append(f"- 包壳判定: **{pk.get('verdict','')}** (confidence {pk.get('confidence',0)}%)")
        out.append("\n## 节区\n")
        for sec in pe.get("sections", []):
            out.append(f"- `{sec.get('name','')}` VA={sec.get('virtual_address','')} 熵={sec.get('entropy',0)} 标志={', '.join(sec.get('flags',[]))}")
    strs = a.get("strings", [])
    if strs:
        out.append("\n## 兴趣字符串(前50)\n")
        for st in strs[:50]:
            out.append(f"- `{st.get('value','')}`")
    ue = a.get("ue", {})
    if isinstance(ue, dict) and ue:
        out.append("\n## UE 专项结论\n")
        out.append(f"- 引擎版本/家族: **{ue.get('engine_version') or ue.get('engine_family') or '未确认'}**")
        for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"), ("gworld", "GWorld"), ("gengine", "GEngine")):
            item = (ue.get("three_majors") or {}).get(key) or {}
            value = item.get("target_va")
            rendered = hex(value) if isinstance(value, int) else (value or "未发现静态候选")
            out.append(
                f"- {label}: `{rendered}` ({item.get('validation_state', 'unconfirmed')}, "
                f"score {item.get('score', item.get('confidence', 0))}, "
                f"evidence {item.get('evidence_status', 'not_found')})"
            )
        out.append("\n### 三大件/全局候选明细\n")
        out.append("| 对象 | 序号 | RVA/VA | 文件偏移 | 引用 RVA | 置信度 | 状态 | 角色 |\n|---|---:|---:|---:|---:|---:|---|---|")
        for key, label in (("gobjects", "GObjects"), ("gnames", "GNames/FNamePool"), ("gworld", "GWorld"), ("gengine", "GEngine")):
            for idx, item in enumerate((ue.get("major_candidates", {}) or {}).get(key, [])[:12]):
                out.append(f"| {label} | {idx} | `{_hex(item.get('target_va'))}` | `{_hex(item.get('target_raw'))}` | `{_hex(item.get('match_va'))}` | {item.get('confidence', 0)} | {item.get('status', 'candidate')} | {item.get('heuristic_role', '')} |")
        fname = ue.get("fname_analysis") or {}
        algo = fname.get("algorithm") or {}
        out.append(f"- FName 算法: {algo.get('name', '未确认')} ({fname.get('validation_state', 'unconfirmed')})")
        out.append("\n### FName 算法候选明细\n")
        for item in (fname.get("algorithm_candidates") or []):
            out.append(f"- `{item.get('id','')}` **{item.get('name','')}**; model=`{item.get('model','')}`; confidence={item.get('confidence', 0)}; state=`{item.get('validation_state','unconfirmed')}`; formula=`{json.dumps(item.get('formula',{}), ensure_ascii=False)}`")
        version_layout = ue.get("version_layout") or {}
        fname_layout = version_layout.get("fname") or {}
        object_layout = version_layout.get("gobjects") or {}
        out.append(
            f"- UE5 布局候选: 版本 `{version_layout.get('version') or ue.get('engine_version') or ''}`, "
            f"FName `{fname_layout.get('index_type', ue.get('fname') or 'unknown')}`/stride `{fname_layout.get('stride', '')}`, "
            f"GObjects `{object_layout.get('array_type', 'unknown')}`/chunk `{object_layout.get('chunk_size', '')}` "
            f"({version_layout.get('validation_state', 'unconfirmed')})"
        )
        get_name_xor = fname.get("get_name_xor") or ue.get("get_name_xor") or {}
        out.append("\n### GetName XOR 指令与密钥候选\n")
        out.append("| 文件偏移 | Opcode | Key | 宽度 | 编码 | 置信度 | 状态 |\n|---:|---|---|---:|---|---:|---|")
        for item in (get_name_xor.get('xor_candidates') or [])[:40]:
            out.append(f"| `{_hex(item.get('offset'))}` | `{item.get('opcode','')}` | `{item.get('key_hex','')}` | {item.get('width','')} | {item.get('encoding','')} | {item.get('confidence',0)} | {item.get('validation_state','candidate')} |")
        out.append(
            f"- GetName XOR: 状态 `{get_name_xor.get('validation_state', 'unconfirmed')}`, "
            f"指令候选 {len(get_name_xor.get('xor_candidates', []) or [])} 项, "
            f"明文候选 {len(get_name_xor.get('plaintext_candidates', []) or [])} 项"
        )
        reflection = ue.get("reflection") or {}
        out.append(f"- 反射字段候选: {len(reflection.get('field_offset_candidates', []) or [])} 项 ({reflection.get('validation_state', 'unconfirmed')})")
        out.append("\n### UE 反射结构与字段偏移明细\n")
        out.append("| Profile | 结构 | 字段 | 偏移 | 置信度 | 状态 |\n|---|---|---|---:|---:|---|")
        for item in (reflection.get('field_offset_candidates') or [])[:160]:
            off = item.get('offset') or {}
            out.append(f"| {item.get('profile','')} | {item.get('structure','')} | {item.get('field','')} | `{off.get('hex', _hex(off.get('value')))}` | {item.get('confidence',0)} | {item.get('validation_state','candidate')} |")
        signals = [item.get("name") for item in (ue.get("encryption") or []) if isinstance(item, dict)]
        out.append(f"- 保护/加密信号: {', '.join(signals) if signals else '无'}")
        workflow = a.get("workflow", {}) or {}
        runtime = ue.get("runtime_validation") or workflow.get("runtime_validation") or {}
        if runtime or workflow.get("runtime_evidence_required"):
            out.append("\n### 运行时证据边界\n")
            out.append(f"- 分析模式: `{runtime.get('analysis_mode', workflow.get('analysis_mode', 'static_dump_only'))}`")
            out.append(f"- 本次是否执行目标: **{'是' if runtime.get('execution_available', False) else '否（Dump 仅静态分析）'}**")
            out.append(f"- 证据状态: `{runtime.get('evidence_status', 'not_collected')}`; 来源: `{runtime.get('evidence_source', 'none')}`")
            out.append(f"- 边界说明: {runtime.get('reason', 'Dump 文件不能观察进程内存、对象遍历或运行时解密。')}")
            plan = runtime.get('collection_plan') or []
            if plan:
                out.append("\n#### 运行时采集计划\n")
                for item in plan:
                    if isinstance(item, dict):
                        out.append(f"- **{item.get('id', '')}**: {item.get('item', '')}; 证据: {item.get('evidence', '')}; 通过标准: {item.get('acceptance', '')}")
            limitations = runtime.get('static_limitations') or []
            if limitations:
                out.append("\n#### 静态分析限制\n")
                out.extend(f"- {item}" for item in limitations)
        out.extend(_ai_assist_markdown(ue))
    unity = a.get("unity", {})
    if isinstance(unity, dict) and unity:
        out.append("\n## Unity 专项结论\n")
        version_info = unity.get("version", {}) or {}
        build = unity.get("buildtype", {}) or {}
        assembly = unity.get("assembly", {}) or {}
        decrypt = unity.get("decrypt", {}) or {}
        sdk = unity.get("sdk", {}) or {}
        out.append(f"- Unity 版本: **{version_info.get('version') or unity.get('unity_version') or '未识别'}**")
        out.append(f"- 构建类型: **{build.get('build_type') or unity.get('build_type') or assembly.get('mode') or 'Other'}**")
        if decrypt:
            out.append(f"- Metadata 状态: `{decrypt.get('status', unity.get('metadata_status', 'not_checked'))}`")
            out.append(f"- 加密证据/是否解密/是否执行: {'是' if decrypt.get('encrypted') else '否'} / {'是' if decrypt.get('decryption_required') else '否'} / {'是' if decrypt.get('decryption_attempted') else '否'}")
            out.append(f"- 解密验证: `{decrypt.get('decryption_status', 'not_checked')}`; 已验证: {'是' if decrypt.get('verified') else '否'}")
            if decrypt.get("recipe"):
                out.append(f"- 恢复 Recipe: `{decrypt.get('recipe')}`")
            if decrypt.get("recovery_manifest"):
                out.append(f"- 恢复 Manifest: `{decrypt.get('recovery_manifest')}`")
        if sdk:
            out.append(f"- SDK 交付: `{sdk.get('status', 'not_started')}`; 完整: {'是' if sdk.get('delivery_complete') else '否'}")
            out.append(f"- Dump.cs: `{sdk.get('dump_cs', '')}`")
            out.append(f"- C++ 结构头: `{sdk.get('il2cpp_h', sdk.get('cpp_dir', ''))}`")
            out.append(f"- DummyDll: `{sdk.get('dummy_dir', '')}`; 数量: {len(sdk.get('dummy_dlls', []) or [])}")
        candidates = decrypt.get("metadata_candidates") or assembly.get("metadata_candidates") or {}
        candidate_items = candidates.get("candidates", []) if isinstance(candidates, dict) else []
        if candidates:
            out.append(
                f"- Metadata candidate scan: `{candidates.get('status', 'not_checked')}`; "
                f"count: {candidates.get('candidate_count', len(candidate_items))}"
            )
            out.append(f"- Candidate conclusion: {candidates.get('candidate_summary', '')}")
        for item in candidate_items:
            if not isinstance(item, dict):
                continue
            out.append(
                f"  - `{item.get('relative_path', item.get('path', ''))}`; "
                f"size={item.get('size', 0)}, entropy={item.get('entropy', '')}, "
                f"magic={'yes' if item.get('magic_found') else 'no'}, "
                f"head={item.get('head_hex', '')}"
            )
        loader_hints = decrypt.get("gameassembly_loader_hints") or assembly.get("gameassembly_metadata_hints") or {}
        if loader_hints:
            out.append(
                f"- GameAssembly static loader clues: `{loader_hints.get('loader_signal', 'none')}`; "
                f"standard metadata path string: "
                f"{'yes' if loader_hints.get('standard_metadata_path_found') else 'no'}"
            )
            for item in list(loader_hints.get("marker_hits", []) or []) + list(loader_hints.get("api_hits", []) or []):
                if isinstance(item, dict):
                    out.append(
                        f"  - `{item.get('marker', '')}`: {item.get('count', 0)} hit(s) "
                        f"at {item.get('offsets', [])}"
                    )
        dynamic = decrypt.get("runtime_validation") or unity.get("runtime_validation") or {}
        if dynamic and dynamic.get("required"):
            out.append("\n### Unity 运行时解密验证要求\n")
            out.append(f"- 状态: `{dynamic.get('status', 'pending')}`; 原因: {dynamic.get('reason', '')}")
            inputs = dynamic.get("inputs") or {}
            if inputs:
                out.append(f"- 输入: Metadata `{inputs.get('metadata', '')}`; GameAssembly `{inputs.get('gameassembly', '')}`; 同构建: {'是' if inputs.get('same_build_required') else '否'}")
            for heading, key in (("采集步骤", "steps"), ("需保留的证据", "evidence"), ("验收标准", "acceptance")):
                items = dynamic.get(key) or []
                if items:
                    out.append(f"\n#### {heading}\n")
                    out.extend(f"- {item}" for item in items)
    net = a.get("network", {})
    if net:
        out.append("\n## 网络\n")
        for c in net.get("connections", [])[:50]:
            out.append(f"- {c['client']['ip']}:{c['client']['port']} -> {c['server']['ip']}:{c['server']['port']} ({c.get('server_name','')}) {c['packets']}pk/{c['bytes']}B")
        for q in net.get("dns_queries", [])[:50]:
            out.append(f"- DNS: {q.get('query','')}")
    out.extend(_generic_ai_markdown(a))
    return "\n".join(out)


def save_report(report: dict, out_dir: Path, name: str) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Keep the existing extension-free behavior while ensuring callers cannot
    # create nested paths or invalid Windows names through a report title.
    stem = analysis_report_name(name)
    jp = out_dir / f"{stem}.json"
    jp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    hp = out_dir / f"{stem}.html"
    hp.write_text(to_html(report), encoding="utf-8")
    mp = out_dir / f"{stem}.md"
    mp.write_text(to_markdown(report), encoding="utf-8")
    paths = {"json": str(jp), "html": str(hp), "markdown": str(mp)}

    # Workflow runs keep the complete report bundle under report/, while the
    # primary Markdown document is also published at the run root so opening a
    # run folder immediately exposes the human-readable result.  The root copy
    # is a real file (not a shortcut) so exported run folders remain portable.
    if out_dir.name.lower() == "report":
        run_root = out_dir.parent
        root_markdown = run_root / mp.name
        if root_markdown.resolve(strict=False) != mp.resolve(strict=False):
            shutil.copy2(mp, root_markdown)
        paths["root_markdown"] = str(root_markdown)
    return paths
