"""报告生成:JSON 主报告 + 可读 HTML/Markdown"""
import json
import time
from pathlib import Path

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
        out.append(f"- 入口点: `{pe.get('entry_point','')}`")
        out.append(f"- 包壳判定: **{pk.get('verdict','')}** (confidence {pk.get('confidence',0)}%)")
        out.append("\n## 节区\n")
        for sec in pe.get("sections", []):
            out.append(f"- `{sec.get('name','')}` VA={sec.get('virtual_address','')} 熵={sec.get('entropy',0)} 标志={', '.join(sec.get('flags',[]))}")
    strs = a.get("strings", [])
    if strs:
        out.append("\n## 兴趣字符串(前50)\n")
        for st in strs[:50]:
            out.append(f"- `{st.get('value','')}`")
    net = a.get("network", {})
    if net:
        out.append("\n## 网络\n")
        for c in net.get("connections", [])[:50]:
            out.append(f"- {c['client']['ip']}:{c['client']['port']} -> {c['server']['ip']}:{c['server']['port']} ({c.get('server_name','')}) {c['packets']}pk/{c['bytes']}B")
        for q in net.get("dns_queries", [])[:50]:
            out.append(f"- DNS: {q.get('query','')}")
    return "\n".join(out)


def save_report(report: dict, out_dir: Path, name: str) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = name.replace(".", "_").replace(" ", "_")
    jp = out_dir / f"{stem}.json"
    jp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    hp = out_dir / f"{stem}.html"
    hp.write_text(to_html(report), encoding="utf-8")
    mp = out_dir / f"{stem}.md"
    mp.write_text(to_markdown(report), encoding="utf-8")
    return {"json": str(jp), "html": str(hp), "markdown": str(mp)}
