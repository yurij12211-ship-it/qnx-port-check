"""Output formats: terminal text, JSON, SARIF 2.1.0 (GitHub code scanning) and Markdown."""
import json

from . import __version__
from .rules import RULES_BY_ID, DOCS, ERROR, WARNING, INFO
from .scanner import summarize

COLORS = {ERROR: "\033[31m", WARNING: "\033[33m", INFO: "\033[36m"}
RESET = "\033[0m"


def text(result, color=True, show_info=False):
    f = result["findings"]
    s = summarize(f)
    out = []
    for x in f:
        if x.severity == INFO and not show_info:
            continue
        sev = x.severity.upper()
        tag = f"{COLORS[x.severity]}{sev:7}{RESET}" if color else f"{sev:7}"
        ver = " [verified in SDP]" if x.verified else ""
        out.append(f"{tag} {x.path}:{x.line}  {x.rule} {x.title}{ver}")
        out.append(f"        {x.snippet}")
        out.append(f"        fix: {x.fix}")
    c = s["counts"]
    sdp = result.get("sdp")
    out.append("")
    out.append(f"Scanned {result['files']} files"
               + (f" against QNX SDP {sdp['version']}" if sdp else " (static rules only; set QNX_TARGET to verify headers)"))
    sk = result.get("skipped_platform_files") or []
    if sk:
        out.append(f"Skipped {len(sk)} files built only for other platforms ({', '.join(sk[:4])}{', ...' if len(sk) > 4 else ''}); use --platform-files to include them.")
    out.append(f"{c[ERROR]} errors, {c[WARNING]} warnings, {c[INFO]} info{'' if show_info or not c[INFO] else ' (hidden, use --show-info)'}. "
               f"Verdict: {s['verdict']} (about {s['estimated_hours']:g} h).")
    return "\n".join(out)


def as_json(result):
    return json.dumps({
        "tool": "qnx-port-check", "version": __version__, "target": "QNX 8.0",
        "files": result["files"], "sdp": result.get("sdp"),
        "skipped_platform_files": result.get("skipped_platform_files", []),
        "summary": summarize(result["findings"]),
        "findings": [x.to_dict() for x in result["findings"]],
    }, indent=2)


def sarif(result):
    level = {ERROR: "error", WARNING: "warning", INFO: "note"}
    used = sorted({x.rule for x in result["findings"]})
    rules = []
    for rid in used:
        r = RULES_BY_ID.get(rid)
        if r:
            rules.append({"id": rid, "name": r.title, "shortDescription": {"text": r.title},
                          "fullDescription": {"text": r.why}, "help": {"text": r.fix},
                          "helpUri": DOCS, "defaultConfiguration": {"level": level[r.severity]}})
        else:
            rules.append({"id": rid, "name": "Header missing from QNX SDP",
                          "shortDescription": {"text": "Header missing from QNX SDP"}})
    results = [{
        "ruleId": x.rule, "level": level[x.severity],
        "message": {"text": f"{x.title}. {x.why} Fix: {x.fix}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": x.path},
                                            "region": {"startLine": x.line}}}],
    } for x in result["findings"]]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "qnx-port-check", "version": __version__,
                                      "informationUri": "https://github.com/yurij12211-ship-it/qnx-port-check",
                                      "rules": rules}},
                  "results": results}],
    }, indent=2)


def markdown(result, project="project"):
    f = result["findings"]
    s = summarize(f)
    c = s["counts"]
    sdp = result.get("sdp")
    lines = [f"# QNX 8.0 porting report: {project}", "",
             f"**Verdict:** {s['verdict']}  ",
             f"**Findings:** {c[ERROR]} errors, {c[WARNING]} warnings, {c[INFO]} info in {result['files']} files  ",
             f"**Rough effort:** ~{s['estimated_hours']:g} hours  ",
             f"**Header check:** " + (f"verified against QNX SDP {sdp['version']}" if sdp else "static rules only"), ""]
    by_rule = {}
    for x in f:
        by_rule.setdefault(x.rule, []).append(x)
    for rid, items in by_rule.items():
        first = items[0]
        lines += [f"## {first.severity.upper()} {rid}: {first.title} ({len(items)})", "",
                  first.why, "", f"**Fix:** {first.fix}", ""]
        for x in items[:20]:
            lines.append(f"- `{x.path}:{x.line}` `{x.snippet}`" + (" (verified)" if x.verified else ""))
        if len(items) > 20:
            lines.append(f"- ... and {len(items) - 20} more")
        lines.append("")
    if not f:
        lines.append("No known Linux-only constructs found. Next step: build with the QNX toolchain (`qnx-port-check toolchain`).")
    return "\n".join(lines)
