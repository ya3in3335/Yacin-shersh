"""Render scan findings as text, markdown or JSON."""

from __future__ import annotations

import json

from .utils import SEVERITY_ORDER

SEV_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _sorted(findings):
    return sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))


def to_json(target: str, findings) -> str:
    return json.dumps(
        {
            "target": target,
            "summary": _summary(findings),
            "findings": [f.as_dict() for f in _sorted(findings)],
        },
        indent=2,
        ensure_ascii=False,
    )


def _summary(findings) -> dict:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def to_text(target: str, findings) -> str:
    lines = [f"Scan report for: {target}", "=" * 60]
    counts = _summary(findings)
    lines.append(
        "Summary: "
        + ", ".join(f"{SEV_LABEL[s]}={counts.get(s, 0)}" for s in
                     ["critical", "high", "medium", "low", "info"])
    )
    lines.append("")
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for f in _sorted(findings):
        lines.append(f"[{SEV_LABEL[f.severity]}] {f.title}  ({f.check})")
        lines.append(f"    target: {f.target}")
        if f.detail:
            lines.append(f"    detail: {f.detail}")
        if f.evidence:
            lines.append(f"    evidence: {f.evidence}")
        if f.remediation:
            lines.append(f"    fix: {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def to_markdown(target: str, findings) -> str:
    counts = _summary(findings)
    out = [f"# Vulnerability scan: `{target}`", ""]
    out.append(
        "| Severity | Count |\n|---|---|\n"
        + "\n".join(
            f"| {SEV_LABEL[s]} | {counts.get(s, 0)} |"
            for s in ["critical", "high", "medium", "low", "info"]
        )
    )
    out.append("")
    for f in _sorted(findings):
        out.append(f"### [{SEV_LABEL[f.severity]}] {f.title}")
        out.append(f"- **check:** {f.check}")
        out.append(f"- **target:** {f.target}")
        if f.detail:
            out.append(f"- **detail:** {f.detail}")
        if f.evidence:
            out.append(f"- **evidence:** `{f.evidence}`")
        if f.remediation:
            out.append(f"- **fix:** {f.remediation}")
        out.append("")
    return "\n".join(out)


RENDERERS = {"text": to_text, "json": to_json, "markdown": to_markdown}
