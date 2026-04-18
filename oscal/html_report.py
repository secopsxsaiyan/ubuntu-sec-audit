#!/usr/bin/env python3
"""
Ubuntu Security Audit — HTML Report Generator
Reads the findings JSONL file and produces a self-contained HTML report.
No external dependencies — stdlib only, Python 3.6+.
"""
import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "satisfied":"#2ecc71",
}

FRAMEWORK_LABELS = {
    "nist":     "NIST SP 800-53 Rev 5",
    "cis":      "CIS Ubuntu 24.04 LTS",
    "iso27001": "ISO/IEC 27001:2022",
    "soc2":     "SOC 2 TSC 2017",
}


def severity_from_points(points: int) -> str:
    if points >= 20:  return "CRITICAL"
    if points >= 10:  return "HIGH"
    if points >= 5:   return "MEDIUM"
    return "LOW"


def load_findings(path: str) -> list:
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "severity" not in obj:
                    obj["severity"] = (
                        severity_from_points(obj.get("points", 0))
                        if obj.get("status") == "not-satisfied"
                        else "satisfied"
                    )
                findings.append(obj)
            except json.JSONDecodeError:
                pass
    return findings


def gauge_svg(score: int, grade: str) -> str:
    color = "#c0392b" if score < 60 else "#e67e22" if score < 80 else "#27ae60"
    pct = score / 100
    r = 60
    circ = 2 * 3.14159 * r
    dash = pct * circ
    return f"""
    <svg viewBox="0 0 160 100" width="160" height="100" class="gauge">
      <circle cx="80" cy="80" r="{r}" fill="none" stroke="#e0e0e0" stroke-width="14"
              stroke-dasharray="{circ:.1f}" stroke-dashoffset="0"
              transform="rotate(-180 80 80)"/>
      <circle cx="80" cy="80" r="{r}" fill="none" stroke="{color}" stroke-width="14"
              stroke-dasharray="{dash:.1f} {circ:.1f}"
              stroke-linecap="round"
              transform="rotate(-180 80 80)"/>
      <text x="80" y="72" text-anchor="middle" font-size="26" font-weight="bold" fill="{color}">{score}</text>
      <text x="80" y="88" text-anchor="middle" font-size="13" fill="#666">Grade {grade}</text>
    </svg>"""


def render(findings: list, score: int, grade: str, hostname: str,
           frameworks: list, duration: str) -> str:

    failed = [f for f in findings if f.get("status") == "not-satisfied"]
    passed = [f for f in findings if f.get("status") == "satisfied"]

    failed.sort(key=lambda x: (
        SEVERITY_ORDER.get(x.get("severity", "LOW"), 4),
        -x.get("points", 0)
    ))

    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for f in failed:
        counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1

    fw_labels = ", ".join(FRAMEWORK_LABELS.get(fw, fw) for fw in frameworks)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    gauge = gauge_svg(score, grade)

    # Build findings rows
    rows = []
    for i, f in enumerate(failed):
        sev = f.get("severity", "LOW")
        sev_color = SEVERITY_COLORS.get(sev, "#888")
        check_id = html.escape(f.get("check_id", ""))
        title    = html.escape(f.get("title", ""))
        pts      = f.get("points", 0)
        evidence = html.escape(f.get("evidence", ""))
        remedy   = html.escape(f.get("remediation", ""))
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{sev_color}">{sev}</span></td>
          <td class="mono">{check_id}</td>
          <td>
            <details>
              <summary>{title}</summary>
              <p class="evidence">{evidence}</p>
              <pre class="remedy">{remedy}</pre>
            </details>
          </td>
          <td class="pts">{pts}</td>
        </tr>""")

    passed_rows = []
    for f in passed:
        passed_rows.append(
            f'<li class="mono">{html.escape(f.get("check_id",""))}</li>'
        )

    fw_badges = "".join(
        f'<span class="fw-badge">{html.escape(FRAMEWORK_LABELS.get(fw, fw))}</span>'
        for fw in frameworks
    )

    score_color = "#c0392b" if score < 60 else "#e67e22" if score < 80 else "#27ae60"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ubuntu Security Audit — {html.escape(hostname)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        background:#f5f6fa;color:#333;line-height:1.5}}
  .header{{background:#1a1a2e;color:#fff;padding:24px 32px;display:flex;
           align-items:center;gap:32px;flex-wrap:wrap}}
  .header-text h1{{font-size:1.4rem;font-weight:600}}
  .header-text p{{opacity:.75;font-size:.9rem;margin-top:4px}}
  .gauge{{display:block}}
  .fw-badge{{display:inline-block;background:#2c3e50;color:#ecf0f1;
             border-radius:4px;padding:2px 8px;font-size:.75rem;margin:2px}}
  .summary{{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap}}
  .card{{background:#fff;border-radius:8px;padding:16px 24px;flex:1;
         min-width:120px;box-shadow:0 1px 4px rgba(0,0,0,.08);text-align:center}}
  .card .num{{font-size:2rem;font-weight:700}}
  .card .lbl{{font-size:.8rem;color:#666;text-transform:uppercase;letter-spacing:.05em}}
  .critical{{color:#c0392b}}.high{{color:#e67e22}}
  .medium{{color:#d4ac0d}}.low{{color:#27ae60}}.passed{{color:#16a085}}
  .main{{padding:0 32px 32px}}
  table{{width:100%;border-collapse:collapse;background:#fff;
         border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  th{{background:#2c3e50;color:#fff;padding:10px 14px;text-align:left;
      font-size:.85rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:10px 14px;border-bottom:1px solid #f0f0f0;vertical-align:top;font-size:.9rem}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#fafafa}}
  .badge{{display:inline-block;color:#fff;border-radius:4px;
          padding:2px 8px;font-size:.75rem;font-weight:600;white-space:nowrap}}
  .mono{{font-family:'SF Mono','Fira Code',monospace;font-size:.82rem}}
  .pts{{text-align:center;font-weight:600}}
  details summary{{cursor:pointer;font-weight:500}}
  details summary:hover{{color:#2980b9}}
  .evidence{{margin-top:8px;color:#555;font-size:.85rem;white-space:pre-wrap}}
  pre.remedy{{background:#1e1e2e;color:#cdd6f4;padding:12px;border-radius:6px;
              font-size:.82rem;margin-top:8px;overflow-x:auto;white-space:pre-wrap}}
  .passed-section{{margin-top:24px;background:#fff;border-radius:8px;
                   padding:16px 24px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .passed-section summary{{cursor:pointer;font-weight:600;color:#16a085}}
  .passed-list{{columns:3;list-style:none;margin-top:10px;gap:8px}}
  .passed-list li{{font-size:.82rem;padding:2px 0;color:#555}}
  @media(max-width:600px){{.summary{{flex-direction:column}}
    .passed-list{{columns:1}}}}
</style>
</head>
<body>
<div class="header">
  {gauge}
  <div class="header-text">
    <h1>Ubuntu Security Audit</h1>
    <p><strong>{html.escape(hostname)}</strong> &nbsp;·&nbsp; {now_str} &nbsp;·&nbsp; {html.escape(duration)}</p>
    <p style="margin-top:8px">{fw_badges}</p>
  </div>
</div>

<div class="summary">
  <div class="card"><div class="num critical">{counts['CRITICAL']}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num high">{counts['HIGH']}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num medium">{counts['MEDIUM']}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num low">{counts['LOW']}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num passed">{len(passed)}</div><div class="lbl">Passed</div></div>
  <div class="card"><div class="num" style="color:{score_color}">{score}/100</div><div class="lbl">Score ({grade})</div></div>
</div>

<div class="main">
  <table>
    <thead>
      <tr>
        <th style="width:100px">Severity</th>
        <th style="width:200px">Check</th>
        <th>Finding / Remediation</th>
        <th style="width:60px">Pts</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan="4" style="text-align:center;padding:24px;color:#27ae60">✓ No issues found</td></tr>'}
    </tbody>
  </table>

  {'<details class="passed-section"><summary>Passed checks (' + str(len(passed)) + ')</summary><ul class="passed-list">' + "".join(passed_rows) + "</ul></details>" if passed else ""}
</div>
</body>
</html>"""


def main():
    p = argparse.ArgumentParser(description="Generate HTML report from findings JSONL")
    p.add_argument("--findings",   required=True,  help="Path to findings JSONL file")
    p.add_argument("--score",      required=True,  type=int)
    p.add_argument("--grade",      required=True)
    p.add_argument("--hostname",   required=True)
    p.add_argument("--frameworks", default="nist", help="Comma-separated framework ids")
    p.add_argument("--duration",   default="")
    p.add_argument("--output",     required=True,  help="Output HTML file path")
    args = p.parse_args()

    findings = load_findings(args.findings)
    frameworks = [fw.strip() for fw in args.frameworks.split(",") if fw.strip()]

    html_content = render(
        findings=findings,
        score=args.score,
        grade=args.grade,
        hostname=args.hostname,
        frameworks=frameworks,
        duration=args.duration,
    )

    Path(args.output).write_text(html_content, encoding="utf-8")


if __name__ == "__main__":
    main()
