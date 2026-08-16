import json
import os
from datetime import datetime


def save_report(domain, subdomains, live_hosts, cve_results, output_dir="output"):
    """
    Save a structured JSON report of the full recon scan.
    """
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "domain": domain,
        "scan_time": datetime.now().isoformat(),
        "total_subdomains": len(subdomains),
        "total_live_hosts": len(live_hosts),
        "live_hosts": [
            {
                "url": h["url"],
                "status_code": h["status_code"],
                "technologies": h.get("techs_found", []),
            }
            for h in live_hosts
        ],
        "cve_findings": cve_results,
    }

    safe_domain = domain.replace("://", "_").replace("/", "_")
    filename = f"{output_dir}/{safe_domain}_recon_report.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Report saved to {filename}")
    return filename

SEVERITY_COLORS = {
    "CRITICAL": "#ff3b5c",
    "HIGH": "#ff6b4a",
    "MEDIUM": "#ffb648",
    "LOW": "#4ade80",
}
 
 
def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(str(severity).upper(), "#9ca3af")
    return f'<span class="badge" style="background:{color}1a;color:{color};border:1px solid {color}44">{str(severity).upper()}</span>'
 
 
def _status_badge(status: int) -> str:
    color = "#4ade80" if 200 <= status < 300 else "#ffb648" if 300 <= status < 400 else "#ff6b4a"
    return f'<span class="badge" style="background:{color}1a;color:{color};border:1px solid {color}44">{status}</span>'
 
 
def generate_html_report(json_path: str) -> str:
    """
    Reads a JSON report already saved by save_report() and generates
    an HTML report with the same base filename, in the same folder.
 
    Example: my_reports/example.com_recon_report.json
          -> my_reports/example.com_recon_report.html
    """
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
 
    domain = data.get("domain", "unknown-target")
    scan_time = data.get("scan_time", "")
    total_subdomains = data.get("total_subdomains", 0)
    total_live_hosts = data.get("total_live_hosts", 0)
    live_hosts = data.get("live_hosts", [])
    cve_findings = data.get("cve_findings", {})
 
    # count unique technologies across all live hosts
    all_techs = set()
    for h in live_hosts:
        all_techs.update(h.get("technologies", []))
 
    # --- live hosts table ---
    live_rows = ""
    for h in live_hosts:
        techs = ", ".join(h.get("technologies", [])) or "-"
        live_rows += (
            f'<tr><td class="mono">{h.get("url","-")}</td>'
            f'<td>{_status_badge(h.get("status_code", 0))}</td>'
            f'<td>{techs}</td></tr>\n'
        )
    if not live_rows:
        live_rows = '<tr><td colspan="3" class="empty">No live hosts detected</td></tr>'
 
    # --- technology chips ---
    tech_chips = "\n".join(f'<span class="chip">{t}</span>' for t in sorted(all_techs))
    if not tech_chips:
        tech_chips = '<span class="empty">No technologies fingerprinted</span>'
 
    # --- cve findings table (cve_findings is {tech: [ {id, severity, description}, ... ]}) ---
    cve_rows = ""
    for tech, cves in cve_findings.items():
        for cve in cves:
            cve_rows += (
                f'<tr><td class="mono">{cve.get("id","-")}</td>'
                f'<td>{_severity_badge(cve.get("severity","-"))}</td>'
                f'<td>{tech}</td>'
                f'<td>{cve.get("description","-")}</td></tr>\n'
            )
    if not cve_rows:
        cve_rows = '<tr><td colspan="4" class="empty">No known CVEs matched</td></tr>'
 
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconX Report - {domain}</title>
<style>
  :root {{
    --bg: #0b0f14; --panel: #121822; --border: #1f2937;
    --text: #e5e7eb; --muted: #8b96a5; --accent: #22d3ee;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif; padding: 48px 24px; }}
  .container {{ max-width: 880px; margin: 0 auto; }}
  .header {{ border: 1px solid var(--border); border-radius: 12px; padding: 32px;
    background: linear-gradient(135deg, #121822, #0d1420); text-align: center; margin-bottom: 24px; }}
  .header h1 {{ margin: 0; font-size: 32px; letter-spacing: 2px; color: var(--accent);
    font-family: 'Consolas', monospace; }}
  .header p {{ color: var(--muted); margin: 8px 0 0; font-size: 14px; }}
  .target-box {{ border: 1px solid var(--border); border-radius: 12px; padding: 20px 28px;
    margin-bottom: 24px; background: var(--panel); }}
  .target-box .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
  .target-box .value {{ font-family: 'Consolas', monospace; font-size: 20px; margin-top: 6px; }}
  .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}
  .stat {{ border: 1px solid var(--border); border-radius: 12px; background: var(--panel);
    padding: 20px; text-align: center; }}
  .stat .num {{ font-size: 32px; font-weight: 700; color: var(--accent); }}
  .stat .lbl {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .section {{ border: 1px solid var(--border); border-radius: 12px; background: var(--panel);
    padding: 24px 28px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; color: var(--muted);
    margin: 0 0 16px; border-bottom: 1px solid var(--border); padding-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td {{ padding: 10px 8px; border-bottom: 1px solid #1a2230; font-size: 14px; }}
  tr:last-child td {{ border-bottom: none; }}
  .mono {{ font-family: 'Consolas', monospace; }}
  .badge {{ padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; font-family: 'Consolas', monospace; }}
  .chip {{ display: inline-block; background: #1a2230; border: 1px solid var(--border); border-radius: 20px;
    padding: 6px 14px; margin: 4px; font-size: 13px; color: var(--accent); }}
  .empty {{ color: var(--muted); font-style: italic; font-size: 13px; }}
  .footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 32px; }}
  @media print {{ body {{ padding: 0; background: white; color: #111; }}
    .section, .stat, .header, .target-box {{ break-inside: avoid; border-color: #ccc; background: #fafafa; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>◆ ReconX</h1>
    <p>Reconnaissance Assessment Report</p>
  </div>
 
  <div class="target-box">
    <div class="label">Target</div>
    <div class="value">{domain}</div>
    <div class="label" style="margin-top:12px">Scan Time</div>
    <div class="value" style="font-size:14px">{scan_time}</div>
  </div>
 
  <div class="summary">
    <div class="stat"><div class="num">{total_subdomains}</div><div class="lbl">Subdomains</div></div>
    <div class="stat"><div class="num">{total_live_hosts}</div><div class="lbl">Live Hosts</div></div>
    <div class="stat"><div class="num">{len(all_techs)}</div><div class="lbl">Technologies</div></div>
  </div>
 
  <div class="section">
    <h2>Live Hosts</h2>
    <table>{live_rows}</table>
  </div>
 
  <div class="section">
    <h2>Technologies Detected</h2>
    <div>{tech_chips}</div>
  </div>
 
  <div class="section">
    <h2>CVE Findings</h2>
    <table>{cve_rows}</table>
  </div>
 
  <div class="footer">Generated by ReconX &middot; For authorized security testing only</div>
</div>
</body>
</html>"""
 
    html_path = os.path.splitext(json_path)[0] + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
 
    print(f"[+] HTML report saved to {html_path}")
    return html_path
 