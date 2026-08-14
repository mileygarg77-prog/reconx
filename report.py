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
                "technologies": [],  # filled in below if you want per-host tech
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