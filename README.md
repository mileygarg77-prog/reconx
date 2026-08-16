# ReconX

A modular Python recon automation tool that chains subdomain enumeration, live host detection, technology fingerprinting, and CVE cross-referencing into a single CLI scan — built as a first step toward practical penetration testing tooling.

## What it does

Given a target domain, ReconX:

1. **Enumerates subdomains** via certificate transparency logs (crt.sh) with HackerTarget as an automatic fallback source
2. **Detects live hosts** from the subdomain list using concurrent HTTP probing
3. **Fingerprints each live host** — server headers, security headers, and detected technologies (CMS, JS frameworks, etc.)
4. **Cross-references detected technologies against the NVD CVE database** to surface known vulnerabilities
5. **Outputs a structured JSON report** for further analysis or integration into other tooling

## Architecture
```
main.py            → CLI entry point, orchestrates the pipeline
subdomains.py       → crt.sh + HackerTarget subdomain enumeration
live_hosts.py       → concurrent live host detection (ThreadPoolExecutor)
headers.py          → HTTP header extraction
technologies.py     → signature-based tech stack fingerprinting
cve_lookup.py       → NVD API integration for CVE cross-referencing
report.py           → JSON report generation
```
Each module is independently testable...

## Usage

```bash
# Basic scan
python main.py --domain example.com

# Custom output directory
python main.py -d example.com -o my_scans

# Skip CVE lookups for a faster recon-only pass
python main.py -d example.com --skip-cve
```

## Setup

```bash
git clone https://github.com/mileygarg77-prog/reconx.git
cd reconx
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
python main.py --domain example.com
```

**Optional:** Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key and paste it into `NVD_API_KEY` in `cve_lookup.py` to raise the rate limit from 5 to 50 requests/30 seconds.

## Sample output

```json
{
  "domain": "example.com",
  "scan_time": "2026-08-14T12:30:00",
  "total_subdomains": 17,
  "total_live_hosts": 9,
  "live_hosts": [
    {
      "url": "https://www.example.com/",
      "status_code": 200,
      "technologies": ["Nginx", "React"]
    }
  ],
  "cve_findings": {
    "jQuery": [
      {
        "id": "CVE-2020-11023",
        "severity": "MEDIUM",
        "description": "..."
      }
    ]
  }
}
```

## Known limitations

- **crt.sh reliability**: crt.sh frequently returns 502 errors or times out under load. ReconX retries automatically and falls back to HackerTarget's API, but if both sources are down, subdomain results may be incomplete.
- **CVE matching is keyword-based, not version-precise**: NVD lookups match on technology name, not detected version — this can surface CVEs that don't apply to the specific version in use, and generic tech names (e.g. "React") risk false-positive matches against unrelated products. A manual override dictionary partially mitigates this but isn't exhaustive.
- **No banner-grabbing or precise version fingerprinting** — technology detection is signature-based (headers + HTML patterns), not exhaustive.
- **NVD rate limits**: without an API key, CVE lookups are paced at 1 request per 6 seconds, which can make large scans slow.

## Possible improvements

- Version-aware CVE matching via banner grabbing
- Additional subdomain sources (Shodan, Censys)
- Async requests instead of threading for better scalability
- Expanded technology signature database

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only scan domains you own or have explicit permission to test.
