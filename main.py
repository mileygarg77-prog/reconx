import argparse
from subdomains import get_subdomains
from live_hosts import get_live_hosts
from headers import extract_headers
from technologies import detect_technologies
from cve_lookup import check_technologies_for_cves
from report import save_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconX - Automated subdomain recon, fingerprinting, and CVE lookup"
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain to scan (e.g. example.com)"
    )
    parser.add_argument(
        "-o", "--output",
        default="output",
        help="Directory to save the JSON report (default: output)"
    )
    parser.add_argument(
        "--skip-cve",
        action="store_true",
        help="Skip NVD CVE lookups (faster, useful for quick recon)"
    )
    return parser.parse_args()


args = parse_args()
domain = args.domain

print("=" * 40)
print("        ReconX Scanner")
print("=" * 40)
print()
print("Target:", domain)
print("Recon started...")
print()

subdomains = get_subdomains(domain)

if subdomains:
    print(f"\n[+] Found {len(subdomains)} unique subdomains total")
else:
    print("[!] No subdomains found (or request failed)")
    exit()

print()
live_hosts = get_live_hosts(subdomains)

print()
print(f"[+] {len(live_hosts)} live hosts out of {len(subdomains)} subdomains checked\n")

print("=" * 40)
print("        Fingerprinting")
print("=" * 40)

for host in live_hosts:
    print(f"\n[*] {host['url']} ({host['status_code']})")

    headers_found = extract_headers(host["headers"])
    if headers_found:
        for key, value in headers_found.items():
            print(f"    {key}: {value}")
    else:
        print("    No notable headers found")

    techs_found = detect_technologies(host["body"])
    if techs_found:
        print(f"    Technologies: {', '.join(techs_found)}")
    else:
        print("    No known technologies detected")

# Phase 4: CVE cross-reference
cve_results = {}

if not args.skip_cve:
    print("\n" + "=" * 40)
    print("        CVE Cross-Reference")
    print("=" * 40)

    all_detected_techs = set()
    for host in live_hosts:
        techs = detect_technologies(host["body"])
        all_detected_techs.update(techs)

    if all_detected_techs:
        print(f"\n[*] Checking {len(all_detected_techs)} unique technologies against NVD...\n")
        cve_results = check_technologies_for_cves(all_detected_techs)

        if cve_results:
            for tech, cves in cve_results.items():
                print(f"\n[+] {tech}:")
                for cve in cves:
                    print(f"    {cve['id']} [{cve['severity']}] - {cve['description']}")
        else:
            print("\n[i] No CVEs found for detected technologies")
    else:
        print("\n[i] No technologies detected to check")
else:
    print("\n[i] Skipping CVE lookups (--skip-cve flag set)")

# Phase 5: Save report
save_report(domain, subdomains, live_hosts, cve_results, output_dir=args.output)