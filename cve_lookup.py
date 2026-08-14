import requests
import time

NVD_API_KEY = None  # paste your key here as a string once you get it, e.g. "abcd-1234..."
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Disambiguate generic tech names that collide with unrelated NVD products
SEARCH_TERM_OVERRIDES = {
    "React": "React.js",
    "Vue.js": "Vue.js JavaScript",
    "Next.js": "Next.js Vercel",
}


def get_cves_for_technology(tech_name, max_results=5):
    """
    Query the NVD API for recent CVEs matching a technology name.
    Returns a list of dicts with CVE ID, severity, and short description.
    """
    search_term = SEARCH_TERM_OVERRIDES.get(tech_name, tech_name)

    params = {
        "keywordSearch": search_term,
        "resultsPerPage": max_results
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"    [!] Error querying NVD for {tech_name}: {e}")
        return []
    except ValueError:
        print(f"    [!] NVD returned invalid JSON for {tech_name}")
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "Unknown")

        # Get English description
        description = "No description available"
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", description)
                break

        # Get severity if available
        severity = "Unknown"
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")

        cves.append({
            "id": cve_id,
            "severity": severity,
            "description": description[:150] + "..." if len(description) > 150 else description
        })

    return cves


def check_technologies_for_cves(tech_list):
    """
    Given a list of detected technology names, look up CVEs for each.
    Returns a dict: {tech_name: [list of cve dicts]}
    """
    results = {}

    for tech in tech_list:
        print(f"    [*] Checking CVEs for {tech}...")
        cves = get_cves_for_technology(tech)
        if cves:
            results[tech] = cves

        # NVD rate limit courtesy delay - important without an API key
        time.sleep(1.5 if NVD_API_KEY else 6)

    return results