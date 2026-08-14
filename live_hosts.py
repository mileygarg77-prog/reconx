import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()


def check_host(subdomain):
    """
    Check if a single subdomain is alive by trying HTTPS then HTTP.
    Returns a dict with the result, or None if both fail.
    """
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            response = requests.get(
                url,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            return {
                "subdomain": subdomain,
                "url": response.url,
                "status_code": response.status_code,
                "scheme": scheme,
                "headers": response.headers,
                "body": response.text
            }
        except requests.exceptions.RequestException:
            continue

    return None


def get_live_hosts(subdomains, max_workers=20):
    """
    Given a list/set of subdomains, check which are alive.
    Uses threading to check many hosts concurrently.
    Returns a list of result dicts for live hosts only.
    """
    live_hosts = []
    total = len(subdomains)

    print(f"[*] Checking {total} subdomains for live hosts...\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_sub = {
            executor.submit(check_host, sub): sub for sub in subdomains
        }

        checked = 0
        for future in as_completed(future_to_sub):
            checked += 1
            result = future.result()
            if result:
                live_hosts.append(result)
                print(f"    [+] {result['url']} ({result['status_code']})")

            if checked % 20 == 0:
                print(f"    ... checked {checked}/{total}")

    return live_hosts