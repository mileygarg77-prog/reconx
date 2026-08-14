import requests
import json
import time


def get_subdomains_crtsh(domain, retries=2):
    """Query crt.sh certificate transparency logs for subdomains."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            data = response.json()
            break
        except requests.exceptions.Timeout:
            print(f"[!] crt.sh timeout (attempt {attempt}/{retries}), retrying...")
            time.sleep(2)
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            print(f"[!] crt.sh returned HTTP {status} (attempt {attempt}/{retries}), retrying...")
            time.sleep(2)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error querying crt.sh: {e}")
            return subdomains
        except json.JSONDecodeError:
            print("[!] crt.sh returned invalid JSON")
            return subdomains
    else:
        print("[!] crt.sh unavailable after retries, skipping this source")
        return subdomains

    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*."):
                subdomains.add(name)
            elif name.startswith("*."):
                subdomains.add(name.replace("*.", ""))

    return subdomains


def get_subdomains_hackertarget(domain):
    """Query HackerTarget's free hostsearch API as a fallback source."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        # HackerTarget returns plain text, one "subdomain,ip" per line
        if "API count exceeded" in response.text or "error" in response.text.lower():
            print(f"[!] HackerTarget: {response.text.strip()}")
            return subdomains

        for line in response.text.strip().split("\n"):
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub:
                    subdomains.add(sub)

    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying HackerTarget: {e}")

    return subdomains


def get_subdomains(domain):
    """
    Combine subdomain results from all available sources.
    Falls back gracefully if one source fails.
    """
    all_subdomains = set()

    print("[*] Trying crt.sh...")
    crtsh_results = get_subdomains_crtsh(domain)
    print(f"    -> {len(crtsh_results)} found")
    all_subdomains.update(crtsh_results)

    print("[*] Trying HackerTarget...")
    ht_results = get_subdomains_hackertarget(domain)
    print(f"    -> {len(ht_results)} found")
    all_subdomains.update(ht_results)

    return all_subdomains