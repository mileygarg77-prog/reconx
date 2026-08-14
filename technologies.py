import re

# signature: (pattern to search for in HTML body, technology name)
SIGNATURES = [
    (r"wp-content", "WordPress"),
    (r"wp-includes", "WordPress"),
    (r"Joomla!", "Joomla"),
    (r"Drupal.settings", "Drupal"),
    (r"cdn.shopify.com", "Shopify"),
    (r"react", "React"),
    (r"__NEXT_DATA__", "Next.js"),
    (r"ng-version", "Angular"),
    (r"vue\.js", "Vue.js"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
    (r"laravel_session", "Laravel"),
    (r"csrfmiddlewaretoken", "Django"),
    (r"X-Powered-By: Express", "Express.js"),
]


def detect_technologies(html_body):
    """
    Scan HTML content for known technology signatures.
    Returns a list of detected technology names (deduplicated).
    """
    detected = set()
    body_lower = html_body.lower()

    for pattern, tech_name in SIGNATURES:
        if re.search(pattern.lower(), body_lower):
            detected.add(tech_name)

    return sorted(detected)