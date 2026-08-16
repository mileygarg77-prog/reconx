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
]

# Precompile once at import time — avoids recompiling on every call
_COMPILED_SIGNATURES = [(re.compile(pattern, re.IGNORECASE), tech) for pattern, tech in SIGNATURES]


def detect_technologies(html_body):
    """
    Scan HTML content for known technology signatures.
    Returns a list of detected technology names (deduplicated).
    """
    detected = set()

    for pattern, tech_name in _COMPILED_SIGNATURES:
        if pattern.search(html_body):
            detected.add(tech_name)

    return sorted(detected)