def extract_headers(response_headers):
    """
    Pull out security-relevant and identifying headers from a response.
    Takes a requests response.headers object, returns a clean dict.
    """
    interesting = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Generator",
        "Via",
        "X-Frame-Options",       # security header - useful bonus info
        "Content-Security-Policy",
        "Strict-Transport-Security",
    ]

    found = {}
    for header in interesting:
        if header in response_headers:
            found[header] = response_headers[header]

    return found

def detect_tech_from_headers(found_headers):
    """
    Infer technology names from collected header values.
    Takes the dict returned by extract_headers(), returns a set of tech names.
    """
    tech = set()

    powered_by = found_headers.get("X-Powered-By", "")
    server = found_headers.get("Server", "")
    generator = found_headers.get("X-Generator", "")

    if "express" in powered_by.lower():
        tech.add("Express.js")
    if "php" in powered_by.lower():
        tech.add("PHP")
    if "asp.net" in powered_by.lower():
        tech.add("ASP.NET")
    if "nginx" in server.lower():
        tech.add("Nginx")
    if "apache" in server.lower():
        tech.add("Apache")
    if "drupal" in generator.lower():
        tech.add("Drupal")
    if "wordpress" in generator.lower():
        tech.add("WordPress")

    return tech