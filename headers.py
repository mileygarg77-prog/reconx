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