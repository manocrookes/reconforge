import re
import httpx


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def extract_title(html: str) -> str:
    """
    Extract the HTML title from a response body.

    Args:
        html: Raw HTML content.

    Returns:
        The page title if found, otherwise 'N/A'.
    """
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()

    return "N/A"


def analyze_security_headers(headers: httpx.Headers) -> dict:
    """
    Analyze the presence of common HTTP security headers.

    Args:
        headers: HTTP response headers.

    Returns:
        A dictionary with present and missing security headers.
    """
    present = {}
    missing = []

    for header in SECURITY_HEADERS:
        value = headers.get(header)
        if value:
            present[header] = value
        else:
            missing.append(header)

    return {
        "present": present,
        "missing": missing,
    }


def enumerate_http(target: str) -> dict:
    """
    Perform basic HTTP enumeration against a target.

    Args:
        target: Domain or hostname.

    Returns:
        A dictionary containing URL, status code, title, headers, and security header analysis.
    """
    urls = [
        f"http://{target}",
        f"https://{target}",
    ]

    for url in urls:
        try:
            response = httpx.get(url, timeout=5, follow_redirects=True)

            headers = {
                "server": response.headers.get("server", "N/A"),
                "content-type": response.headers.get("content-type", "N/A"),
                "content-length": response.headers.get("content-length", "N/A"),
            }

            security_headers = analyze_security_headers(response.headers)

            return {
                "url": str(response.url),
                "status_code": response.status_code,
                "title": extract_title(response.text),
                "headers": headers,
                "security_headers": security_headers,
            }
        except httpx.RequestError:
            continue

    return {
        "url": "N/A",
        "status_code": "N/A",
        "title": "N/A",
        "headers": {
            "server": "N/A",
            "content-type": "N/A",
            "content-length": "N/A",
        },
        "security_headers": {
            "present": {},
            "missing": SECURITY_HEADERS,
        },
    }
