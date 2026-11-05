"""Passive HTTPS HEAD check for one expressly authorized origin."""

import http.client
import ssl
from urllib.parse import urlsplit


def normalize_origin(url: str) -> tuple[str, int, str]:
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError("Invalid origin")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("An HTTPS origin without credentials is required")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Paths, queries and fragments are not supported")
    try:
        port = parsed.port or 443
    except ValueError as error:
        raise ValueError("Invalid port") from error
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    origin = f"https://{parsed.hostname.lower()}" + (f":{port}" if port != 443 else "")
    return parsed.hostname.lower(), port, origin


def check_https_origin(url: str, authorization) -> dict:
    host, port, origin = normalize_origin(url)
    authorization.require(origin, "https.headers.read")
    connection = http.client.HTTPSConnection(host, port, timeout=5, context=ssl.create_default_context())
    try:
        connection.request("HEAD", "/")
        response = connection.getresponse()
        headers = {name.lower(): value[:512] for name, value in response.getheaders()
                   if name.lower() in {"strict-transport-security", "content-security-policy", "x-content-type-options"}}
        findings = []
        if 300 <= response.status < 400:
            findings.append({"id": "redirect-response", "severity": "info", "description": "Redirect returned; target was not followed"})
        else:
            if "strict-transport-security" not in headers:
                findings.append({"id": "missing-hsts", "severity": "low", "description": "HSTS header absent"})
            if "content-security-policy" not in headers:
                findings.append({"id": "missing-csp", "severity": "info", "description": "CSP header absent"})
        return {"target": origin, "status": response.status, "headers": headers, "findings": findings,
                "note": "HEAD / only; redirects were not followed"}
    except ssl.SSLError:
        return {"target": origin, "status": None, "headers": {},
                "findings": [{"id": "tls-error", "severity": "high", "description": "TLS validation or handshake failed"}],
                "note": "No HTTP response received"}
    except OSError:
        return {"target": origin, "status": None, "headers": {},
                "findings": [{"id": "connection-error", "severity": "info", "description": "Connection failed"}],
                "note": "No HTTP response received"}
    finally:
        connection.close()
