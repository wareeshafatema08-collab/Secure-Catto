
import requests
import socket
import ssl
from urllib.parse import urlparse, urljoin
from datetime import datetime
from ipaddress import ip_address


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Helps prevent Cross-Site Scripting (XSS) "
        "and other code injection attacks."
    ),
    "Strict-Transport-Security": (
        "Forces browsers to communicate with the website "
        "using secure HTTPS connections."
    ),
    "X-Frame-Options": (
        "Helps prevent clickjacking attacks."
    ),
    "X-Content-Type-Options": (
        "Prevents browsers from guessing the content type."
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is shared."
    ),
    "Permissions-Policy": (
        "Controls access to browser features and APIs."
    )
}


def validate_url(url):
    if not url or not isinstance(url, str):
        raise ValueError("Please enter a valid website URL.")

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)

    if parsed_url.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed_url.hostname:
        raise ValueError("Invalid website URL.")

    if parsed_url.username or parsed_url.password:
        raise ValueError("URLs containing login credentials are not allowed.")

    if parsed_url.port is not None:
        if parsed_url.port < 1 or parsed_url.port > 65535:
            raise ValueError("Invalid port number.")

    hostname = parsed_url.hostname

    try:
        ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            address_info = socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM
            )
            addresses = list(set(
                item[4][0] for item in address_info
            ))
        except socket.gaierror:
            raise ValueError("Website address could not be resolved.")

    if not addresses:
        raise ValueError("Website address could not be resolved.")

    for address in addresses:
        ip = ip_address(address)

        if not ip.is_global:
            raise ValueError(
                "Private, local and non-public IP addresses are not allowed."
            )

    return url


def get_safe_response(url, timeout, follow_redirects):
    current_url = validate_url(url)
    redirect_count = 0
    max_redirects = 5

    while True:
        response = requests.get(
            current_url,
            timeout=timeout,
            allow_redirects=False,
            headers={
                "User-Agent": "SecureCatto-Security-Analyzer/1.0"
            }
        )

        if not follow_redirects:
            return response

        if response.status_code not in (301, 302, 303, 307, 308):
            return response

        redirect_location = response.headers.get("Location")

        if not redirect_location:
            return response

        if redirect_count >= max_redirects:
            response.close()
            raise ValueError("Maximum redirect limit exceeded.")

        next_url = urljoin(current_url, redirect_location)

        try:
            next_url = validate_url(next_url)
        except ValueError:
            response.close()
            raise ValueError(
                "Redirect blocked because its destination is not safe."
            )

        response.close()
        current_url = next_url
        redirect_count += 1


def check_tls_certificate(url, timeout):
    parsed_url = urlparse(url)

    if parsed_url.scheme != "https":
        return "Not Applicable", "Not Applicable"

    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=hostname
            ) as secure_connection:

                tls_version = secure_connection.version()
                certificate = secure_connection.getpeercert()

                expiry = certificate.get("notAfter", "Unavailable")

                if expiry != "Unavailable":
                    expiry = datetime.strptime(
                        expiry,
                        "%b %d %H:%M:%S %Y %Z"
                    ).strftime("%d %B %Y")

                return tls_version, expiry

    except Exception:
        return "Unavailable", "Unavailable"


def scan_website(
    url,
    timeout=10,
    follow_redirects=False,
    include_headers=True,
    include_cookies=True
):
    url = validate_url(url)

    if not isinstance(timeout, (int, float)) or timeout < 1:
        raise ValueError("Invalid scan timeout.")

    response = get_safe_response(
        url,
        timeout,
        follow_redirects
    )

    final_url = response.url
    status_code = response.status_code
    response_headers = response.headers

    is_https = urlparse(final_url).scheme == "https"

    header_results = {}
    missing_headers = []

    for header, description in SECURITY_HEADERS.items():

        present = header in response_headers

        header_results[header] = {
            "present": present,
            "description": description,
            "value": response_headers.get(header, "Missing")
        }

        if not present:
            missing_headers.append(header)

    cookie_results = []

    for cookie in response.cookies:

        cookie_results.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "samesite": cookie.get_nonstandard_attr(
                "SameSite",
                "Not Set"
            )
        })

    tls_version, certificate_expiry = check_tls_certificate(
        final_url,
        timeout
    )

    security_score = 100

    if not is_https:
        security_score -= 30

    security_score -= len(missing_headers) * 8

    for cookie in cookie_results:

        if is_https and not cookie["secure"]:
            security_score -= 5

        if not cookie["httponly"]:
            security_score -= 5

        if str(cookie["samesite"]).lower() not in (
            "lax",
            "strict",
            "none"
        ):
            security_score -= 5

    security_score = max(0, min(100, security_score))

    if security_score >= 80:
        risk_level = "Low"
    elif security_score >= 50:
        risk_level = "Medium"
    else:
        risk_level = "High"

    recommendations = []

    if not is_https:
        recommendations.append(
            "Enable HTTPS and install a valid SSL/TLS certificate."
        )

    recommendation_messages = {
        "Content-Security-Policy":
            "Configure a Content-Security-Policy header.",

        "Strict-Transport-Security":
            "Configure the Strict-Transport-Security header.",

        "X-Frame-Options":
            "Add X-Frame-Options to help prevent clickjacking.",

        "X-Content-Type-Options":
            "Add X-Content-Type-Options: nosniff.",

        "Referrer-Policy":
            "Configure an appropriate Referrer-Policy.",

        "Permissions-Policy":
            "Configure a suitable Permissions-Policy."
    }

    for header in missing_headers:
        recommendations.append(
            recommendation_messages[header]
        )

    for cookie in cookie_results:

        if is_https and not cookie["secure"]:
            recommendations.append(
                f"Enable the Secure flag for cookie '{cookie['name']}'."
            )

        if not cookie["httponly"]:
            recommendations.append(
                f"Enable the HttpOnly flag for cookie '{cookie['name']}'."
            )

        if str(cookie["samesite"]).lower() not in (
            "lax",
            "strict",
            "none"
        ):
            recommendations.append(
                f"Set an appropriate SameSite attribute for cookie "
                f"'{cookie['name']}'."
            )

    if not recommendations:
        recommendations.append(
            "No missing security checks were detected by this scanner."
        )

    if not include_headers:
        header_results = {}

    if not include_cookies:
        cookie_results = []

    result = {
        "url": final_url,
        "status_code": status_code,
        "https": is_https,
        "security_score": security_score,
        "risk_level": risk_level,
        "headers": header_results,
        "cookies": cookie_results,
        "tls_version": tls_version,
        "certificate_expiry": certificate_expiry,
        "recommendations": recommendations,
        "scan_time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    response.close()

    return result
