
import ipaddress
import re
from urllib.parse import unquote, urlsplit


SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account",
    "password", "signin", "sign-in", "update", "wallet",
    "banking", "payment", "confirm", "recover", "suspended",
    "gift", "free", "claim", "invoice"
}

SUSPICIOUS_TLDS = {
    "zip", "click", "top", "work", "gq", "tk", "country"
}


def normalise_url(raw_url):
    """Validate and normalise a URL without visiting the website."""
    value = (raw_url or "").strip()

    if not value:
        raise ValueError("Please enter a website URL.")

    if len(value) > 2048:
        raise ValueError("The URL is too long. Please enter a shorter URL.")

    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("The URL contains invalid control characters.")

    if any(char.isspace() for char in value):
        raise ValueError("The URL must not contain spaces.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port  # Accessing this validates a supplied port.
    except ValueError:
        raise ValueError("The URL format or port number is invalid.")

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be scanned.")

    if not hostname:
        raise ValueError("Enter a URL with a domain, such as example.com.")

    hostname = hostname.lower().rstrip(".")

    if hostname == "localhost":
        raise ValueError("Please enter a public website domain.")

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if not is_ip_address:
        if "." not in hostname:
            raise ValueError("Enter a complete domain, such as example.com.")

        labels = hostname.split(".")
        if any(not label for label in labels):
            raise ValueError("The domain contains an empty section.")

        for label in labels:
            if (
                len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not re.fullmatch(r"[a-z0-9-]+", label)
            ):
                raise ValueError("The domain name format is invalid.")

    return value, parsed, hostname, is_ip_address


def scan_url(raw_url):
    url, parsed, hostname, is_ip_address = normalise_url(raw_url)
    decoded_url = unquote(url).lower()

    score = 0
    reasons = []

    def flag(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    # URL scheme and embedded credentials
    if parsed.scheme.lower() != "https":
        flag(10, "The URL uses HTTP rather than encrypted HTTPS.")

    if parsed.username is not None or parsed.password is not None:
        flag(
            25,
            "The URL contains embedded login information before the @ symbol."
        )

    # Hostname patterns
    if is_ip_address:
        flag(25, "The destination uses an IP address instead of a domain name.")

    if "xn--" in hostname:
        flag(20, "The domain uses punycode, which can occur in look-alike domains.")

    labels = hostname.split(".")

    if len(labels) >= 5:
        flag(12, "The domain has an unusually large number of subdomains.")

    if len(hostname) > 45:
        flag(8, "The hostname is unusually long.")

    if "--" in hostname:
        flag(8, "The hostname contains repeated hyphens.")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        flag(8, f"The domain uses the .{tld} top-level domain.")

    # URL content patterns
    if len(url) > 120:
        flag(8, "The full URL is unusually long.")

    if url.count("%") >= 3:
        flag(8, "The URL contains several percent-encoded characters.")

    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in decoded_url
    )

    if matched_words:
        shown = ", ".join(matched_words[:5])
        flag(12, f"The URL contains potentially deceptive terms: {shown}.")

    if hostname in SHORTENER_DOMAINS:
        flag(12, "A URL-shortening service hides the final destination.")

    score = min(score, 100)

    if score >= 45:
        verdict = "Likely Phishing"
        severity = "High"
        harm = (
            "This link may be used for credential theft, financial fraud, "
            "impersonation, or malware delivery. Avoid entering passwords, "
            "one-time passwords, or payment details."
        )
        evidence = "Several warning indicators detected"

    elif score >= 20:
        verdict = "Suspicious"
        severity = "Medium"
        harm = (
            "This URL has patterns that can occur in deceptive links. "
            "Verify the exact domain using the organisation's official "
            "website or a trusted contact before sharing information."
        )
        evidence = "Some warning indicators detected"

    else:
        verdict = "No obvious warning signs detected"
        severity = "Low"
        harm = (
            "This basic scan found few of the patterns it checks. "
            "That does not prove the website is legitimate. New, targeted, "
            "or well-disguised phishing websites may not trigger these rules."
        )
        evidence = "Few warning indicators detected"

    if not reasons:
        reasons.append(
            "No major warning patterns covered by this basic scanner were detected."
        )

    return {
        "url": url,
        "verdict": verdict,
        "severity": severity,
        "score": score,
        "evidence": evidence,
        "harm": harm,
        "reasons": reasons,
    }