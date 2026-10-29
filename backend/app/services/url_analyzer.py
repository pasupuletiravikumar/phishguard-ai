import re
import math
import ipaddress
import urllib.parse
from typing import List, Tuple, Optional, Dict, Any
from app.schemas.scan import Finding, Severity, UrlDetails

# Maintained list of popular URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "goo.gl",
    "tiny.cc", "rb.gy", "cutt.ly", "shorturl.at", "bl.ink", "hyperurl.co",
    "v.gd", "soo.gd", "s.id", "clck.ru", "rebrand.ly", "trib.al"
}

# Suspicious high-value brand names targeted by typosquatting / phishing
TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "dropbox", "dhl", "fedex", "usps", "binance", "coinbase"
]

# Sensitive keywords often found in phishing paths / query
SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "billing", "authenticate", "credential", "password",
    "wallet", "suspended", "security-alert", "confirm", "banking"
]

# Risky / non-standard web ports
RISKY_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 8080, 8443, 8888}

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def extract_registered_domain(hostname: str) -> Tuple[str, List[str]]:
    """
    Splits hostname into registered domain and subdomains.
    Uses common 2-level TLD heuristics (e.g. .co.uk, .com.au).
    """
    clean_host = hostname.lower().strip(".")
    parts = clean_host.split(".")
    if len(parts) <= 1:
        return clean_host, []
    
    two_level_tlds = {"co.uk", "org.uk", "gov.uk", "com.au", "net.au", "co.in", "net.in", "co.nz", "com.br"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_level_tlds:
        reg_domain = ".".join(parts[-3:])
        subdomains = parts[:-3]
    else:
        reg_domain = ".".join(parts[-2:])
        subdomains = parts[:-2]
    return reg_domain, subdomains

class UrlAnalyzer:
    """Deterministic, modular URL security analysis engine."""

    def analyze(self, raw_input: str) -> Tuple[List[Finding], UrlDetails]:
        findings: List[Finding] = []
        raw_url = raw_input.strip()

        # Check for missing scheme
        parsed_scheme = "http"
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
            findings.append(Finding(
                rule_id="RULE_URL_MISSING_SCHEME",
                title="Missing Protocol Scheme",
                severity=Severity.LOW,
                weight=5.0,
                explanation="The URL did not specify an explicit protocol scheme (such as https://).",
                evidence=f"Input URL starts with: '{raw_url[:15]}'",
                remediation="Ensure full URL scheme is specified when sharing web links.",
                confidence=0.9
            ))
            raw_url = "https://" + raw_url

        try:
            parsed = urllib.parse.urlsplit(raw_url)
        except Exception as e:
            findings.append(Finding(
                rule_id="RULE_URL_MALFORMED",
                title="Malformed URL Syntax",
                severity=Severity.HIGH,
                weight=60.0,
                explanation=f"The URL could not be parsed according to standard RFC 3986 syntax: {str(e)}",
                evidence=raw_input,
                remediation="Do not access malformed URLs as they can exploit parser differentials.",
                confidence=1.0
            ))
            empty_details = UrlDetails(
                raw_url=raw_input, scheme="unknown", hostname="unknown", registered_domain="unknown",
                subdomains=[], port=None, path="", query_param_count=0, is_ip_address=False,
                is_shortener=False, is_punycode=False, shannon_entropy=0.0, suspicious_keywords_found=[],
                has_credentials_in_url=False
            )
            return findings, empty_details

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        hostname = parsed.hostname or ""
        port = parsed.port
        path = parsed.path
        query = parsed.query
        userinfo = None

        # Check embedded credentials (e.g. user:pass@host)
        if "@" in netloc:
            parts = netloc.split("@", 1)
            userinfo = parts[0]
            findings.append(Finding(
                rule_id="RULE_URL_EMBEDDED_CREDENTIALS",
                title="Embedded User Credentials in URL",
                severity=Severity.HIGH,
                weight=65.0,
                explanation="The URL contains authentication credentials or an '@' symbol before the hostname. This is a classic phishing technique to deceive users about the destination.",
                evidence=f"Credentials segment: '{userinfo}@'",
                remediation="Never navigate to URLs containing '@' in the authority component.",
                confidence=0.95
            ))

        # Check HTTP scheme
        if scheme == "http":
            findings.append(Finding(
                rule_id="RULE_URL_INSECURE_HTTP",
                title="Insecure HTTP Transport Protocol",
                severity=Severity.LOW,
                weight=15.0,
                explanation="The URL communicates over unencrypted plain-text HTTP rather than HTTPS.",
                evidence=f"Scheme: {scheme}://",
                remediation="Avoid transmitting sensitive credentials or personal data over unencrypted HTTP.",
                confidence=0.85
            ))

        # Check IP address host
        is_ip = False
        try:
            clean_host_str = hostname.strip("[]")
            ipaddress.ip_address(clean_host_str)
            is_ip = True
            findings.append(Finding(
                rule_id="RULE_URL_IP_HOST",
                title="Raw IP Address Used As Hostname",
                severity=Severity.HIGH,
                weight=55.0,
                explanation="The URL uses a numeric IP address directly instead of a registered domain name. Legitimate web services rarely present raw IP addresses to end users.",
                evidence=f"Hostname: {hostname}",
                remediation="Verify who owns the IP address using ARIN/RIPE WHOIS before connecting.",
                confidence=0.9
            ))
        except ValueError:
            is_ip = False

        # Domain breakdown
        reg_domain, subdomains = extract_registered_domain(hostname)

        # Check excessive subdomains
        if len(subdomains) >= 3:
            findings.append(Finding(
                rule_id="RULE_URL_EXCESSIVE_SUBDOMAINS",
                title="Excessive Subdomain Nesting Depth",
                severity=Severity.MODERATE,
                weight=35.0,
                explanation=f"The URL contains {len(subdomains)} subdomain levels. Phishing campaigns frequently chain subdomains (e.g., login.bank.com.attacker.com) to simulate legitimate entities.",
                evidence=f"Subdomains: {'.'.join(subdomains)}",
                remediation="Inspect the rightmost registrable domain segment carefully.",
                confidence=0.85
            ))

        # Check Punycode / IDN Homograph
        is_punycode = "xn--" in hostname.lower()
        if is_punycode:
            findings.append(Finding(
                rule_id="RULE_URL_PUNYCODE_HOMOGRAPH",
                title="Punycode / Internationalized Domain Name (IDN)",
                severity=Severity.HIGH,
                weight=65.0,
                explanation="The domain uses Punycode encoding ('xn--'), which can be used to mount homograph attacks where Cyrillic or Greek characters look visually identical to Latin letters.",
                evidence=f"Encoded host: {hostname}",
                remediation="Examine the decoded Unicode representation to ensure characters are not spoofed.",
                confidence=0.95
            ))

        # Check URL shorteners
        is_shortener = reg_domain.lower() in URL_SHORTENERS or hostname.lower() in URL_SHORTENERS
        if is_shortener:
            findings.append(Finding(
                rule_id="RULE_URL_SHORTENER_DETECTED",
                title="URL Shortening Service Detected",
                severity=Severity.MODERATE,
                weight=30.0,
                explanation=f"The domain '{reg_domain}' is a known link shortening service that masks the final landing destination.",
                evidence=f"Shortener domain: {reg_domain}",
                remediation="Expand shortened links with a safe preview tool before opening.",
                confidence=0.95
            ))

        # Check Non-standard / Risky Ports
        if port and port in RISKY_PORTS:
            findings.append(Finding(
                rule_id="RULE_URL_NONSTANDARD_PORT",
                title=f"Non-Standard Risky Service Port ({port})",
                severity=Severity.MODERATE,
                weight=35.0,
                explanation=f"The URL connects on port {port}, which is outside standard HTTP (80) and HTTPS (443) ports.",
                evidence=f"Port: {port}",
                remediation="Ensure firewalls do not expose non-standard service ports unnecessarily.",
                confidence=0.85
            ))

        # Check Suspicious URL Length
        if len(raw_input) > 100:
            findings.append(Finding(
                rule_id="RULE_URL_EXCESSIVE_LENGTH",
                title="Unusually Long URL Length",
                severity=Severity.LOW,
                weight=15.0,
                explanation=f"The URL length is {len(raw_input)} characters. Phishing kits often append long randomized strings to evade simple signature filters.",
                evidence=f"Length: {len(raw_input)} characters",
                remediation="Inspect query parameters for embedded redirect URLs or serialized payloads.",
                confidence=0.75
            ))

        # Check Suspicious URL Encoding / Percent Encoding
        percent_encodings = re.findall(r"%[0-9a-fA-F]{2}", raw_input)
        if len(percent_encodings) >= 4 or "%2e%2e" in raw_input.lower():
            findings.append(Finding(
                rule_id="RULE_URL_HEAVY_PERCENT_ENCODING",
                title="Heavy or Suspicious Character Percent-Encoding",
                severity=Severity.MODERATE,
                weight=30.0,
                explanation="The URL contains multiple hex percent-encoded sequences, which can be employed to obfuscate malicious path segments or script payloads.",
                evidence=f"Encoded sequences found: {', '.join(percent_encodings[:5])}",
                remediation="Decode and verify all encoded URL parameters prior to submission.",
                confidence=0.8
            ))

        # Typosquatting / Brand Lookalike Heuristics
        lookalike_detected = None
        lower_host = hostname.lower()
        for brand in TARGET_BRANDS:
            # Check if brand appears in subdomain or domain with slight modifications
            # Examples: paypa1, micros0ft, amaz0n, or google-security
            typo_patterns = [
                brand.replace("o", "0"),
                brand.replace("l", "1"),
                brand.replace("i", "1"),
                brand.replace("e", "3"),
                f"{brand}-",
                f"-{brand}",
                f"{brand}security",
                f"{brand}verify"
            ]
            for pattern in typo_patterns:
                if pattern != brand and pattern in lower_host and brand not in reg_domain:
                    lookalike_detected = brand
                    findings.append(Finding(
                        rule_id="RULE_URL_TYPOSQUATTING_LOOKALIKE",
                        title=f"Potential Brand Typosquatting / Impersonation ({brand.capitalize()})",
                        severity=Severity.CRITICAL,
                        weight=85.0,
                        explanation=f"The hostname mimics the brand '{brand.capitalize()}' using character substitutions or hyphens while registered under an unrelated domain ('{reg_domain}').",
                        evidence=f"Found suspicious pattern '{pattern}' in host '{hostname}'",
                        remediation=f"Do not enter {brand.capitalize()} credentials here. Visit the official {brand}.com portal directly.",
                        confidence=0.95
                    ))
                    break
            if lookalike_detected:
                break

        # Check Suspicious Sensitive Keywords in Path or Subdomains
        found_keywords = []
        combined_path_query = (path + "?" + query).lower()
        for kw in SENSITIVE_KEYWORDS:
            if kw in combined_path_query or any(kw in sub for sub in subdomains):
                found_keywords.append(kw)

        if found_keywords:
            findings.append(Finding(
                rule_id="RULE_URL_SENSITIVE_ACTION_KEYWORDS",
                title="Suspicious Credential / Authentication Keywords Found",
                severity=Severity.MODERATE if len(found_keywords) <= 2 else Severity.HIGH,
                weight=25.0 + min(len(found_keywords) * 10.0, 35.0),
                explanation=f"The URL contains sensitive action keywords ({', '.join(found_keywords[:4])}) typically associated with credential harvesting or account reset lures.",
                evidence=f"Keywords matched: {', '.join(found_keywords)}",
                remediation="Verify whether the domain legitimately owns the requested login endpoint.",
                confidence=0.85
            ))

        # Shannon Entropy Check
        host_entropy = calculate_entropy(hostname)
        if host_entropy > 4.2 and not is_ip:
            findings.append(Finding(
                rule_id="RULE_URL_HIGH_ENTROPY_HOST",
                title="High Shannon Entropy in Hostname (Random Character Distribution)",
                severity=Severity.MODERATE,
                weight=30.0,
                explanation=f"The hostname exhibits high information entropy ({host_entropy} bits), which is characteristic of Domain Generation Algorithms (DGAs) or dynamic disposable hosts.",
                evidence=f"Host Shannon entropy: {host_entropy} bits",
                remediation="Check domain age and reputation via WHOIS and passive DNS records.",
                confidence=0.8
            ))

        # Count query parameters
        query_params = urllib.parse.parse_qs(query)
        query_param_count = len(query_params)

        details = UrlDetails(
            raw_url=raw_input,
            scheme=scheme,
            hostname=hostname,
            registered_domain=reg_domain,
            subdomains=subdomains,
            port=port,
            path=path,
            query_param_count=query_param_count,
            is_ip_address=is_ip,
            is_shortener=is_shortener,
            is_punycode=is_punycode,
            shannon_entropy=host_entropy,
            suspicious_keywords_found=found_keywords,
            has_credentials_in_url=userinfo is not None,
            lookalike_target=lookalike_detected
        )

        return findings, details
