import re
import math
import ipaddress
import urllib.parse
from typing import Dict, List, Any

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "goo.gl",
    "tiny.cc", "rb.gy", "cutt.ly", "shorturl.at"
}

KEYWORDS = [
    "login", "verify", "account", "update", "banking", "secure",
    "security", "authenticate", "password", "confirm", "wallet", "signin"
]

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_digits",
    "has_ip_host",
    "is_https",
    "is_shortener",
    "hostname_entropy",
    "has_at_symbol",
    "keyword_count",
    "has_punycode"
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    l = len(s)
    for cnt in freq.values():
        p = cnt / l
        ent -= p * math.log2(p)
    return round(ent, 4)

def extract_url_features(url: str) -> Dict[str, float]:
    """Extracts 16 lexical and structural features from a URL."""
    clean_url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "https://" + clean_url

    try:
        parsed = urllib.parse.urlsplit(clean_url)
    except Exception:
        parsed = urllib.parse.urlsplit("https://malformed.test")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    hostname = parsed.hostname or ""
    path = parsed.path.lower()
    query = parsed.query.lower()

    # Hostname and subdomains
    host_parts = hostname.split(".")
    num_subdomains = max(0, len(host_parts) - 2) if len(host_parts) > 1 else 0

    # IP check
    has_ip = 0.0
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        has_ip = 1.0
    except ValueError:
        has_ip = 0.0

    # Shortener check
    is_shortener = 1.0 if hostname in SHORTENER_DOMAINS else 0.0

    # Keyword search in path and query
    combined = path + "?" + query
    kw_count = sum(1 for kw in KEYWORDS if kw in combined or kw in hostname)

    features = {
        "url_length": float(len(url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "num_subdomains": float(num_subdomains),
        "num_dots": float(url.count(".")),
        "num_hyphens": float(url.count("-")),
        "num_underscores": float(url.count("_")),
        "num_slashes": float(url.count("/")),
        "num_digits": float(sum(c.isdigit() for c in url)),
        "has_ip_host": has_ip,
        "is_https": 1.0 if scheme == "https" else 0.0,
        "is_shortener": is_shortener,
        "hostname_entropy": shannon_entropy(hostname),
        "has_at_symbol": 1.0 if "@" in url else 0.0,
        "keyword_count": float(kw_count),
        "has_punycode": 1.0 if "xn--" in hostname else 0.0
    }

    return features

def features_to_vector(features: Dict[str, float]) -> List[float]:
    return [features[name] for name in FEATURE_NAMES]
