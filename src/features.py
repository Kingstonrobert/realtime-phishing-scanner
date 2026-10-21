"""High-performance, purely local URL lexical and structural feature engineering.

Engineered for ultra-low latency (<5ms per URL) without blocking network I/O.
Includes optional bounded-time async DNS enrichment (<20ms strict fallback).
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import numpy as np

# High-risk security and credential harvesting keywords
RISK_KEYWORDS = {
    "login": 1.5,
    "signin": 1.5,
    "verify": 1.4,
    "verification": 1.4,
    "banking": 1.8,
    "secure": 1.2,
    "security": 1.2,
    "update": 1.1,
    "paypal": 1.8,
    "account": 1.2,
    "wallet": 1.6,
    "admin": 1.3,
    "confirm": 1.3,
    "credential": 1.8,
    "webscr": 2.0,
    "authenticate": 1.4,
    "billing": 1.4,
    "invoice": 1.2,
    "support": 1.0,
    "recover": 1.3,
    "password": 1.8,
    "auth": 1.2,
    "ebay": 1.6,
    "apple": 1.4,
    "microsoft": 1.4,
    "netflix": 1.4,
    "amazon": 1.3,
}

# Suspicious TLDs commonly abused by ephemeral phishing campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "loan",
    "buzz", "club", "fit", "country", "stream", "gdn", "mom", "kim",
    "racing", "surfer", "download", "casa", "surf", "vip", "icu", "rest",
    "bar", "monster", "fail", "win", "bid", "men", "date", "party", "review",
}

# Common Latin confusables / Homoglyphs (Cyrillic, Greek lookalikes)
HOMOGLYPH_RANGES = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek
    (0x0530, 0x058F),  # Armenian
    (0x2100, 0x214F),  # Letterlike symbols
    (0xFF00, 0xFFEF),  # Halfwidth and Fullwidth forms
]

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_dots_domain",
    "num_subdomains",
    "num_hyphens",
    "num_hyphens_domain",
    "num_underscores",
    "num_slash",
    "num_questionmarks",
    "num_equal",
    "num_at",
    "num_percent",
    "has_double_slash_redirect",
    "is_ip_domain",
    "has_port",
    "is_https",
    "domain_entropy",
    "path_entropy",
    "url_entropy",
    "digit_ratio_url",
    "digit_ratio_domain",
    "letter_ratio_domain",
    "special_char_ratio_url",
    "is_suspicious_tld",
    "is_punycode",
    "has_homoglyphs",
    "risk_keyword_count",
    "risk_keyword_score",
    "has_login_keyword",
    "has_verify_keyword",
    "has_secure_keyword",
    "has_account_keyword",
    "max_consecutive_char",
    "longest_token_length",
]


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string in bits."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def check_homoglyphs(s: str) -> bool:
    """Check if string contains non-ASCII lookalike / homoglyph characters."""
    for char in s:
        cp = ord(char)
        if cp > 127:
            for start, end in HOMOGLYPH_RANGES:
                if start <= cp <= end:
                    return True
    return False


def is_ip_address(domain: str) -> bool:
    """Check if domain is a direct IPv4 or IPv6 address."""
    clean = domain.strip()
    if clean.startswith("[") and "]" in clean:
        clean = clean[1:clean.index("]")]
    else:
        clean = clean.split(":")[0]
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def clean_and_parse_url(raw_url: str) -> Tuple[str, Any]:
    """Robustly sanitize and parse raw URL handling missing schemes or malformed inputs."""
    url = raw_url.strip()
    if not url:
        url = "http://empty.invalid/"
    # If no scheme, default to http:// for parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        parsed = urlparse("http://" + url)
        raw_has_scheme = False
    else:
        parsed = urlparse(url)
        raw_has_scheme = True
    return url, parsed, raw_has_scheme


def extract_features_dict(raw_url: str) -> Dict[str, float]:
    """Extract lexical and structural features as a dictionary.

    Runs purely locally in <1 millisecond.
    """
    url, parsed, raw_has_scheme = clean_and_parse_url(raw_url)

    # Netloc extraction
    domain = parsed.netloc.lower() if parsed.netloc else parsed.path.split("/")[0].lower()
    port = parsed.port
    has_port = 1.0 if port not in (None, 80, 443) else 0.0

    # Strip port if present in domain string
    if ":" in domain:
        domain = domain.split(":")[0]

    path = parsed.path or ""
    query = parsed.query or ""

    # Length features
    url_len = float(len(url))
    domain_len = float(len(domain))
    path_len = float(len(path))
    query_len = float(len(query))

    # Structural counts
    num_dots = float(url.count("."))
    num_dots_domain = float(domain.count("."))
    num_hyphens = float(url.count("-"))
    num_hyphens_domain = float(domain.count("-"))
    num_underscores = float(url.count("_"))
    num_slash = float(url.count("/"))
    num_questionmarks = float(url.count("?"))
    num_equal = float(url.count("="))
    num_at = float(url.count("@"))
    num_percent = float(url.count("%"))

    # Subdomains count (excluding TLD and main domain part)
    domain_parts = [p for p in domain.split(".") if p]
    num_subdomains = float(max(0, len(domain_parts) - 2)) if len(domain_parts) >= 2 else 0.0

    # Double slash redirect check in path (e.g. http://example.com//phish.com)
    has_double_slash_redirect = 1.0 if "//" in path else 0.0

    # IP address check
    is_ip = 1.0 if is_ip_address(domain) else 0.0

    # HTTPS check
    is_https = 1.0 if (parsed.scheme.lower() == "https") else 0.0

    # Shannon Entropy
    domain_entropy = shannon_entropy(domain)
    path_entropy = shannon_entropy(path)
    url_entropy = shannon_entropy(url)

    # Character distributions
    digits_url = sum(c.isdigit() for c in url)
    digits_domain = sum(c.isdigit() for c in domain)
    letters_domain = sum(c.isalpha() for c in domain)
    special_chars_url = sum(not c.isalnum() for c in url)

    digit_ratio_url = float(digits_url / max(1, len(url)))
    digit_ratio_domain = float(digits_domain / max(1, len(domain)))
    letter_ratio_domain = float(letters_domain / max(1, len(domain)))
    special_char_ratio_url = float(special_chars_url / max(1, len(url)))

    # TLD extraction & suspicious TLD flag
    tld = domain_parts[-1] if domain_parts else ""
    is_suspicious_tld = 1.0 if (tld in SUSPICIOUS_TLDS) else 0.0

    # Punycode & Homoglyph detection
    is_punycode = 1.0 if ("xn--" in domain or "xn--" in url) else 0.0
    has_homoglyphs = 1.0 if check_homoglyphs(url) else 0.0

    # Risk keywords search across path, query, and domain
    lower_url = unquote(url).lower()
    risk_keyword_count = 0.0
    risk_keyword_score = 0.0
    for kw, weight in RISK_KEYWORDS.items():
        if kw in lower_url:
            risk_keyword_count += 1.0
            risk_keyword_score += weight

    has_login_keyword = 1.0 if any(k in lower_url for k in ("login", "signin", "auth")) else 0.0
    has_verify_keyword = 1.0 if any(k in lower_url for k in ("verify", "verification", "confirm")) else 0.0
    has_secure_keyword = 1.0 if any(k in lower_url for k in ("secure", "security", "protect")) else 0.0
    has_account_keyword = 1.0 if any(k in lower_url for k in ("account", "banking", "wallet", "paypal")) else 0.0

    # Repetitive patterns & longest token
    tokens = re.split(r"[\W_]+", lower_url)
    longest_token_length = float(max((len(t) for t in tokens if t), default=0))

    # Consecutive repeated characters (e.g. gooooogle)
    max_consecutive = 1
    current_consecutive = 1
    for i in range(1, len(lower_url)):
        if lower_url[i] == lower_url[i - 1]:
            current_consecutive += 1
            if current_consecutive > max_consecutive:
                max_consecutive = current_consecutive
        else:
            current_consecutive = 1
    max_consecutive_char = float(max_consecutive)

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_dots_domain": num_dots_domain,
        "num_subdomains": num_subdomains,
        "num_hyphens": num_hyphens,
        "num_hyphens_domain": num_hyphens_domain,
        "num_underscores": num_underscores,
        "num_slash": num_slash,
        "num_questionmarks": num_questionmarks,
        "num_equal": num_equal,
        "num_at": num_at,
        "num_percent": num_percent,
        "has_double_slash_redirect": has_double_slash_redirect,
        "is_ip_domain": is_ip,
        "has_port": has_port,
        "is_https": is_https,
        "domain_entropy": domain_entropy,
        "path_entropy": path_entropy,
        "url_entropy": url_entropy,
        "digit_ratio_url": digit_ratio_url,
        "digit_ratio_domain": digit_ratio_domain,
        "letter_ratio_domain": letter_ratio_domain,
        "special_char_ratio_url": special_char_ratio_url,
        "is_suspicious_tld": is_suspicious_tld,
        "is_punycode": is_punycode,
        "has_homoglyphs": has_homoglyphs,
        "risk_keyword_count": risk_keyword_count,
        "risk_keyword_score": risk_keyword_score,
        "has_login_keyword": has_login_keyword,
        "has_verify_keyword": has_verify_keyword,
        "has_secure_keyword": has_secure_keyword,
        "has_account_keyword": has_account_keyword,
        "max_consecutive_char": max_consecutive_char,
        "longest_token_length": longest_token_length,
    }


def extract_feature_vector(raw_url: str) -> np.ndarray:
    """Extract a 1D float32 numpy array matching FEATURE_NAMES order."""
    f_dict = extract_features_dict(raw_url)
    return np.array([f_dict[name] for name in FEATURE_NAMES], dtype=np.float32)


def extract_features_batch(urls: List[str]) -> np.ndarray:
    """Extract features for a list of URLs as a 2D float32 numpy matrix."""
    return np.array([extract_feature_vector(u) for u in urls], dtype=np.float32)


def identify_risk_factors(raw_url: str, features: Optional[Dict[str, float]] = None) -> List[str]:
    """Identify human-readable explainable security risk factors for a URL."""
    f = features if features is not None else extract_features_dict(raw_url)
    reasons: List[str] = []

    if f.get("is_ip_domain", 0) > 0:
        reasons.append("Raw IP address used as hostname instead of a registered domain")
    if f.get("is_punycode", 0) > 0:
        reasons.append("Punycode (xn--) domain detected; potential homograph spoofing")
    if f.get("has_homoglyphs", 0) > 0:
        reasons.append("Cyrillic/Greek homoglyphic characters mimicking Latin script")
    if f.get("is_suspicious_tld", 0) > 0:
        reasons.append("Top-Level Domain (TLD) associated with high-frequency malicious abuse")
    if f.get("num_at", 0) > 0:
        reasons.append("URL contains '@' symbol; often used to spoof legitimate destination host")
    if f.get("has_double_slash_redirect", 0) > 0:
        reasons.append("Embedded '//' redirect detected inside URL path")
    if f.get("num_subdomains", 0) >= 3:
        reasons.append(f"Excessive subdomain depth ({int(f['num_subdomains'])} levels) often used to conceal true domain")
    if f.get("domain_entropy", 0) >= 4.1:
        reasons.append(f"High domain character entropy ({f['domain_entropy']:.2f} bits) suggests DGA algorithm or random generator")
    if f.get("num_hyphens_domain", 0) >= 3:
        reasons.append(f"Excessive hyphenation in domain ({int(f['num_hyphens_domain'])}) common in typosquatting")
    if f.get("has_login_keyword", 0) > 0 and f.get("has_account_keyword", 0) > 0:
        reasons.append("High-risk credential harvesting keywords combination (login/banking/account)")
    elif f.get("risk_keyword_count", 0) >= 2:
        reasons.append(f"Multiple security/auth keywords present ({int(f['risk_keyword_count'])})")
    if f.get("digit_ratio_domain", 0) > 0.35:
        reasons.append(f"High numeric digit concentration in domain ({f['digit_ratio_domain']*100:.1f}%)")
    if f.get("url_length", 0) > 120:
        reasons.append(f"Abnormally long URL ({int(f['url_length'])} chars) often used to bury malicious payload")
    if f.get("is_https", 1) == 0 and f.get("has_login_keyword", 0) > 0:
        reasons.append("Insecure plain HTTP scheme combined with authentication targets")

    if not reasons and f.get("url_entropy", 0) > 4.5:
        reasons.append("Elevated overall URL entropy")

    return reasons


async def enrich_dns_async(domain: str, timeout_ms: float = 20.0) -> Dict[str, Any]:
    """Strictly bounded asynchronous DNS lookup.

    Guarantees completion within `timeout_ms` (default 20ms) using a hard timeout fallback.
    Never blocks inference or causes latency SLA breaches.
    """
    clean_domain = domain.split(":")[0].strip("[]")
    if not clean_domain or is_ip_address(clean_domain):
        return {"dns_resolved": True, "ip": clean_domain, "time_ms": 0.0, "status": "ip_literal"}

    def _sync_dns_query() -> Dict[str, Any]:
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout_ms / 1000.0
            resolver.timeout = timeout_ms / 1000.0
            answers = resolver.resolve(clean_domain, "A")
            ips = [rdata.to_text() for rdata in answers]
            return {"dns_resolved": True, "ips": ips, "status": "resolved"}
        except Exception as e:
            return {"dns_resolved": False, "ips": [], "status": type(e).__name__}

    try:
        # Run synchronous dns call in default threadpool with hard asyncio timeout
        result = await asyncio.wait_for(
            asyncio.to_thread(_sync_dns_query),
            timeout=timeout_ms / 1000.0
        )
        return result
    except (asyncio.TimeoutError, Exception):
        return {"dns_resolved": None, "ips": [], "status": "timeout_fallback"}
