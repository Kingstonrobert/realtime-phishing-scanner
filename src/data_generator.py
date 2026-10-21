"""Realistic dataset generation and benchmark URL collection for phishing detection."""

from __future__ import annotations

import random
from typing import List, Tuple
import pandas as pd

BENIGN_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "github.com", "amazon.com",
    "wikipedia.org", "cloudflare.com", "stackoverflow.com", "reddit.com", "youtube.com",
    "linkedin.com", "nytimes.com", "bbc.co.uk", "medium.com", "yahoo.com",
    "stripe.com", "mozilla.org", "dropbox.com", "slack.com", "salesforce.com",
    "spotify.com", "adobe.com", "wordpress.org", "gitlab.com", "docker.com",
    "cnn.com", "theguardian.com", "nih.gov", "archive.org", "quora.com",
    "zoom.us", "vimeo.com", "ebay.com", "espn.com", "booking.com",
    "airbnb.com", "pinterest.com", "imdb.com", "craigslist.org", "etsy.com",
    "kaggle.com", "huggingface.co", "pypi.org", "npmjs.com", "ietf.org",
    "w3.org", "gnu.org", "apache.org", "python.org", "golang.org",
]

BENIGN_SUBDOMAINS = [
    "www", "api", "docs", "developer", "mail", "portal", "support",
    "blog", "cdn", "assets", "static", "status", "auth", "accounts",
    "cloud", "app", "dashboard", "help", "download", "community",
]

BENIGN_PATHS = [
    "",
    "/index.html",
    "/about",
    "/docs/getting-started",
    "/api/v2/items",
    "/search?q=machine+learning&category=tech",
    "/news/2026/03/technology-advancements",
    "/user/profile/settings",
    "/wiki/Computer_science",
    "/download/latest/release.tar.gz",
    "/products/detail?id=100234&ref=homepage",
    "/questions/74839210/how-to-optimize-latency",
    "/watch?v=dQw4w9WgXcQ&t=42s",
    "/blog/engineering/fast-inference-architecture",
    "/explore/trending/topics",
    "/terms-of-service",
    "/contact-us",
    "/pricing/plans?billing=annual",
    "/releases/tag/v2.1.0",
    "/help/articles/360012345",
]

SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "loan",
    "buzz", "club", "fit", "country", "stream", "gdn", "mom", "kim",
    "racing", "surfer", "download", "icu", "rest", "fail", "win", "bid",
    "monster", "bar", "men", "date", "party", "review",
]

TARGET_BRANDS = [
    "paypal", "appleid", "microsoft", "google", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "binance", "metamask",
    "coinbase", "facebook", "instagram", "dhl", "fedex", "usps",
]

PHISHING_KEYWORDS = [
    "login", "verify", "signin", "account", "banking", "secure", "update",
    "security", "wallet", "confirm", "auth", "credential", "recover",
    "billing", "invoice", "validate", "suspended", "unlock", "passcode",
]

RANDOM_WORDS = [
    "portal", "server", "gateway", "service", "client", "session",
    "webscr", "secureauth", "direct", "online", "alert", "notification",
    "helpdesk", "resolution", "check", "form", "identity",
]


def generate_benign_url(rng: random.Random) -> str:
    scheme = "https" if rng.random() > 0.1 else "http"
    base_domain = rng.choice(BENIGN_DOMAINS)
    
    # 40% chance to have a legitimate subdomain
    if rng.random() > 0.4:
        sub = rng.choice(BENIGN_SUBDOMAINS)
        domain = f"{sub}.{base_domain}"
    else:
        domain = base_domain
        
    path = rng.choice(BENIGN_PATHS)
    
    if path and "?" not in path and rng.random() > 0.6:
        path += f"?page={rng.randint(1, 10)}&lang=en"
        
    return f"{scheme}://{domain}{path}"


def generate_phishing_url(rng: random.Random) -> str:
    archetype = rng.choice([
        "ip_domain",
        "brand_subdomain_spoof",
        "suspicious_tld_combo",
        "homoglyph_punycode",
        "dga_high_entropy",
        "double_slash_redirect",
        "userinfo_at_spoof",
        "excessive_subdomains",
        "credential_harvesting_path",
    ])
    
    scheme = "http" if rng.random() > 0.35 else "https"
    brand = rng.choice(TARGET_BRANDS)
    kw = rng.choice(PHISHING_KEYWORDS)
    kw2 = rng.choice(PHISHING_KEYWORDS)
    word = rng.choice(RANDOM_WORDS)
    tld = rng.choice(SUSPICIOUS_TLDS)
    ext = rng.choice(["", ".html", ".php", ".aspx", ".htm"])
    has_query = rng.random() > 0.4

    if archetype == "ip_domain":
        # IP address domain with diverse path styles
        ip = f"{rng.randint(11, 215)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        port = f":{rng.choice([8080, 8443, 8000, 8888, 3000])}" if rng.random() > 0.5 else ""
        query_str = f"?id={rng.randint(10000, 99999)}" if has_query else ""
        
        path_style = rng.choice([
            f"/{brand}/{kw}{ext}",
            f"/{brand}/{kw}/{kw2}{ext}",
            f"/{kw}{ext}",
            f"/{brand}-security/{kw}{ext}",
        ])
        return f"http://{ip}{port}{path_style}{query_str}"

    elif archetype == "brand_subdomain_spoof":
        # e.g., paypal.com-account-verify.tk
        query_str = f"?session={rng.randint(100000, 999999)}" if has_query else ""
        return f"{scheme}://{brand}.com-{kw}-{word}.{tld}/{kw2}{ext}{query_str}"

    elif archetype == "suspicious_tld_combo":
        # e.g., secure-banking-login.xyz
        query_str = f"?token={rng.randint(1000, 9999)}" if has_query else ""
        return f"{scheme}://{brand}-{kw}-{word}.{tld}/{kw2}{ext}{query_str}"

    elif archetype == "homoglyph_punycode":
        # Punycode / typo spoofing
        puny_variants = [
            f"xn--{brand}-v9a.{tld}",
            f"xn--gogle-pra.{tld}",
            f"xn--pple-43d.{tld}",
            f"{brand.replace('o', '0').replace('l', '1')}-{kw}.{tld}",
        ]
        chosen = rng.choice(puny_variants)
        query_str = f"?ref={rng.randint(100, 999)}" if has_query else ""
        return f"{scheme}://{chosen}/{kw}{ext}{query_str}"

    elif archetype == "dga_high_entropy":
        # DGA domain
        rand_str = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(12, 20)))
        return f"{scheme}://{rand_str}.{tld}/{brand}/{kw}{ext}"

    elif archetype == "double_slash_redirect":
        # Redirect pattern
        legit = rng.choice(BENIGN_DOMAINS)
        return f"http://{legit}//{brand}-{kw}.{tld}/login?dest=auth"

    elif archetype == "userinfo_at_spoof":
        # @ symbol userinfo spoof
        legit = rng.choice(BENIGN_DOMAINS)
        return f"http://{legit}@{brand}-security-update.{tld}/index.html"

    elif archetype == "excessive_subdomains":
        # Multiple deep subdomains
        return f"{scheme}://{kw}.{brand}.support.{word}.verify.{rng.choice(RANDOM_WORDS)}.{tld}/auth"

    else:  # credential_harvesting_path
        query_str = f"?cmd=_login-run&dispatch={rng.randint(10000, 99999)}" if has_query else ""
        return f"{scheme}://{brand}-security-portal.{tld}/webscr{ext}{query_str}"


def generate_dataset(num_samples: int = 14000, seed: int = 42) -> pd.DataFrame:
    """Generate a balanced, high-variance dataset of benign and phishing URLs."""
    rng = random.Random(seed)
    half = num_samples // 2

    records: List[Tuple[str, int]] = []

    # Generate Benign URLs
    for _ in range(half):
        records.append((generate_benign_url(rng), 0))

    # Generate Phishing URLs
    for _ in range(num_samples - half):
        records.append((generate_phishing_url(rng), 1))

    # Shuffle
    rng.shuffle(records)

    df = pd.DataFrame(records, columns=["url", "label"])
    return df


if __name__ == "__main__":
    df = generate_dataset(num_samples=14000)
    df.to_csv("data/urls_dataset.csv", index=False)
    print(f"Dataset generated: {len(df)} URLs (Benign: {(df['label'] == 0).sum()}, Phishing: {(df['label'] == 1).sum()})")
