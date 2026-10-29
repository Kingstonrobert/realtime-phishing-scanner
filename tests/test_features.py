"""Unit tests for URL feature extraction and edge cases."""

import numpy as np
import pytest

from src.features import (
    FEATURE_NAMES,
    check_homoglyphs,
    clean_and_parse_url,
    extract_feature_vector,
    extract_features_dict,
    identify_risk_factors,
    is_ip_address,
    shannon_entropy,
)


def test_feature_vector_structure():
    """Verify feature vector length, types, and absence of NaNs or Infs."""
    url = "https://www.google.com/search?q=machine+learning"
    vec = extract_feature_vector(url)

    assert isinstance(vec, np.ndarray)
    assert vec.shape == (len(FEATURE_NAMES),)
    assert vec.dtype == np.float32
    assert not np.isnan(vec).any(), "Feature vector contains NaN"
    assert not np.isinf(vec).any(), "Feature vector contains Inf"


def test_shannon_entropy():
    """Verify entropy calculations for uniform, random, and empty strings."""
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    # "ab" uniform -> 1 bit of entropy
    assert pytest.approx(shannon_entropy("ab"), 0.01) == 1.0
    # High entropy string
    ent = shannon_entropy("x8q1b9z03jfkals")
    assert ent > 3.0


def test_ip_address_detection():
    """Verify IPv4 and IPv6 detection."""
    assert is_ip_address("192.168.1.1")
    assert is_ip_address("10.0.0.1:8080")
    assert is_ip_address("[2001:db8::1]")
    assert not is_ip_address("google.com")
    assert not is_ip_address("paypal.com.evil.com")


def test_homoglyph_detection():
    """Verify detection of confusable Cyrillic/Greek characters."""
    # Latin 'paypal'
    assert not check_homoglyphs("paypal.com")
    # Cyrillic 'а' (U+0430) substituted in 'pаypal'
    cyrillic_a = "\u0430"
    spoofed = f"p{cyrillic_a}ypal.com"
    assert check_homoglyphs(spoofed)


def test_visual_confusables_and_typosquatting():
    """Verify detection of visual ASCII substitutions like rn -> m, 0 -> o, 1 -> l."""
    # 'rn' mimicking 'm' in 'rnicrosoft'
    f_rn = extract_features_dict("http://rnicrosoft.com")
    assert f_rn["is_typosquatting"] == 1.0
    reasons_rn = identify_risk_factors("http://rnicrosoft.com", f_rn)
    assert any("Microsoft" in r and "rn" in r for r in reasons_rn)

    # '1' mimicking 'l' in 'paypa1'
    f_pay = extract_features_dict("http://paypa1.com")
    assert f_pay["is_typosquatting"] == 1.0

    # Legitimate Microsoft
    f_legit = extract_features_dict("https://www.microsoft.com")
    assert f_legit["is_typosquatting"] == 0.0


def test_punycode_detection():
    """Verify Punycode detection flag."""
    puny_url = "http://xn--gogle-pra.com/signin"
    feats = extract_features_dict(puny_url)
    assert feats["is_punycode"] == 1.0


def test_suspicious_tld_flag():
    """Verify flagging of known abused TLDs."""
    tld_url = "http://login-portal.tk/auth"
    feats = extract_features_dict(tld_url)
    assert feats["is_suspicious_tld"] == 1.0

    legit_url = "https://mybank.com/portal"
    feats_legit = extract_features_dict(legit_url)
    assert feats_legit["is_suspicious_tld"] == 0.0


def test_double_slash_redirect_detection():
    """Verify embedded '//' in path is detected."""
    url = "https://legit-service.com//evil-phish.net/login"
    feats = extract_features_dict(url)
    assert feats["has_double_slash_redirect"] == 1.0


def test_userinfo_at_symbol():
    """Verify @ symbol in URL is counted."""
    url = "https://google.com@phish-attacker.xyz/secure"
    feats = extract_features_dict(url)
    assert feats["num_at"] == 1.0


def test_malformed_and_extreme_urls():
    """Verify robustness on empty, malformed, non-standard schemes, and huge URLs."""
    edge_cases = [
        "",
        "   ",
        "ftp://files.example.com",
        "custom-scheme://host/path",
        "://malformed.url",
        "http://",
        "https://" + "a" * 3000 + ".com/path",
        "123.456.789.000",
        "http://[::1]:8080/path",
        "https://example.com/???query=&&&",
    ]
    for url in edge_cases:
        vec = extract_feature_vector(url)
        assert len(vec) == len(FEATURE_NAMES)
        assert not np.isnan(vec).any()
        assert not np.isinf(vec).any()


def test_identify_risk_factors():
    """Verify human-readable risk factors are produced accurately."""
    phish_url = "http://192.168.0.1:8080/paypal/login/verify.php"
    reasons = identify_risk_factors(phish_url)
    assert any("IP address" in r for r in reasons)
    assert any("credential" in r.lower() or "login" in r.lower() for r in reasons)
