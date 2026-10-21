"""Unit tests for model loading, latency, and prediction inference."""

import os
import time
import pytest
from src.features import extract_feature_vector
from src.inference import PhishingScanner


@pytest.fixture(scope="module")
def scanner():
    return PhishingScanner(models_dir="models")


def test_model_initialization(scanner):
    """Verify model loaded properly (ONNX or LightGBM)."""
    assert scanner.model_backend in ("onnx_runtime", "lightgbm_native", "logistic_regression")
    assert scanner.threshold > 0.0


def test_inference_latency(scanner):
    """Verify single URL inference latency is strictly <10ms (and typical <2ms)."""
    url = "https://www.wikipedia.org/wiki/Computer_science"

    # Warmup
    scanner.scan_sync(url)

    latencies = []
    for _ in range(50):
        t0 = time.perf_counter()
        res = scanner.scan_sync("https://github.com/torvalds/linux")
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt_ms)

    avg_ms = sum(latencies) / len(latencies)
    assert avg_ms < 10.0, f"Average latency {avg_ms:.2f}ms exceeds 10ms target"


def test_benign_classification(scanner):
    """Verify legitimate popular domains are classified as benign."""
    legit_urls = [
        "https://www.google.com/search?q=weather",
        "https://github.com/features/actions",
        "https://en.wikipedia.org/wiki/Deep_learning",
        "https://docs.python.org/3/library/asyncio.html",
    ]
    for u in legit_urls:
        res = scanner.scan_sync(u)
        assert res["classification"] == "benign"
        assert res["is_phishing"] is False
        assert res["risk_score"] < 0.5


def test_phishing_classification(scanner):
    """Verify glaring phishing patterns are classified as phishing."""
    phishing_urls = [
        "http://192.168.1.100:8080/paypal/login/verify.html",
        "http://paypal.com-account-update.tk/signin.php",
        "http://appleid.apple.com-verify.ga/auth",
        "https://secure-banking-login.xyz/confirm?session=99281",
    ]
    for u in phishing_urls:
        res = scanner.scan_sync(u)
        assert res["classification"] == "phishing"
        assert res["is_phishing"] is True
        assert res["risk_score"] >= scanner.threshold
        assert len(res["risk_factors"]) > 0
