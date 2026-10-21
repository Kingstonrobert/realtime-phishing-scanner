"""Ultra-low latency inference engine with ONNX runtime and in-memory LRU cache."""

from __future__ import annotations

import json
import os
import sys
import time
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

# Ensure local imports work cleanly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.features import (
    FEATURE_NAMES,
    enrich_dns_async,
    extract_feature_vector,
    extract_features_dict,
    identify_risk_factors,
)

try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False


class ThreadSafeLRUCache:
    """High-throughput, thread-safe in-memory LRU cache for URL scan results."""

    def __init__(self, capacity: int = 50000):
        self.capacity = capacity
        self.cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
                self.hits += 1
                return self.cache[key]
            self.misses += 1
            return None

    def put(self, key: str, value: Dict[str, Any]) -> None:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

    def clear(self) -> None:
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            total = self.hits + self.misses
            ratio = (self.hits / total) if total > 0 else 0.0
            return {
                "size": len(self.cache),
                "capacity": self.capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio": round(ratio, 4),
            }


class PhishingScanner:
    """Production inference scanner designed for <5ms cold and <0.1ms cached latency."""

    def __init__(self, models_dir: str = "models", cache_size: int = 50000):
        self.models_dir = Path(models_dir)
        self.cache = ThreadSafeLRUCache(capacity=cache_size)
        self.onnx_session: Optional[Any] = None
        self.lgb_model: Optional[Any] = None
        self.threshold = 0.5
        self.metadata: Dict[str, Any] = {}
        self.model_backend = "none"

        self._load_metadata()
        self._load_model()

    def _load_metadata(self) -> None:
        meta_file = self.models_dir / "metadata.json"
        if meta_file.exists():
            with open(meta_file, "r") as f:
                self.metadata = json.load(f)
                self.threshold = float(self.metadata.get("default_threshold", 0.5))

    def _load_model(self) -> None:
        onnx_file = self.models_dir / "phishing_model.onnx"
        joblib_file = self.models_dir / "phishing_lgbm.joblib"

        # 1. Prefer ONNX runtime for C++ compiled inference speed
        if HAS_ONNX and onnx_file.exists():
            try:
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 2
                opts.inter_op_num_threads = 2
                opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self.onnx_session = ort.InferenceSession(
                    str(onnx_file),
                    sess_options=opts,
                    providers=["CPUExecutionProvider"],
                )
                self.model_backend = "onnx_runtime"
                return
            except Exception as e:
                print(f"[!] Warning: Failed to initialize ONNX session ({e}). Falling back to LightGBM...")

        # 2. Fallback to LightGBM
        if joblib_file.exists():
            try:
                self.lgb_model = joblib.load(joblib_file)
                self.model_backend = "lightgbm_native"
                return
            except Exception as e:
                print(f"[!] Warning: Failed to load LightGBM ({e}).")

        # 3. Fallback to Logistic Regression
        lr_file = self.models_dir / "phishing_logreg.joblib"
        if lr_file.exists():
            self.lgb_model = joblib.load(lr_file)
            self.model_backend = "logistic_regression"
            return

        raise RuntimeError(f"No trained model found in {self.models_dir}. Please run train.py first.")

    def _predict_raw(self, feature_vec: np.ndarray) -> float:
        """Execute raw inference returning probability of phishing (0.0 to 1.0)."""
        # Ensure 2D shape (1, num_features)
        X = np.ascontiguousarray(feature_vec.reshape(1, -1), dtype=np.float32)

        if self.onnx_session is not None:
            input_name = self.onnx_session.get_inputs()[0].name
            outputs = self.onnx_session.run(None, {input_name: X})
            # ONNX LightGBM classifier returns [labels, probabilities_sequence_or_tensor]
            if len(outputs) > 1:
                prob_output = outputs[1]
                if isinstance(prob_output, list) and isinstance(prob_output[0], dict):
                    # Sequence of maps {class_id: probability}
                    return float(prob_output[0].get(1, 0.0))
                elif isinstance(prob_output, np.ndarray):
                    if prob_output.ndim == 2 and prob_output.shape[1] >= 2:
                        return float(prob_output[0, 1])
                    return float(prob_output.ravel()[0])
            # Fallback to single output
            pred = outputs[0]
            if isinstance(pred, np.ndarray):
                return float(pred.ravel()[0])

        if self.lgb_model is not None:
            probas = self.lgb_model.predict_proba(X)
            return float(probas[0, 1])

        return 0.5

    def scan_sync(self, url: str) -> Dict[str, Any]:
        """Synchronously scan a URL with caching and <1ms typical latency."""
        t_start = time.perf_counter()
        normalized_url = url.strip()

        # 1. Cache hit check
        cached_result = self.cache.get(normalized_url)
        if cached_result is not None:
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            res = dict(cached_result)
            res["execution_time_ms"] = round(latency_ms, 3)
            res["cached"] = True
            return res

        # 2. Local feature extraction (< 0.5 ms)
        f_dict = extract_features_dict(normalized_url)
        feature_vec = np.array([f_dict[name] for name in FEATURE_NAMES], dtype=np.float32)

        # 3. Model inference (< 0.5 ms)
        risk_score = self._predict_raw(feature_vec)
        is_phishing = bool(risk_score >= self.threshold)
        classification = "phishing" if is_phishing else "benign"

        # 4. Human-readable risk explanations
        reasons = identify_risk_factors(normalized_url, f_dict)

        # 5. Build response object
        latency_ms = (time.perf_counter() - t_start) * 1000.0
        result = {
            "url": normalized_url,
            "classification": classification,
            "is_phishing": is_phishing,
            "risk_score": round(risk_score, 4),
            "threshold": self.threshold,
            "risk_factors": reasons,
            "execution_time_ms": round(latency_ms, 3),
            "model_used": self.model_backend,
            "cached": False,
        }

        # 6. Store in LRU cache
        self.cache.put(normalized_url, result)
        return result

    async def scan_async(self, url: str, enrich_dns: bool = False) -> Dict[str, Any]:
        """Asynchronously scan a URL with optional strictly bounded DNS enrichment."""
        res = self.scan_sync(url)

        if enrich_dns:
            from urllib.parse import urlparse
            t_dns_start = time.perf_counter()
            parsed = urlparse(url if "://" in url else f"http://{url}")
            domain = parsed.netloc or parsed.path.split("/")[0]
            dns_info = await enrich_dns_async(domain, timeout_ms=20.0)
            dns_ms = (time.perf_counter() - t_dns_start) * 1000.0

            res = dict(res)
            res["dns_enrichment"] = dns_info
            res["dns_time_ms"] = round(dns_ms, 2)
            res["execution_time_ms"] = round(res["execution_time_ms"] + dns_ms, 3)

        return res
