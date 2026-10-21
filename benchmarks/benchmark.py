"""Automated benchmarking script for throughput, latency percentiles, and SLA verification.

Tests over 1,000 sample URLs and asserts p95 latency remains strictly below 100ms.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

# Ensure local imports work cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.data_generator import generate_dataset
from src.features import extract_feature_vector, extract_features_dict
from src.inference import PhishingScanner


def run_benchmark(
    num_samples: int = 1000,
    models_dir: str = "models",
    output_json: str = "benchmarks/benchmark_results.json",
    assert_p95_under_100ms: bool = True,
) -> Dict[str, Any]:
    """Execute rigorous throughput, latency percentiles, and cache benchmark."""
    print("=" * 80)
    print(f"REAL-TIME PHISHING SCANNER BENCHMARK ({num_samples} URLs)")
    print("=" * 80)

    # 1. Initialize Scanner
    scanner = PhishingScanner(models_dir=models_dir)
    print(f"[*] Scanner initialized | Backend: {scanner.model_backend} | Default Threshold: {scanner.threshold}")

    # 2. Prepare 1,000 sample URLs (50% benign, 50% phishing)
    df = generate_dataset(num_samples=num_samples, seed=1337)
    sample_urls = df["url"].tolist()
    labels = df["label"].tolist()

    # Clear cache before cold benchmark
    scanner.cache.clear()

    # 3. Component Breakdown Benchmark (Feature Extraction vs Model Inference)
    feat_latencies_ms: List[float] = []
    infer_latencies_ms: List[float] = []

    print("\n[*] Benchmarking Component Level Latencies...")
    for u in sample_urls[:200]:
        t0 = time.perf_counter()
        f_vec = extract_feature_vector(u)
        t1 = time.perf_counter()
        _ = scanner._predict_raw(f_vec)
        t2 = time.perf_counter()

        feat_latencies_ms.append((t1 - t0) * 1000.0)
        infer_latencies_ms.append((t2 - t1) * 1000.0)

    avg_feat = float(np.mean(feat_latencies_ms))
    p95_feat = float(np.percentile(feat_latencies_ms, 95))
    avg_inf = float(np.mean(infer_latencies_ms))
    p95_inf = float(np.percentile(infer_latencies_ms, 95))

    print(f"    - Feature Extraction: Mean = {avg_feat:.3f} ms | p95 = {p95_feat:.3f} ms")
    print(f"    - Model Inference:    Mean = {avg_inf:.3f} ms | p95 = {p95_inf:.3f} ms")

    # 4. Cold Scan Latency Benchmark (1,000 unique URLs, zero cache hits)
    scanner.cache.clear()
    cold_latencies_ms: List[float] = []

    print(f"\n[*] Executing Cold Scan Benchmark across {num_samples} unique URLs...")
    t_start_cold = time.perf_counter()
    for u in sample_urls:
        t0 = time.perf_counter()
        res = scanner.scan_sync(u)
        dt = (time.perf_counter() - t0) * 1000.0
        cold_latencies_ms.append(dt)
    t_total_cold = time.perf_counter() - t_start_cold

    cold_throughput = num_samples / t_total_cold
    cold_mean = float(np.mean(cold_latencies_ms))
    cold_p50 = float(np.percentile(cold_latencies_ms, 50))
    cold_p90 = float(np.percentile(cold_latencies_ms, 90))
    cold_p95 = float(np.percentile(cold_latencies_ms, 95))
    cold_p99 = float(np.percentile(cold_latencies_ms, 99))
    cold_max = float(np.max(cold_latencies_ms))
    cold_min = float(np.min(cold_latencies_ms))

    # 5. Warm / Cached Scan Latency Benchmark (repeated hits on LRU cache)
    print("\n[*] Executing Warm / Cached Benchmark across 1,000 URLs...")
    warm_latencies_ms: List[float] = []
    t_start_warm = time.perf_counter()
    for u in sample_urls:
        t0 = time.perf_counter()
        res = scanner.scan_sync(u)
        dt = (time.perf_counter() - t0) * 1000.0
        warm_latencies_ms.append(dt)
    t_total_warm = time.perf_counter() - t_start_warm

    warm_throughput = num_samples / t_total_warm
    warm_mean = float(np.mean(warm_latencies_ms))
    warm_p50 = float(np.percentile(warm_latencies_ms, 50))
    warm_p95 = float(np.percentile(warm_latencies_ms, 95))
    warm_p99 = float(np.percentile(warm_latencies_ms, 99))

    # Print Formatted Report
    print("\n" + "=" * 80)
    print("BENCHMARK RESULTS SUMMARY")
    print("=" * 80)
    print(f"{'Metric':<30} | {'Cold Inference':<18} | {'Warm / Cached':<18}")
    print("-" * 80)
    print(f"{'Throughput (req/sec)':<30} | {cold_throughput:>15.1f} req/s | {warm_throughput:>15.1f} req/s")
    print(f"{'Mean Latency':<30} | {cold_mean:>15.3f} ms    | {warm_mean:>15.3f} ms")
    print(f"{'Median Latency (p50)':<30} | {cold_p50:>15.3f} ms    | {warm_p50:>15.3f} ms")
    print(f"{'90th Percentile (p90)':<30} | {cold_p90:>15.3f} ms    | -")
    print(f"{'95th Percentile (p95)':<30} | {cold_p95:>15.3f} ms    | {warm_p95:>15.3f} ms")
    print(f"{'99th Percentile (p99)':<30} | {cold_p99:>15.3f} ms    | {warm_p99:>15.3f} ms")
    print(f"{'Min Latency':<30} | {cold_min:>15.3f} ms    | -")
    print(f"{'Max Latency':<30} | {cold_max:>15.3f} ms    | -")
    print("=" * 80)

    # 6. Verify SLA Compliance
    print(f"\n[?] SLA Verification: p95 ({cold_p95:.3f} ms) < 100.000 ms Budget")
    if cold_p95 < 100.0:
        headroom = 100.0 - cold_p95
        print(f"[PASS] SLA STRICTLY SATISFIED! Latency is {cold_p95:.3f}ms (headroom: {headroom:.3f}ms, {headroom/100.0*100:.1f}%)")
    else:
        print(f"[FAIL] SLA BREACHED! p95 is {cold_p95:.3f}ms >= 100ms")
        if assert_p95_under_100ms:
            raise AssertionError(f"SLA breached: p95 latency {cold_p95:.3f}ms exceeds 100ms limit")

    results = {
        "num_samples": num_samples,
        "model_backend": scanner.model_backend,
        "sla_target_ms": 100.0,
        "sla_passed": bool(cold_p95 < 100.0),
        "components": {
            "feature_extraction_mean_ms": round(avg_feat, 4),
            "feature_extraction_p95_ms": round(p95_feat, 4),
            "model_inference_mean_ms": round(avg_inf, 4),
            "model_inference_p95_ms": round(p95_inf, 4),
        },
        "cold_scan": {
            "throughput_req_per_sec": round(cold_throughput, 1),
            "mean_ms": round(cold_mean, 4),
            "p50_ms": round(cold_p50, 4),
            "p90_ms": round(cold_p90, 4),
            "p95_ms": round(cold_p95, 4),
            "p99_ms": round(cold_p99, 4),
            "min_ms": round(cold_min, 4),
            "max_ms": round(cold_max, 4),
        },
        "warm_scan": {
            "throughput_req_per_sec": round(warm_throughput, 1),
            "mean_ms": round(warm_mean, 4),
            "p50_ms": round(warm_p50, 4),
            "p95_ms": round(warm_p95, 4),
            "p99_ms": round(warm_p99, 4),
        },
        "cache_stats": scanner.cache.stats(),
    }

    # Save results to json
    os.makedirs(os.path.dirname(output_json) or ".", exist_ok=True)
    with open(output_json, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Detailed benchmark report written to {output_json}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark URL Scanner")
    parser.add_argument("--samples", type=int, default=1000, help="Number of URLs to test")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory with models")
    parser.add_argument("--output", type=str, default="benchmarks/benchmark_results.json", help="JSON output file")
    args = parser.parse_args()

    run_benchmark(num_samples=args.samples, models_dir=args.models_dir, output_json=args.output)
