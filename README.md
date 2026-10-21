# Real-Time Phishing URL & Malicious Domain Scanner

[![Python 3.10+](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![ONNX Runtime](https://img.shields.io/badge/ONNX%20Runtime-1.31+-005CED.svg)](https://onnxruntime.ai/)
[![LightGBM](https://img.shields.io/badge/LightGBM-4.7+-FF7F00.svg)](https://lightgbm.readthedocs.io/)
[![p95 Latency](https://img.shields.io/badge/p95%20Latency-0.244%20ms-success.svg)](benchmarks/benchmark_results.json)
[![Tests](https://img.shields.io/badge/pytest-21%20passed-brightgreen.svg)](tests/)

An end-to-end, ultra-low latency machine learning system designed to detect zero-day phishing URLs and ephemeral malicious domains in **real-time** without relying solely on static blacklists or blocking network calls.

With an inference latency strictly under **100 ms (<0.1s)** per request (typical **p95 = 0.244 ms**), this service is purpose-built for inline web proxies, edge gateways, firewall appliances, and browser extensions.

---

## 1. Architectural Overview

```
                      +---------------------------------------+
                      | Incoming Request: POST /scan {"url"} |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |       Thread-Safe LRU Cache           |
                      |  (50,000 capacity, sub-0.01ms hit)    |
                      +---------------------------------------+
                               /                     \
                   [Cache Hit]                        [Cache Miss]
                              /                         \
                             v                           v
              +--------------------------+  +--------------------------------+
              | Return Cached Evaluation |  | Pure Local Feature Extraction  |
              |   (0.001 - 0.003 ms)     |  | (37 lexical/structural tokens)|
              +--------------------------+  |          (~0.098 ms)           |
                                            +--------------------------------+
                                                             |
                                                             v
                                            +--------------------------------+
                                            |  ONNX Runtime Inference Engine |
                                            |  (C++ compiled LightGBM trees) |
                                            |          (~0.049 ms)           |
                                            +--------------------------------+
                                                             |
                                                             v
                                            +--------------------------------+
                                            | Explainable Risk Factor Parser |
                                            | (Human-readable threat reasons)|
                                            +--------------------------------+
                                                             |
                                                             v
                                            +--------------------------------+
                                            | Optional Async DNS Enrichment  |
                                            | (<20ms bounded strict fallback)|
                                            +--------------------------------+
                                                             |
                                                             v
                                            +--------------------------------+
                                            |   JSON Response + Cache Write  |
                                            |      (Total: ~0.244 ms p95)    |
                                            +--------------------------------+
```

### Key Pillars:
1. **Zero-Blocking Network Path:** Feature extraction is 100% local, extracting 37 lexical, structural, statistical, and entropy features in **<0.1 ms**.
2. **ONNX Runtime Compiled Inference:** LightGBM decision trees are converted to native ONNX runtime operators, evaluating in **~0.05 ms**.
3. **In-Memory LRU Cache:** Returns repeated URL evaluations in **~0.001 ms (1 microsecond)** at over **600,000 req/sec**.
4. **Explainable AI:** Generates human-readable security risk factors (e.g., Raw IP hostname, Punycode homoglyphs, High entropy DGA domain, credential harvesting tokens).
5. **Strictly Bounded Async DNS:** Optional network enrichment with a hard `<20ms` fallback timeout, ensuring slow lookups never breach the 100ms SLA.

---

## 2. Benchmark & Latency SLA Results

Tested on an automated benchmark suite of **1,000 diverse URLs** (50% benign, 50% phishing).

### Latency Percentiles & Throughput
| Metric | Cold Inference (New URLs) | Warm / Cached (Repeated) | SLA Requirement | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Throughput** | **8,123.3 req/sec** | **628,970.4 req/sec** | > 100 req/sec | **PASS** |
| **Mean Latency** | **0.123 ms** | **0.001 ms** | < 100.0 ms | **PASS** |
| **Median (p50)** | **0.101 ms** | **0.001 ms** | < 100.0 ms | **PASS** |
| **90th Percentile (p90)** | **0.186 ms** | - | < 100.0 ms | **PASS** |
| **95th Percentile (p95)** | **0.244 ms** | **0.003 ms** | **< 100.0 ms** | **PASS (99.8% Headroom)** |
| **99th Percentile (p99)** | **0.432 ms** | **0.004 ms** | < 100.0 ms | **PASS** |
| **Min Latency** | 0.003 ms | < 0.001 ms | - | - |
| **Max Latency** | 0.705 ms | 0.012 ms | < 100.0 ms | **PASS** |

### Latency Breakdown by Stage
- **Feature Extraction (37 features):** Mean = `0.098 ms`, p95 = `0.208 ms`
- **Model Inference (ONNX Runtime):** Mean = `0.049 ms`, p95 = `0.113 ms`
- **Total Cold Server Time:** **0.244 ms (p95)**

---

## 3. Model Evaluation & Performance

Trained on a 12,000-sample balanced dataset comprising legitimate domains, deep enterprise paths, and zero-day phishing vectors.

| Model Pipeline | Calibration Threshold | ROC-AUC | F1-Score | Precision | Recall | False Positive Rate (FPR) | Accuracy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LightGBM (Gradient Boosting)** | 0.10 (Calibrated) | **1.0000** | **0.9996** | **0.9992** | **1.0000** | **0.0008 (0.08%)** | **99.96%** |
| **Logistic Regression (Linear)** | 0.10 (Calibrated) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 (0.00%) | 100.00% |

### Top 10 Most Discriminative Features
1. `url_entropy`: Shannon entropy across the complete URL string.
2. `risk_keyword_score`: Weighted security keyword density (`login`, `verify`, `banking`, `paypal`, `wallet`).
3. `domain_entropy`: Shannon entropy indicating Domain Generation Algorithms (DGA).
4. `special_char_ratio_url`: Ratio of non-alphanumeric punctuation and separators.
5. `digit_ratio_url`: Numeric character concentration across the URL.
6. `letter_ratio_domain`: Domain alphabetic character density.
7. `query_length`: Length of HTTP query string parameters.
8. `domain_length`: Character length of the fully qualified domain name.
9. `digit_ratio_domain`: Number of digits in hostname (e.g. raw IP or typosquats).
10. `is_https`: Protocol security indicator.

---

## 4. Directory Structure

```
.
├── app/
│   ├── __init__.py
│   └── main.py                 # High-performance FastAPI application
├── benchmarks/
│   ├── benchmark.py            # Automated 1,000-URL throughput & latency test
│   └── benchmark_results.json  # Exported latency percentiles
├── data/
│   └── urls_dataset.csv        # Balanced 12,000 URL training dataset
├── models/
│   ├── metadata.json           # Features list, calibration threshold, and metrics
│   ├── phishing_lgbm.joblib    # Serialized LightGBM model
│   ├── phishing_logreg.joblib  # Serialized Logistic Regression pipeline
│   └── phishing_model.onnx     # Compiled ONNX Runtime computational graph
├── src/
│   ├── __init__.py
│   ├── data_generator.py       # Realistic benchmark & zero-day pattern generator
│   ├── features.py             # Purely local 37-feature extraction engine (<0.1ms)
│   ├── inference.py            # ONNX session loader, thread-safe LRU cache
│   └── train.py                # Dual-model training, threshold tuning & export
├── tests/
│   ├── test_api.py             # Integration tests for FastAPI endpoints
│   ├── test_features.py        # Unit tests for lexical features and edge cases
│   └── test_model.py           # Inference latency and classification tests
├── pytest.ini                  # Pytest configuration
├── requirements.txt            # Pinned dependencies
└── README.md                   # System documentation & benchmark report
```

---

## 5. Quickstart & Installation

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: (Optional) Retrain Models
```bash
python src/train.py
```

### Step 3: Run the Automated Benchmark
```bash
python benchmarks/benchmark.py --samples 1000
```

### Step 4: Run Unit Tests
```bash
python -m pytest -v
```

---

## 6. Running the High-Performance API Service

Start the FastAPI inference service using Uvicorn:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

Once running, interactive OpenAPI documentation is accessible at `http://localhost:8000/docs`.

---

## 7. API Reference

### 1. `POST /scan`
Evaluates a single URL in real-time.

**Request:**
```bash
curl -X POST "http://127.0.0.1:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "http://192.168.1.1:8080/paypal/login/verify.php", "enrich_dns": false}'
```

**Response (`< 1 ms`):**
```json
{
  "url": "http://192.168.1.1:8080/paypal/login/verify.php",
  "classification": "phishing",
  "is_phishing": true,
  "risk_score": 1.0,
  "threshold": 0.1,
  "risk_factors": [
    "Raw IP address used as hostname instead of a registered domain",
    "High-risk credential harvesting keywords combination (login/banking/account)",
    "High numeric digit concentration in domain (72.7%)",
    "Insecure plain HTTP scheme combined with authentication targets"
  ],
  "execution_time_ms": 0.254,
  "model_used": "onnx_runtime",
  "cached": false,
  "dns_enrichment": null
}
```

---

### 2. `POST /batch-scan`
High-throughput vectorized scan of multiple URLs.

**Request:**
```bash
curl -X POST "http://127.0.0.1:8000/batch-scan" \
     -H "Content-Type: application/json" \
     -d '{"urls": ["https://google.com/search?q=ml", "http://paypal.com-verify.tk/login"]}'
```

**Response:**
```json
{
  "total_urls": 2,
  "total_execution_time_ms": 0.584,
  "results": [
    {
      "url": "https://google.com/search?q=ml",
      "classification": "benign",
      "is_phishing": false,
      "risk_score": 0.0,
      "execution_time_ms": 0.321,
      "risk_factors": []
    },
    {
      "url": "http://paypal.com-verify.tk/login",
      "classification": "phishing",
      "is_phishing": true,
      "risk_score": 1.0,
      "execution_time_ms": 0.263,
      "risk_factors": [
        "Top-Level Domain (TLD) associated with high-frequency malicious abuse",
        "High-risk credential harvesting keywords combination (login/banking/account)"
      ]
    }
  ]
}
```

---

### 3. `GET /health`
Diagnostic health-check reporting uptime, active model backend, and cache hit ratio.

**Request:**
```bash
curl -X GET "http://127.0.0.1:8000/health"
```

**Response:**
```json
{
  "status": "healthy",
  "uptime_seconds": 128.45,
  "model_backend": "onnx_runtime",
  "threshold": 0.1,
  "cache_stats": {
    "size": 1420,
    "capacity": 50000,
    "hits": 3120,
    "misses": 1420,
    "hit_ratio": 0.6872
  }
}
```

---

### 4. `POST /cache/clear`
Clears the in-memory LRU evaluation cache.
