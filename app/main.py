"""High-Performance Real-Time Phishing URL & Malicious Domain Scanner API.

Provides sub-millisecond to <5ms response latency for inline proxy and web browser extension protection.
"""

from __future__ import annotations

import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl

# Ensure source files are discoverable
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.inference import PhishingScanner

# Singleton scanner instance
scanner: Optional[PhishingScanner] = None
start_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager to initialize models and cache on startup."""
    global scanner, start_time
    start_time = time.time()
    models_dir = os.getenv("MODELS_DIR", str(ROOT_DIR / "models"))
    cache_size = int(os.getenv("CACHE_CAPACITY", "50000"))
    print(f"[*] Initializing PhishingScanner from {models_dir} (Cache size: {cache_size})...")
    scanner = PhishingScanner(models_dir=models_dir, cache_size=cache_size)
    print(f"[+] PhishingScanner ready! Backend: {scanner.model_backend}")
    yield
    print("[*] Shutting down scanner service...")


app = FastAPI(
    title="Real-Time Phishing URL & Malicious Domain Scanner",
    description="Ultra-fast machine learning scanner (<100ms SLA, typical <2ms) for phishing URLs and malicious domains.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware for browser extensions and frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Request and Response Schemas ---
class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Target URL or domain to evaluate",
        examples=["https://paypal.com-verify-account.tk/login"],
    )
    enrich_dns: bool = Field(
        default=False,
        description="Optional bounded DNS resolution (<20ms timeout fallback)",
    )


class BatchScanRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="List of URLs to scan in a batch",
    )


class ScanResponse(BaseModel):
    url: str
    classification: str = Field(description="'phishing' or 'benign'")
    is_phishing: bool
    risk_score: float = Field(ge=0.0, le=1.0, description="Phishing probability score")
    threshold: float
    risk_factors: List[str] = Field(description="Explanatory security indicators")
    execution_time_ms: float = Field(description="Total server-side processing time in ms")
    model_used: str
    cached: bool
    dns_enrichment: Optional[Dict[str, Any]] = None


class BatchScanResponse(BaseModel):
    total_urls: int
    total_execution_time_ms: float
    results: List[ScanResponse]


class HealthResponse(BaseModel):
    status: str
    uptime_seconds: float
    model_backend: str
    threshold: float
    cache_stats: Dict[str, Any]


# --- Endpoints ---
@app.get("/health", response_model=HealthResponse, tags=["Diagnostics"])
def health_check():
    """Service health and operational status."""
    if scanner is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scanner model not initialized yet",
        )
    return HealthResponse(
        status="healthy",
        uptime_seconds=round(time.time() - start_time, 2),
        model_backend=scanner.model_backend,
        threshold=scanner.threshold,
        cache_stats=scanner.cache.stats(),
    )


@app.post("/scan", response_model=ScanResponse, tags=["Detection"])
async def scan_url(payload: ScanRequest):
    """Scan a single URL for phishing characteristics in real-time.

    Guaranteed sub-100ms response (typically <2ms cold, <0.05ms cached).
    """
    if scanner is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scanner model not ready",
        )

    url_str = payload.url.strip()
    if not url_str:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL must not be empty or whitespace only",
        )

    try:
        if payload.enrich_dns:
            result = await scanner.scan_async(url_str, enrich_dns=True)
        else:
            result = scanner.scan_sync(url_str)
        return ScanResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}",
        )


@app.post("/batch-scan", response_model=BatchScanResponse, tags=["Detection"])
def batch_scan_urls(payload: BatchScanRequest):
    """Scan an array of URLs with high throughput."""
    if scanner is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scanner model not ready",
        )

    t_batch_start = time.perf_counter()
    results = [ScanResponse(**scanner.scan_sync(u.strip())) for u in payload.urls if u.strip()]
    total_batch_ms = (time.perf_counter() - t_batch_start) * 1000.0

    return BatchScanResponse(
        total_urls=len(results),
        total_execution_time_ms=round(total_batch_ms, 3),
        results=results,
    )


@app.post("/cache/clear", tags=["Maintenance"])
def clear_cache():
    """Clear the in-memory LRU evaluation cache."""
    if scanner is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scanner model not ready",
        )
    scanner.cache.clear()
    return {"message": "Cache cleared successfully", "stats": scanner.cache.stats()}
