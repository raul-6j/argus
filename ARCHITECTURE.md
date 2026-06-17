# ARGUS — System Architecture
**Project:** ARGUS — Adaptive Real-time Guardian for URL Screening
**Course:** 21CSA699A | **Author:** Rahul Raj M A
**Version:** 1.0 | **Date:** June 2026
**Status:** Design phase — implement during M3–M6 (Weeks 5–13)

---

## 1. Component diagram

```
╔══════════════════════════════════════════════════════════════════════╗
║                        ARGUS SYSTEM                                  ║
║                                                                       ║
║  ┌─────────────────────────────────────────────────────────────────┐ ║
║  │                    TRAINING SUBSYSTEM                           │ ║
║  │                                                                 │ ║
║  │  ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌───────────┐  │ ║
║  │  │  Raw     │   │  Data     │   │ Feature  │   │  Model    │  │ ║
║  │  │ Datasets │──▶│  Pipeline │──▶│ Engineer │──▶│  Trainer  │  │ ║
║  │  │ UCI/Kaggle│  │(preprocess│   │(extract  │   │ (CV, eval,│  │ ║
║  │  │          │   │ +merge)   │   │ all tiers│   │  compare) │  │ ║
║  │  └──────────┘   └───────────┘   └──────────┘   └─────┬─────┘  │ ║
║  │                                                        │        │ ║
║  │                                              ┌─────────▼──────┐ │ ║
║  │                                              │  models/       │ │ ║
║  │                                              │  production/   │ │ ║
║  │                                              │  model.joblib  │ │ ║
║  │                                              └─────────┬──────┘ │ ║
║  └────────────────────────────────────────────────────────│────────┘ ║
║                                                           │           ║
║  ┌────────────────────────────────────────────────────────│────────┐ ║
║  │                   INFERENCE SUBSYSTEM                  │        │ ║
║  │                                                        │        │ ║
║  │  ┌─────────┐   ┌──────────────────────────────────┐   │        │ ║
║  │  │  Flask  │   │         EXTRACTOR               │   │        │ ║
║  │  │  REST   │   │                                  │   │        │ ║
║  │  │  API    │──▶│  ┌────────┐  ┌────────────────┐ │   │        │ ║
║  │  │         │   │  │Tier 1  │  │ Thread Pool    │ │   │        │ ║
║  │  │POST     │   │  │Lexical │  │ ┌────────────┐ │ │   │        │ ║
║  │  │/predict │   │  │(sync   │  │ │Tier 2 WHOIS│ │ │   │        │ ║
║  │  │         │   │  │< 1ms)  │  │ │(async)     │ │ │   │        │ ║
║  │  │GET      │   │  └────────┘  │ ├────────────┤ │ │   │        │ ║
║  │  │/health  │   │              │ │Tier 3 DNS  │ │ │   │        │ ║
║  │  │         │   │              │ │(async)     │ │ │   │        │ ║
║  │  │GET      │   │              │ └────────────┘ │ │   │        │ ║
║  │  │/models  │   │              └────────────────┘ │   │        │ ║
║  │  │         │   │                      │           │   │        │ ║
║  │  │GET      │   │  ┌───────────────────▼─────────┐│   │        │ ║
║  │  │/features│   │  │    Feature Vector Assembly  ││   │        │ ║
║  │  └────┬────┘   │  │  (impute sentinels → array) ││   │        │ ║
║  │       │        │  └───────────────────┬─────────┘│   │        │ ║
║  │       │        └──────────────────────│───────────┘   │        │ ║
║  │       │                               │               │        │ ║
║  │       │        ┌──────────────────────▼───────────────▼──────┐ │ ║
║  │       │        │          MODEL REGISTRY                      │ │ ║
║  │       │        │  (all 4 pipelines loaded at startup)         │ │ ║
║  │       │        │  production_model → predict_proba()          │ │ ║
║  │       └────────│─────────────────────────────────────────────▶│ │ ║
║  │                └─────────────────────────────────────────────┘ │ ║
║  └────────────────────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 2. Data flow: raw URL → prediction → API response

```
Client
  │
  │  POST /predict  {"url": "https://login-verify-paypal.xyz/..."}
  ▼
Flask route handler
  │
  ├─ [1] Input validation (Marshmallow schema)
  │      • URL format check (urlparse succeeds)
  │      • Length check (≤ 2048 chars)
  │      → 400 immediately if invalid
  │
  ├─ [2] Record request start time (time.perf_counter)
  │
  ├─ [3] Tier 1: URL lexical extraction (synchronous, ~0ms)
  │       url_lexical.extract(url) → dict[str, float]
  │       F01–F34 (34 features, all from string manipulation)
  │
  ├─ [4] Tier 2+3: Async enrichment (ThreadPoolExecutor, 1500ms timeout)
  │       PERSISTENT pool (module-level, not context manager — see §6)
  │       ├─ future_whois = pool.submit(whois_features.extract, domain)
  │       └─ future_dns   = pool.submit(dns_features.extract, domain)
  │
  │       wait([future_whois, future_dns], timeout=1.5)
  │       ├─ completed → merge result dict
  │       └─ timed out → sentinel dict  {key: -1, ..., "_timeout": True}
  │
  ├─ [5] Feature vector assembly
  │       extractor.assemble(tier1, tier2, tier3)
  │       → numpy array shape (1, 48) in trained column order
  │       → all sentinels (-1) handled by Pipeline's SimpleImputer
  │
  ├─ [6] Model inference
  │       model_registry.production.predict_proba(X) → [p_legit, p_phish]
  │       prediction = "phishing" if p_phish >= THRESHOLD else "legitimate"
  │       THRESHOLD from config.yaml (default 0.5; tune post-training)
  │
  ├─ [7] Record end time → latency_ms = (end - start) * 1000
  │
  └─ [8] Return JSON response (see §4)

Total wall time:
  • URL-only path (WHOIS/DNS fail or skip): ~8–15ms
  • Full enrichment path: ~250–900ms
  • Timeout fallback path: ~1500ms + ~10ms model inference
  • p99 target: <200ms for URL-only; <2000ms for enriched
```

---

## 3. Module breakdown: `src/` directory structure

```
argus/
│
├── app.py                        # Flask application factory + startup
│                                 # Loads model registry, starts thread pool,
│                                 # registers blueprints
│
├── config.py                     # Configuration loader
│                                 # Reads config/settings.yaml into dataclass
│                                 # Never hardcode thresholds — all in YAML
│
├── config/
│   └── settings.yaml             # All tunable values:
│                                 #   model_path, prediction_threshold,
│                                 #   whois_timeout_ms, feature_column_order,
│                                 #   suspicious_tld_list, keyword_list
│
├── api/
│   ├── __init__.py               # Blueprint registration
│   ├── predict.py                # POST /predict route
│   ├── health.py                 # GET /health route
│   ├── models.py                 # GET /models route (metadata)
│   └── schemas.py                # Marshmallow: PredictRequest, PredictResponse
│
├── features/
│   ├── __init__.py
│   ├── url_lexical.py            # Tier 1: F01–F34 (pure functions, no I/O)
│   │                             # extract(url: str) -> dict[str, float]
│   ├── whois_features.py         # Tier 2: F35–F41 (blocking, run in pool)
│   │                             # extract(domain: str) -> dict[str, float]
│   ├── dns_features.py           # Tier 3: F42–F48 (blocking, run in pool)
│   │                             # extract(domain: str) -> dict[str, float]
│   ├── html_features.py          # Tier 4: F49–F65 (training-time ONLY)
│   │                             # NOT imported by app.py
│   ├── ssl_features.py           # Tier 5: F66–F72 (training-time ONLY)
│   │                             # NOT imported by app.py
│   └── extractor.py              # Orchestrator
│                                 # • module-level ThreadPoolExecutor(max_workers=4)
│                                 # • extract_all(url) -> np.ndarray shape (1,48)
│                                 # • assemble(t1, t2, t3) -> ordered array
│
├── models/
│   ├── __init__.py
│   ├── registry.py               # ModelRegistry class
│   │                             # Loads all .joblib files at startup
│   │                             # Exposes: .production, .all_models dict
│   │                             # Thread-safe: models are read-only after load
│   └── production/
│       └── model.joblib          # Best model from M5 (scikit-learn Pipeline)
│           logistic_regression/  # All 4 models kept for /models endpoint
│           decision_tree/
│           random_forest/
│           svm/
│
├── training/                     # NOT part of the Flask app — run separately
│   ├── pipeline.py               # Full train-eval pipeline (Jupyter → script)
│   ├── feature_builder.py        # Extracts ALL tiers for training dataset
│   ├── evaluate.py               # CV, test metrics, confusion matrix, ROC
│   └── reproduce.py              # Seed enforcement, artifact hashing
│
├── data/
│   ├── raw/                      # Downloaded datasets (gitignored, large)
│   │   ├── uci_phishing.csv
│   │   └── kaggle_phishing.csv
│   └── processed/                # Output of training/pipeline.py
│       ├── train.parquet
│       ├── val.parquet
│       └── test.parquet          # Touched ONCE — only by evaluate.py
│
├── reports/                      # Output of evaluate.py (gitignored)
│   ├── model_comparison.json
│   ├── roc_curves.png
│   ├── confusion_matrices.png
│   └── feature_importance.png
│
├── tests/
│   ├── unit/
│   │   ├── test_url_lexical.py   # One test per feature function
│   │   ├── test_extractor.py     # Timeout fallback, sentinel handling
│   │   └── test_schemas.py       # Request validation edge cases
│   ├── integration/
│   │   ├── test_predict_endpoint.py  # Full /predict round-trip
│   │   └── test_latency.py           # p99 < 200ms assertion for URL-only
│   └── conftest.py               # Fixtures: test client, mock WHOIS/DNS
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt              # Pinned with pip-compile
├── requirements-dev.txt          # pytest, black, mypy, pip-tools
└── .env.example                  # ARGUS_MODEL_PATH, ARGUS_CONFIG_PATH
```

**Module responsibility rules:**

- `url_lexical.py` must be **pure**: no imports beyond stdlib (`re`, `urllib.parse`, `math`, `tldextract`). Zero side effects. Every function must be independently unit-testable with a string input.
- `html_features.py` and `ssl_features.py` must **never be imported** by `app.py` or `extractor.py`. They are training utilities. A CI lint rule should enforce this.
- `extractor.py` owns the **persistent thread pool** — one instance at module load, shared across all requests. Never create a new pool per request.
- `registry.py` loads models **once at startup** inside `create_app()`. All Flask request handlers get a read-only reference. Model objects are thread-safe for `predict_proba()` in scikit-learn.
- `config.py` must be the **single source of truth** for all thresholds. Any value that may need tuning post-training (prediction threshold, WHOIS timeout, TTL thresholds) lives in `settings.yaml`, not in code.

---

## 4. Flask API design

### 4.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/predict` | None | Classify a URL as phishing or legitimate |
| `GET` | `/health` | None | Liveness check — returns model load status |
| `GET` | `/models` | None | List loaded models and their metadata |
| `GET` | `/features` | None | Return feature schema (names, types, tiers) |

### 4.2 POST /predict

**Request:**
```json
{
  "url": "https://login-verify-paypal.xyz/account/secure",
  "mode": "full"
}
```

`mode` options:
- `"full"` (default) — Tier 1 + Tier 2 (WHOIS) + Tier 3 (DNS), up to 1500ms timeout
- `"fast"` — Tier 1 only, synchronous, <50ms guaranteed
- `"model_only"` — caller supplies pre-extracted features (for batch pipelines)

**Success response (200):**
```json
{
  "prediction": "phishing",
  "confidence": 0.94,
  "label": 1,
  "threshold_used": 0.5,
  "features_used": {
    "tier1_count": 22,
    "tier2_count": 5,
    "tier3_count": 4,
    "whois_available": true,
    "dns_available": true
  },
  "top_features": [
    {"name": "domain_age_days",       "value": 3,    "importance_rank": 1},
    {"name": "is_recently_registered","value": true, "importance_rank": 2},
    {"name": "has_ip_address",        "value": false,"importance_rank": 3}
  ],
  "model_version": "argus-rf-v1.0",
  "latency_ms": 387,
  "request_id": "a3f2c1d8-..."
}
```

**top_features** — top 3 feature values from the production model's feature importance ranking, included in every response. Enables the thesis Section 3.6 explainability claim without requiring SHAP at inference time.

**Error responses:**

| HTTP code | `error` value | Trigger condition |
|-----------|---------------|-------------------|
| `400` | `INVALID_URL` | `urlparse` fails, empty string, or length > 2048 |
| `400` | `MISSING_FIELD` | `url` key absent from request body |
| `422` | `MALFORMED_URL` | URL parses but has no hostname (e.g. `"javascript:void(0)"`) |
| `503` | `MODEL_NOT_LOADED` | Registry has no production model (startup failure) |
| `504` | `FEATURE_TIMEOUT` | All async enrichment timed out AND Tier 1 also failed |
| `500` | `INTERNAL_ERROR` | Uncaught exception — logged with request_id |

**Error response body (consistent schema):**
```json
{
  "error": "INVALID_URL",
  "message": "URL failed validation: no scheme present",
  "request_id": "a3f2c1d8-..."
}
```

### 4.3 GET /health

```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_version": "argus-rf-v1.0",
  "uptime_seconds": 3842
}
```

Returns `503` with `"status": "degraded"` if the model registry is empty.

### 4.4 GET /models

```json
{
  "production": "random_forest",
  "models": [
    {"name": "random_forest",      "version": "v1.0", "f1": 0.974, "recall": 0.968},
    {"name": "logistic_regression","version": "v1.0", "f1": 0.961, "recall": 0.953},
    {"name": "decision_tree",      "version": "v1.0", "f1": 0.958, "recall": 0.961},
    {"name": "svm",                "version": "v1.0", "f1": 0.971, "recall": 0.965}
  ]
}
```

---

## 5. Model serving strategy

### 5.1 What is serialised

Each trained model is serialised as a **complete scikit-learn Pipeline** via `joblib.dump`. The Pipeline wraps three stages:

```python
Pipeline([
    ("imputer", SimpleImputer(strategy="median")),   # handles -1 sentinels
    ("scaler",  StandardScaler()),                   # fit on train set ONLY
    ("clf",     <classifier>)                        # DT / RF / LR / SVM
])
```

Serialising the full Pipeline (not just the classifier) is critical for two reasons:
1. The scaler's `mean_` and `scale_` arrays are training-set statistics — they must be the same at inference as at training. Serialising them inside the Pipeline eliminates any possibility of mismatch.
2. The imputer's `statistics_` (median per feature) handles the `-1` sentinel values that Tiers 2 and 3 return on timeout. These must match the imputation applied during training.

**Benchmark sizes (48 features, 11k training samples):**

| Model | Serialised | In-memory | Inf latency |
|-------|-----------|-----------|-------------|
| Random Forest (n=100) | 25.9 MB | ~30 MB | 6.3 ms |
| SVM (rbf, probability) | 4.1 MB | ~5 MB | 1.0 ms |
| Decision Tree | 0.3 MB | ~1 MB | 0.3 ms |
| Logistic Regression | 0.003 MB | <1 MB | 0.3 ms |

**Cap RF at `n_estimators=100`** for Azure free-tier deployment. n=200 doubles both serialised size (52MB) and inference time (12.7ms) with negligible accuracy gain on this dataset size.

### 5.2 Startup loading strategy

```python
# app.py — create_app()

def create_app(config_path: str = "config/settings.yaml") -> Flask:
    app = Flask(__name__)
    cfg = load_config(config_path)

    # Load ALL models at startup — not lazily.
    # Reasoning: lazy loading introduces latency on the first real request.
    # Total startup memory: ~275 MB (well within 1GB Azure limit).
    registry = ModelRegistry(cfg.models_dir)
    registry.load_all()          # Loads 4 .joblib files synchronously
    registry.set_production(cfg.production_model_name)

    # Validate production model can produce predictions before accepting traffic
    registry.warmup()            # Runs a single dummy prediction — catches
                                 # joblib version mismatch at startup, not runtime

    app.registry = registry
    # ... register blueprints, error handlers
    return app
```

`registry.warmup()` is the defensive pattern for a common failure mode: if the model was trained on Python 3.11 + scikit-learn 1.4 but the container runs Python 3.10 + scikit-learn 1.3, joblib will load the file silently but `predict_proba()` will raise a `ValueError`. Catching this at startup (which causes the container to fail fast and restart) is far safer than catching it on the first real request.

### 5.3 Thread safety

scikit-learn's `predict_proba()` is **thread-safe for read-only inference** — multiple Flask worker threads can call it concurrently without a lock. This is only true because inference does not mutate the fitted model object. Do not call `fit()` or `partial_fit()` from the request path.

---

## 6. Concurrency design

### 6.1 The critical bug to avoid

**Never use `ThreadPoolExecutor` as a context manager for timeout-bounded async work.**

When using `with ThreadPoolExecutor(...) as pool:`, Python's `__exit__` calls `pool.shutdown(wait=True)`, which **blocks until every submitted future completes** — even if `wait()` already returned due to timeout. Measured consequence: a 1,500ms timeout with a 2,000ms WHOIS call takes 2,000ms, not 1,500ms.

```python
# ❌ WRONG — __exit__ blocks 2,000ms despite 1,500ms timeout
def extract_async(url):
    with ThreadPoolExecutor(max_workers=2) as pool:   # BUG: blocks on exit
        fw = pool.submit(whois_features.extract, url)
        fd = pool.submit(dns_features.extract, url)
        done, _ = wait([fw, fd], timeout=1.5)         # fires correctly
        # ... but __exit__ still waits for fw to finish
```

```python
# ✅ CORRECT — persistent module-level pool, no context manager
_POOL = ThreadPoolExecutor(max_workers=4)   # created once at module load

def extract_async(url: str, timeout: float = 1.5) -> tuple[dict, dict]:
    domain = tldextract.extract(url).registered_domain
    fw = _POOL.submit(whois_features.extract, domain)
    fd = _POOL.submit(dns_features.extract, domain)
    done, _ = wait([fw, fd], timeout=timeout)
    whois = fw.result() if fw in done else _sentinel_whois()
    dns   = fd.result() if fd in done else _sentinel_dns()
    return whois, dns
```

This was verified empirically: the context manager pattern produces 2,001ms wall time; the persistent pool pattern produces 501ms wall time for a 1,500ms timeout with a 2,000ms WHOIS call.

### 6.2 Full extractor.py concurrency design

```
Request arrives at Flask (worker thread W1)
│
├── url_lexical.extract(url)          [W1, sync, ~0ms]
│
├── _POOL.submit(whois.extract)  ───► [Pool thread P1, async]
├── _POOL.submit(dns.extract)    ───► [Pool thread P2, async]
│
├── wait([fw, fd], timeout=1.5)       [W1 blocks here, not a spin-wait]
│   ├── P2 finishes at ~80ms  ──────► result collected
│   ├── P1 finishes at ~350ms ──────► result collected
│   └── both done before 1.5s → proceed
│
├── assemble(t1_dict, t2_dict, t3_dict) → np.ndarray [W1, ~0.1ms]
│
└── registry.production.predict_proba(X) [W1, ~6ms RF]
```

### 6.3 Timeout fallback behaviour

When `wait()` returns with a future in `not_done`:

1. Call `_sentinel_whois()` or `_sentinel_dns()` — returns a dict with all Tier 2/3 feature keys set to `-1.0` (not `NaN` — the `SimpleImputer` inside the Pipeline replaces `-1` with the training-set median for that feature).
2. Set `whois_available: false` or `dns_available: false` in the response metadata.
3. The pipeline's `SimpleImputer` then replaces the `-1` sentinels with the median value computed from the training set. This is the same strategy used for genuinely missing WHOIS data in the training corpus, so the model degrades gracefully rather than crashing.
4. Do **not** raise an error or return a 503 — a URL-only prediction is better than no prediction.

### 6.4 Flask worker model

Use `gunicorn` with `--workers 2 --threads 4` on Azure free-tier (0.5 vCPU):

```
gunicorn app:create_app() --workers 2 --threads 4 --worker-class gthread
```

- 2 workers × 4 threads = 8 concurrent requests
- Each request holds one Flask thread while the `wait()` blocks (non-CPU-bound blocking is fine with threads; would need `asyncio`/`gevent` to do better, which adds complexity without meaningful benefit at this scale)
- Each worker loads the model registry independently — ~275MB × 2 workers = ~550MB total, within the 1GB limit

---

## 7. Technology choices with justification

| Component | Choice | Justification | Rejected alternative |
|---|---|---|---|
| **Web framework** | Flask 3.0 | Rahul has production Flask experience (SQLAlchemy, Redis); REST API is the defined output contract; Blueprint architecture matches module structure | Streamlit — no REST API, harder to test programmatically, DEC-001 resolved |
| **ML library** | scikit-learn 1.5 | All 4 classifiers (DT, RF, LR, SVM) in one library; Pipeline API serialises scaler+imputer+model as one unit; stable joblib serialisation | PyTorch/XGBoost — out of scope per DEC-002; XGBoost noted as future work |
| **Serialisation** | joblib | scikit-learn's native serialiser; handles numpy arrays efficiently; produces compact `.joblib` files (not pickle — joblib uses memory-mapped arrays for large objects) | pickle — less efficient for numpy; json/ONNX — adds complexity without benefit at this scale |
| **Concurrency** | `concurrent.futures.ThreadPoolExecutor` | WHOIS + DNS calls are I/O-bound blocking operations; threads release the GIL during socket I/O; persistent pool eliminates per-request overhead | asyncio — would require async WHOIS/DNS clients (`aiodns` works, but `python-whois` is sync-only, requiring `loop.run_in_executor` anyway — equivalent complexity) |
| **Feature extraction** | tldextract | Handles TLD edge cases correctly (`.co.uk`, `.com.au`); does not make network calls by default; maintained library | urlparse alone — fails on multi-part TLDs; manual regex — maintenance burden |
| **Domain parsing** | python-whois | Most mature WHOIS library; handles response variation across registrars | whoisit — newer RDAP-based; less battle-tested; RDAP not universal yet |
| **DNS lookups** | dnspython | Full DNS client; gives raw TTL values (not just existence); handles NXDOMAIN vs NoNameservers distinction | socket.gethostbyname — no TTL; no MX queries |
| **Request validation** | marshmallow | Declarative schema; clean error messages; separates validation from business logic | Manual validation in route — untestable; pydantic — heavier dependency for this use case |
| **Configuration** | YAML + dataclass | Human-readable; version-controlled; all thresholds in one place | Environment variables alone — no structure, hard to review; hardcoded values — breaks reproducibility |
| **Containerisation** | Docker + Azure Container Apps | Azure free-tier gives 0.5 vCPU / 1GB RAM / 180,000 vCPU-seconds/month; Docker ensures environment parity between dev (macOS M1) and production (Linux x86) | Direct Heroku/Railway deploy — less control over environment; no Docker discipline |
| **Reproducibility** | `random_state=42` everywhere + pinned requirements + `data/processed/` version hashing | Every training run is fully deterministic; any examiner can reproduce results from source | Unpinned dependencies — scikit-learn minor versions change default hyperparameter handling |
| **Testing** | pytest + coverage | Standard; integrates with GitHub Actions; `conftest.py` fixtures allow mocking WHOIS/DNS without network calls | unittest — more verbose; no coverage integration |

**One important note on `n_jobs` for RF**: Set `n_jobs=1` in the production model (not `-1`). On Azure free-tier with 0.5 vCPU, `n_jobs=-1` spawns parallel processes that immediately compete for the same half-vCPU and produce higher latency than single-threaded inference. This was not benchmarked above but is a known Azure Container Apps gotcha.

---

## 8. The three highest-risk architectural decisions

### Risk 1 — Persistent thread pool and Flask worker interactions (HIGH)

**The risk:** The persistent `_POOL = ThreadPoolExecutor(max_workers=4)` in `extractor.py` is created at module import time. With `gunicorn --workers 2`, each worker process gets its own pool instance (processes don't share memory). But if you use `gunicorn --workers 1 --threads 8` (a common "easier" configuration), all threads share one pool — and if 8 requests arrive simultaneously, each submitting 2 futures, the pool has 16 pending I/O futures competing for 4 threads. The remaining 12 futures queue behind them, and effective latency spikes from 350ms to 350ms × 4 batches = 1,400ms.

**The trigger:** This only manifests under concurrent load. In solo demo use it is invisible.

**Mitigation:** Set `max_workers` to `2 × gunicorn_threads` (so 4 workers × 2 = 8 for a `--threads 4` config). Document the relationship between gunicorn worker config and pool size in `settings.yaml`. Add a load test in `tests/integration/test_latency.py` that fires 10 concurrent requests and asserts p99 < 2,000ms.

---

### Risk 2 — joblib version mismatch between training and serving environments (HIGH)

**The risk:** `model.joblib` is produced during training (Weeks 7–9) on your MacBook M1 (macOS, ARM64). The production container runs Linux x86_64. joblib serialisation is not architecture-neutral for all object types — in particular, models that were trained with `n_jobs=-1` may embed platform-specific process metadata. Additionally, if scikit-learn is upgraded between training and the Docker build (e.g. 1.4 → 1.5), hyperparameter defaults can shift and the loaded model may behave differently.

**The trigger:** You will not see this until you run the container for the first time. If the warmup check in `registry.load_all()` is not implemented, you won't see it until the first real prediction in production.

**Mitigation:**
1. Train the final production model **inside Docker**, not on the MacBook directly. Add a `Makefile` target: `make train` that runs `docker run argus python training/pipeline.py`. This ensures training and serving environments are identical.
2. Pin scikit-learn and joblib versions identically in `requirements.txt` and the training environment.
3. Implement `registry.warmup()` — runs `predict_proba(np.zeros((1, 48)))` at startup. Any version mismatch will raise immediately rather than on a real request.
4. Store the scikit-learn version and Python version in the model metadata file alongside the `.joblib`:
   ```json
   // models/random_forest/metadata.json
   {"sklearn_version": "1.5.0", "python_version": "3.10.12", "trained_at": "2026-09-15", "f1": 0.974}
   ```

---

### Risk 3 — WHOIS rate limiting in production silently degrades model quality (MEDIUM-HIGH)

**The risk:** `python-whois` makes live WHOIS queries. Major WHOIS servers (Verisign for `.com`, RIPE for European TLDs) enforce rate limits of approximately 1 request per second per IP. In a demo context with one user this is invisible. But in the thesis integration testing phase (Week 14), if you run automated tests with 50–100 URLs, you will hit the rate limit within the first 60 seconds. The server returns an empty response or a rate-limit error message. `python-whois` will either raise an exception (caught, produces sentinel) or — more dangerously — return a partial parse of the rate-limit error message as a domain object with a creation_date of `None`. This causes `domain_age_days` to be set to `-1` (sentinel) for every URL after the rate limit, making the model behave as if WHOIS is unavailable for all of them.

**The trigger:** Any automated test run of more than ~30 URLs with WHOIS enabled. The failure is silent — latency stays normal, but `whois_available` flips to `false` for all subsequent requests.

**Mitigation:**
1. Add a **per-domain WHOIS cache** keyed by `registered_domain` with a 6-hour TTL. Implement as a simple `dict` with a timestamp check (for a single-process deployment, `functools.lru_cache` works; for multi-worker, use a module-level `threading.Lock`-protected dict). This also improves latency for repeated domain submissions.
2. In integration tests, **mock WHOIS** via `unittest.mock.patch('whois_features.whois.whois', return_value=MockWhoisResult(...))`. The `conftest.py` fixture should provide this by default so tests never make real network calls.
3. In the thesis, explicitly acknowledge WHOIS rate limiting as an operational constraint (Chapter 4, Section 4.x) — it demonstrates real-world engineering awareness, which examiners value.

---

## 9. Appendix: key architectural decisions to log in DECISIONS.md

Add these four entries to `DECISIONS.md` before beginning implementation:

**DEC-007 — Web Framework** (resolves DEC-001)
- Decision: Flask
- Reason: REST API is the defined output contract; Rahul has production Flask experience; Blueprint architecture aligns with module structure; testable via Flask test client without a live server.

**DEC-008 — Concurrency pattern**
- Decision: Persistent `ThreadPoolExecutor` at module level; `wait()` with explicit timeout; no context manager
- Reason: Context manager `__exit__` blocks until all futures complete regardless of timeout, defeating the 1,500ms latency budget. Empirically verified: context manager = 2,001ms; persistent pool = 501ms for same timeout.

**DEC-009 — Model serialisation scope**
- Decision: Serialise full scikit-learn Pipeline (Imputer + Scaler + Classifier), not classifier alone
- Reason: Scaler statistics must be identical between training and inference; serialising them inside the Pipeline eliminates environment-specific mismatch risk.

**DEC-010 — RF n_estimators cap**
- Decision: Cap `n_estimators=100` for production deployment model
- Reason: n=200 doubles serialised size (52MB) and inference time (12.7ms) with negligible F1 gain on an 11k training set. n=100 at 6.3ms inference satisfies the <200ms p99 budget with margin.
