# THESIS_OUTLINE.md — ARGUS Report Structure
Course: 21CSA699A | Author: Rahul Raj M A | Citation: IEEE | Style: Third person, past tense for work done, present tense for established facts
Total target: 10,000–15,000 words (body text only)

---

## Chapter Map

| Chapter | Title | Words | Write When | Status |
|---|---|---|---|---|
| — | Abstract | 250–300 | Week 15 (revise proposal draft) | ☐ |
| 1 | Introduction | 1,500–2,000 | Week 15 | ☐ |
| 2 | Literature Review | 2,500–3,000 | Week 15 | ☐ |
| 3 | Methodology | 3,000–4,000 | Week 16 | ☐ |
| 4 | Implementation | 1,500–2,000 | Week 16 | ☐ |
| 5 | Results and Discussion | 2,000–2,500 | Week 16 | ☐ |
| 6 | Conclusion and Future Work | 800–1,000 | Week 17 | ☐ |
| — | References | — | Ongoing from Week 1 | ☐ |
| — | Appendices | — | Week 17 | ☐ |

---

## Abstract
Revise from proposal after results are finalised. Must include: problem (1 sentence) → approach (2 sentences) → method summary (2 sentences) → key result (1 sentence) → contribution (1 sentence). No citations.

---

## Chapter 1 — Introduction
**Must argue:**
1. Scale of phishing damage — cite APWG, FBI IC3 (2023–2025 stats)
2. Why blacklists fail — reactive, bypass by URL rotation
3. Why ML is better — generalisable, proactive, pattern-based
4. Research gap — most systems are either research-only (no deployment) or deployed (no rigorous comparison). ARGUS does both.
5. Three research contributions — feature pipeline (25+ features), 4-classifier comparison, deployed real-time web app
6. Scope boundaries — briefly
7. Chapter roadmap — one sentence per chapter

Minimum 4 citations. No implementation detail.

---

## Chapter 2 — Literature Review
**Structure:**

| Section | Topic | Words | Key Requirement |
|---|---|---|---|
| 2.1 | Phishing overview + taxonomy | 300 | Define phishing types; cite APWG |
| 2.2 | Traditional detection (blacklists, heuristics) | 400 | Limitations only — why ML is needed |
| 2.3 | ML-based detection approaches | 800 | Cover DT/RF, SVM, LR, deep learning — one paragraph each with 1–2 papers |
| 2.4 | Feature engineering for URL classification | 500 | URL lexical, domain, HTML features — cite Mohammad (2012), Sahingoz (2019) |
| 2.5 | Datasets in prior work | 300 | UCI benchmark history; PhishTank |
| 2.6 | Research gap + ARGUS positioning | 400 | Synthesise gap; state exactly how ARGUS addresses it |

Minimum 15 peer-reviewed citations (IEEE Xplore, ACM, Springer). Range: 2008–2025.

---

## Chapter 3 — Methodology
**Structure:**

| Section | Topic | Words | Key Requirement |
|---|---|---|---|
| 3.1 | System architecture | 400 | Component diagram description; training path vs. inference path |
| 3.2 | Dataset selection + preparation | 600 | UCI + Kaggle; label normalisation; suspicious class handling; split strategy; leakage prevention |
| 3.3 | Feature engineering | 800 | Three feature categories; extraction method per feature; cite literature support |
| 3.4 | ML models + training | 600 | Pipeline design (Imputer→Scaler→Model); each classifier with key hyperparams; 5-fold CV |
| 3.5 | Evaluation framework | 400 | All 5 metrics with formulas (LaTeX); why F1 > accuracy for imbalanced data |
| 3.6 | Web application design | 400 | Flask/Streamlit; user workflow; real-time inference path |

---

## Chapter 4 — Implementation
**Focus:** What was built and key engineering decisions. Not a code walkthrough.
- Dev environment + version control approach
- Data pipeline: label conversion challenge, Pipeline structure, reproducibility enforcement
- Feature extraction: tldextract for domain parsing, BeautifulSoup for HTML, timeout handling
- Model training: training time per model (approximate), serialisation with joblib
- Web app: framework chosen (document DEC-001 resolution here), model load at startup, live feature extraction trigger

---

## Chapter 5 — Results and Discussion
- CV results table → consistency and variance across folds
- Test set metrics table → best model, margin over second-best
- Confusion matrices → false negative rate emphasis (missed phishing = high risk)
- Feature importance → top 10 features; what they reveal about phishing behaviour
- Latency benchmark → is best model real-time compatible?
- Comparison with published benchmarks (Mohammad, Sahingoz, Korkmaz)
- Limitations: dataset age, no adversarial testing, dead URL problem for HTML features

---

## Chapter 6 — Conclusion and Future Work
- Restate problem + ARGUS response (2–3 sentences)
- Whether research questions from Chapter 1 were answered
- Significance of contribution
- **Future work (minimum 4):**
  - Retrain on PhishTank + Tranco 2024–2025 data
  - Add XGBoost/LightGBM to comparison
  - Adversarial robustness testing
  - Browser extension deployment
  - SHAP explainability in web UI
  - Azure Container Apps deployment (AZ-500 alignment)

---

## References
- Minimum 20, target 25–30
- Format: IEEE numbered [1], [2], …
- Maintain references.bib in repo; add each paper immediately when read
- Required: 3–4 phishing statistics, 8–10 ML detection papers, 3–4 feature engineering, 2–3 dataset, 2–3 general ML

## Appendices
A — Full feature list | B — All confusion matrices | C — ROC curves | D — Hyperparameter tuning results | E — Web app screenshots | F — Setup and run instructions

---

## Writing Rules
- Tense: present for facts ("Random Forest is…"), past for work done ("features were extracted…")
- Person: third person throughout — never "I"
- Equations: LaTeX notation, numbered sequentially
- Figures/tables: numbered, captioned, explicitly referenced in text
- Abbreviations: define on first use ("Support Vector Machine (SVM)") then abbreviate
- Every factual/statistical claim needs a citation or experimental evidence
