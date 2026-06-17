# DECISIONS.md — ARGUS Decision Log
Append every architectural/modelling decision here. Never delete entries.
Format: ID | Title | Options | **Choice** | Reason | Date

---

## Pending

### DEC-001 — Web Framework
- Options: Flask, Streamlit
- Flask: full routing control, REST API extensible, aligns with Rahul's existing skills
- Streamlit: faster to prototype, no HTML/CSS, purpose-built for ML demos
- **Decision:** TBD — resolve before Week 11
- Consequences: affects M6 scope and deployment approach

---

## Accepted

### DEC-002 — Classifier Set
- Options: DT + RF + LR + SVM (chosen) | add XGBoost/LightGBM | reduce to 2
- **Decision:** Decision Tree, Random Forest, Logistic Regression, SVM
- Reason: Covers interpretable (DT, LR) + ensemble (RF) + kernel-based (SVM); all in scikit-learn; well-benchmarked in phishing detection literature; academic scope permits 4-model comparison
- Date: 10 May 2026

### DEC-003 — Datasets
- Options: UCI only | PhishTank raw feed | Kaggle only | UCI + Kaggle
- **Decision:** UCI (primary) + Kaggle (supplementary)
- Reason: UCI is the standard academic benchmark — enables direct comparison with prior literature. Kaggle supplements class balance. Neither requires live crawling to build training data.
- Date: 10 May 2026

### DEC-004 — Primary Evaluation Metric
- Options: Accuracy only | F1 primary | ROC-AUC primary | all five equally
- **Decision:** Report all five (Accuracy, Precision, Recall, F1, ROC-AUC); F1 is primary selection criterion; ROC-AUC is tie-break
- Reason: Imbalanced classes make accuracy misleading. F1 balances precision/recall; false negatives (missed phishing) are more costly than false positives.
- Date: 10 May 2026

### DEC-005 — Deployment Platform
- Options: Local only | Heroku | Streamlit Cloud | Azure Container Apps
- **Decision:** Local deployment (primary); Streamlit Cloud or Heroku as optional live demo
- Reason: Academic evaluation requires a working demo, not production uptime. Azure is a stretch goal aligned with AZ-500 roadmap.
- Date: 10 May 2026

### DEC-006 — Cross-Validation Strategy
- Options: Simple 70/30 split | 5-fold CV | Stratified 5-fold CV | Nested CV
- **Decision:** Stratified 5-fold CV on training set; final evaluation on held-out 15% test set (touched once only)
- Reason: Stratified folds preserve class distribution. Held-out test set gives unbiased final metrics for thesis. Standard in phishing detection literature.
- Date: 10 May 2026

---

## Template
```
### DEC-00X — [Title]
- Options: [A], [B], [C]
- **Decision:** [Choice]
- Reason: [Primary reason]
- Date: [DD Month YYYY]
- Supersedes / Superseded by: [if applicable]
```
