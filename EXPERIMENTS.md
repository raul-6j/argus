# EXPERIMENTS.md — ARGUS Model Experiments
Populate during M5 (Week 10). Never edit historical results — append only.
Primary selection metric: F1-Score. Tie-break: ROC-AUC. Test set touched once only.

---

## Hyperparameter Configuration

| Model | Key Parameters | Value |
|---|---|---|
| Logistic Regression | C, solver, max_iter, class_weight | *[fill after tuning]* |
| Decision Tree | max_depth, min_samples_split, criterion, class_weight | *[fill]* |
| Random Forest | n_estimators, max_depth, max_features, class_weight, n_jobs | *[fill]* |
| SVM | kernel, C, gamma, class_weight, probability | *[fill]* |

All models: `random_state=42`. All wrapped in scikit-learn Pipeline (Imputer → Scaler → Model).

---

## Cross-Validation Results (5-Fold Stratified, Training Set)

| Model | CV Accuracy | CV Precision | CV Recall | CV F1 | CV ROC-AUC |
|---|---|---|---|---|---|
| Logistic Regression | *[fill ± std]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |
| Decision Tree | *[fill ± std]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |
| Random Forest | *[fill ± std]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |
| SVM | *[fill ± std]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |

---

## Final Test Set Results (Held-Out — Run Once)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | Inference (ms) |
|---|---|---|---|---|---|---|
| Logistic Regression | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |
| Decision Tree | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |
| Random Forest | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |
| SVM | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]* |

**Selected model:** *[fill]* | **Reason:** *[fill — log in DECISIONS.md as DEC-00X]*

---

## Confusion Matrices — Test Set

| Model | TP | FP | FN | TN | FN Rate (missed phishing) |
|---|---|---|---|---|---|
| Logistic Regression | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]%* |
| Decision Tree | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]%* |
| Random Forest | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]%* |
| SVM | *[fill]* | *[fill]* | *[fill]* | *[fill]* | *[fill]%* |

---

## Feature Importance — Best Model (Top 10)

| Rank | Feature | Score | Category |
|---|---|---|---|
| 1–10 | *[fill after best model selected]* | | |

---

## Comparison with Published Benchmarks

| Paper | Algorithm | Dataset | Accuracy | F1 | vs. ARGUS |
|---|---|---|---|---|---|
| Mohammad et al. (2014) | Multiple | UCI | ~96.3% | — | *[fill]* |
| Sahingoz et al. (2019) | Random Forest | Mixed | 97.98% | *[fill]* | *[fill]* |
| Korkmaz et al. (2020) | Random Forest | UCI+custom | 97.1% | *[fill]* | *[fill]* |

---

## Saved Artefacts

| Artefact | Path |
|---|---|
| All trained models | models/{model_name}/model.joblib |
| **Production model** | models/production/model.joblib |
| Metrics JSON | reports/model_comparison.json |
| ROC curves | reports/roc_curves.png |
| Feature importance | reports/feature_importance.png |
| Confusion matrices | reports/confusion_matrices.png |
