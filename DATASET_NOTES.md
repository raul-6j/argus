# DATASET_NOTES.md — ARGUS Dataset Notes
Populate during M2 (Weeks 3–4). This file is cited directly in the thesis Methodology chapter.

---

## Datasets

### UCI Phishing Websites Dataset (Primary)
| Attribute | Detail |
|---|---|
| Source | https://archive.ics.uci.edu/dataset/327 |
| Citation | Mohammad, Thabtah, McCluskey (2012), Univ. of Huddersfield |
| Instances | 11,055 |
| Features | 30 pre-engineered + 1 label (Result) |
| Label encoding | −1 = phishing, 0 = suspicious, 1 = legitimate |
| Label conversion | Map: −1 → 1 (phishing), 1 → 0 (legit); suspicious class — see open questions |
| Format | ARFF + CSV |
| Academic use | Publicly available; unrestricted academic use |
| Download date | *[fill]* |

**Why:** Standard benchmark — enables direct comparison with prior literature. Pre-engineered features reduce training pipeline complexity.
**Limitation:** Dataset is from 2012–2014. HTTPS is now common on phishing sites — weakens `has_https` as a signal.

### Kaggle Phishing Dataset (Supplementary)
| Attribute | Detail |
|---|---|
| Source | *[fill after selecting dataset on Kaggle]* |
| Instances | *[fill]* |
| Features | *[fill]* |
| Label field | *[fill]* |
| Licence | *[verify and note on download]* |
| Download date | *[fill]* |

**Why:** Supplements UCI for better class balance and more recent samples.

---

## Class Distribution (Fill after download)

| Dataset | Phishing | Legitimate | Suspicious | Total |
|---|---|---|---|---|
| UCI | *[fill]* | *[fill]* | *[fill]* | 11,055 |
| Kaggle | *[fill]* | *[fill]* | — | *[fill]* |
| **Combined** | *[fill]* | *[fill]* | — | *[fill]* |

Imbalance ratio: *[fill]* | Handling strategy: *[fill — e.g., class_weight='balanced' / SMOTE / none]*

**Open question:** UCI suspicious class (label=0) — drop / merge with phishing / keep as third class? → Decide in Week 3, log in DECISIONS.md.

---

## Preprocessing Steps (Fill after Week 3–4)

| Step | Action | Outcome |
|---|---|---|
| 1. Load + validate | Load both CSVs, check row counts + column names | *[fill]* |
| 2. Label normalisation | UCI: −1→1, 1→0; handle suspicious | *[fill]* |
| 3. Duplicate removal | Drop exact duplicate rows | *[N removed]* |
| 4. Missing value audit | Count nulls per column | *[fill]* |
| 5. Imputation | Strategy per column (median/mode/drop) | *[fill]* |
| 6. Merge datasets | Concatenate UCI + Kaggle, align schemas | *[total rows]* |
| 7. Feature scaling | StandardScaler — fit on train ONLY via Pipeline | *[fill]* |
| 8. Split | Stratified 70% train / 15% val / 15% test, random_state=42 | *[row counts]* |
| 9. Serialise | Save to data/processed/ as parquet or CSV | *[file paths]* |

**Critical:** Scaler is fit on training set only. Applied (transform-only) to val/test. Enforced via scikit-learn Pipeline. Fitting on full dataset before split = data leakage.

---

## EDA Findings (Fill after Week 3–4)
- Most discriminative features (preliminary): *[fill after initial RF importance run]*
- Highly correlated feature pairs (candidates for removal): *[fill]*
- Features with >20% null rate: *[fill]*
- Features dropped: *[fill + reason]*
- Class imbalance severity: *[fill — mild <2:1 / moderate 2–5:1 / severe >5:1]*

---

## Data Split Summary (Fill after Week 3–4)
| Split | Rows | Phishing | Legitimate |
|---|---|---|---|
| Train (70%) | *[fill]* | *[fill]* | *[fill]* |
| Validation (15%) | *[fill]* | *[fill]* | *[fill]* |
| Test (15%) | *[fill]* | *[fill]* | *[fill]* |

---

## BibTeX (UCI)
```
@misc{uci_phishing_2012,
  author = {Mohammad, R.M. and Thabtah, F. and McCluskey, T.L.},
  title  = {Phishing Websites},
  year   = {2012},
  howpublished = {UCI Machine Learning Repository},
  note   = {https://archive.ics.uci.edu/dataset/327}
}
```
Kaggle citation: *[fill after dataset is confirmed]*
