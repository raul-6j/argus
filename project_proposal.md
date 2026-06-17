# Major Project 21CSA699A Proposal (Individual Mode)

## Title
# ARGUS – Adaptive Real-time Guardian for URL Screening
### A Machine Learning-Based Real-Time Phishing Website Detection System

**Student Name:** Rahul Raj M A  
**Roll No.:** AA.SC.P2MCA24070062

---

# Abstract

In an era characterized by the rapid growth of internet-based services, phishing attacks have become one of the most widespread and financially damaging forms of cybercrime. Attackers create fraudulent websites that imitate legitimate platforms such as banking portals, e-commerce websites, and government services in order to steal sensitive user credentials, financial information, and personal data. Traditional blacklist-based detection methods are mostly reactive and are unable to effectively handle the speed and sophistication of modern phishing attacks.

This project proposes **ARGUS (Adaptive Real-time Guardian for URL Screening)**, an intelligent machine learning-based system designed for the proactive detection of phishing websites through automated analysis of URL and webpage features. The name ARGUS is inspired by *Argus Panoptes* from Greek mythology, the hundred-eyed giant known for constant vigilance and watchfulness. Similarly, the proposed system continuously analyzes websites in real time to identify malicious behavior with high accuracy.

ARGUS extracts a wide range of structural, syntactic, and behavioral features from URLs and webpage content. These features include:

- Domain age indicators
- Usage of IP addresses in URLs
- HTTPS token irregularities
- Subdomain depth
- Frequency of special characters
- Anchor tag ratios
- Redirection patterns

The extracted features are processed using supervised machine learning algorithms such as:

- Decision Tree
- Random Forest
- Logistic Regression
- Support Vector Machine (SVM)

The system is trained and tested using publicly available benchmark datasets obtained from the UCI Machine Learning Repository and Kaggle. Model performance is evaluated using standard metrics including:

- Accuracy
- Precision
- Recall
- F1-Score
- ROC-AUC Score

The best-performing model is integrated into a lightweight Flask or Streamlit web application, allowing users to submit URLs and instantly receive a classification result indicating whether the website is phishing or legitimate, along with confidence scores.

ARGUS aims to contribute to the field of cybersecurity by providing an efficient, scalable, and real-time phishing detection solution capable of improving online safety for users and organizations.

---

# Assumptions / Declarations

- The project is undertaken in individual mode as per the regulations stipulated under Major Project 21CSA699A.
- The datasets employed (UCI Phishing Websites Dataset and Kaggle Phishing Websites Dataset) are publicly available and are used strictly for academic and research purposes.
- No proprietary or confidential industry data is involved. The project does not require industry integration.
- All features are extracted from URL structure and publicly accessible webpage content. No private user data is collected, processed, or stored.
- The model is intended as a decision-support tool and is not a replacement for certified cybersecurity infrastructure.
- The web interface is designed for demonstration and evaluation purposes and will be hosted locally or on a free-tier cloud platform (e.g., Heroku, Streamlit Community Cloud).
- All libraries and frameworks used are open-source and freely available under their respective licenses.

---

# Main Objectives

- Design and develop ARGUS, a real-time machine learning-based phishing website detection system capable of classifying URLs as phishing or legitimate through a user-friendly web interface.
- Study and analyze existing phishing detection techniques and machine learning approaches.
- Collect, preprocess, and validate phishing datasets from sources such as the UCI Repository and Kaggle.
- Extract and engineer URL-based, domain-based, and webpage-based features for effective phishing detection.
- Train and evaluate machine learning models including Decision Tree, Random Forest, Logistic Regression, and SVM using standard performance metrics.
- Implement real-time feature extraction using tools such as BeautifulSoup and tldextract.
- Develop and deploy a Flask or Streamlit-based web application for real-time phishing URL analysis and prediction.

---

# Main Deliverables

- Preprocessed and feature-engineered phishing dataset ready for model training.
- Trained and serialized ML models with documented performance metrics and comparative analysis.
- Functional real-time ARGUS web application (Flask/Streamlit) with live URL classification capability.
- Comprehensive technical report including system architecture, methodology, experimental results, and conclusions.
- Project demonstration video and academic presentation slides.

---

# Timeline and Milestones

| Milestone | Description | Timeline |
|------------|-------------|------------|
| Literature Review & Dataset Acquisition | Study prior work on phishing detection; download and validate UCI and Kaggle phishing datasets | Week 1-2 |
| Data Preprocessing & EDA | Clean data, handle missing values, encode categorical features, perform correlation analysis and feature importance ranking | Week 3-4 |
| Feature Engineering | Extract and engineer 25+ URL, domain, and content-based features; normalize and split dataset | Week 5-6 |
| Model Development & Training | Train and tune Decision Tree, Random Forest, Logistic Regression, and SVM classifiers; implement cross-validation | Week 7-9 |
| Model Evaluation & Comparison | Compute Accuracy, Precision, Recall, F1-Score, ROC-AUC for all models; select best-performing model | Week 10 |
| Web Interface Development | Develop Flask/Streamlit UI for real-time URL input and prediction display; integrate BeautifulSoup for live feature extraction | Week 11-13 |
| System Integration & Testing | End-to-end testing with live URLs, adversarial phishing samples, and edge cases; performance benchmarking | Week 14 |
| Documentation & Final Submission | Prepare technical report, user guide, demo video, and project presentation | Week 15-17 |

---

# Tools to be Used

| Software / Hardware Tool | Purpose |
|--------------------------|---------|
| Python 3.10+ | Primary programming language for data processing, ML model development, and web backend |
| Pandas & NumPy | Dataset loading, cleaning, feature transformation, and numerical operations |
| Scikit-learn | ML model implementation (Decision Tree, Random Forest, Logistic Regression, SVM) |
| Matplotlib & Seaborn | Exploratory data analysis visualizations, confusion matrices, ROC curves, feature importance plots |
| Flask / Streamlit | Web framework for real-time phishing detection interface |
| BeautifulSoup & tldextract | Live webpage scraping and domain-level feature extraction |
| Jupyter Notebook / VS Code | Development and experimentation environment |
| Git & GitHub | Version control and project management |
| UCI Repository Dataset | Phishing Websites Dataset (11,055 instances, 30 URL/domain features) |
| Kaggle Phishing Dataset | Supplementary labeled dataset for improved generalization |
| Standard Laptop / PC | Apple MacBook (M1 Chip), 8GB+ RAM, macOS |

---

# Learning Involved

| Topic | Description |
|---------|-------------|
| Machine Learning Fundamentals | Decision Tree, Random Forest, Logistic Regression, SVM theory, tuning, and evaluation |
| Feature Engineering for URLs | Extraction of URL, domain, and behavioral features |
| Cybersecurity & Phishing Taxonomy | Understanding phishing attacks and malicious URL characteristics |
| Model Evaluation Metrics | Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix |
| Web Development (Flask/Streamlit) | Building interactive ML-powered web applications |
| Data Preprocessing & EDA | Cleaning, normalization, encoding, missing-value handling, correlation analysis |
| Web Scraping (BeautifulSoup) | Real-time extraction of webpage attributes |
| Software Engineering & Git | Version control, project structuring, modular development, and documentation |

---

## Date
**10/05/2026**

## Student Name and Signature

**Rahul Raj M A**