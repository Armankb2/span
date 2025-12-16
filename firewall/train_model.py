# ml/train_model.py
import os
import argparse
import json
import yaml
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, roc_auc_score, f1_score
from scipy.sparse import hstack, csr_matrix
from feature_builder import extract_urls, url_numeric_features, text_numeric_features, metadata_numeric_features

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_artifacts')
os.makedirs(MODEL_DIR, exist_ok=True)

def load_dataset_from_csv(path):
    df = pd.read_csv(path)
    def parse_urls(u):
        if pd.isna(u): return []
        try:
            return json.loads(u)
        except:
            return [x.strip() for x in str(u).split('|') if x.strip()]
    df['parsed_urls'] = df['urls'].apply(parse_urls)
    def parse_metadata(m):
        if pd.isna(m): return {}
        try:
            return json.loads(m)
        except:
            return {}
    df['parsed_metadata'] = df['metadata'].apply(parse_metadata)
    return df

def build_feature_matrix(df, config):
    texts = df['text'].fillna('').astype(str).tolist()
    tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1,2), stop_words='english')
    X_text = tfidf.fit_transform(texts)

    url_feats = np.vstack([
        url_numeric_features(row['parsed_urls'], config['url_analysis']['suspicious_tlds'], config['url_analysis']['url_shorteners'], [])
        for _, row in df.iterrows()
    ])
    txt_feats = np.vstack([text_numeric_features(t) for t in texts])
    meta_feats = np.vstack([metadata_numeric_features(row['parsed_metadata']) for _, row in df.iterrows()])

    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    numeric = np.hstack([url_feats, txt_feats, meta_feats])
    numeric = scaler.fit_transform(numeric)

    X_numeric_sparse = csr_matrix(numeric)
    X = hstack([X_text, X_numeric_sparse])
    return X, tfidf, scaler

def train(args):
    # load config
    with open(args.config, 'r') as f:
        cfg = yaml.safe_load(f)

    df = load_dataset_from_csv(args.data)
    print("Loaded dataset:", len(df))
    X, tfidf, scaler = build_feature_matrix(df, cfg)
    y = df['label'].astype(int).values

    # Use stratify only if we have enough samples of each class
    try:
        X_train, X_val, y_train, y_val = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
    except ValueError:
        # If stratify fails (not enough samples per class), split without stratify
        print("Warning: Could not stratify split, using random split instead")
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_val)
    y_proba = clf.predict_proba(X_val)[:,1]
    print("=== Validation Results ===")
    print(classification_report(y_val, y_pred, digits=4))
    try:
        print("ROC AUC:", roc_auc_score(y_val, y_proba))
    except:
        pass
    print("F1:", f1_score(y_val, y_pred))

    # Save
    joblib.dump(clf, os.path.join(MODEL_DIR, 'rf_model.joblib'))
    joblib.dump(tfidf, os.path.join(MODEL_DIR, 'tfidf.joblib'))
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.joblib'))
    # Save some metadata
    with open(os.path.join(MODEL_DIR, 'model_info.txt'), 'w') as f:
        f.write(f"trained_on: {args.data}\n")
        f.write(f"n_train: {len(df)}\n")
    print("Saved artifacts to", MODEL_DIR)

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--data', required=True, help='Path to CSV (train+val)')
    p.add_argument('--config', default='../config.yaml', help='Path to config YAML')
    args = p.parse_args()
    train(args)