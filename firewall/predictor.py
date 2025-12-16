# ml/predictor.py
import os
import joblib
try:
    import numpy as np
    from scipy.sparse import hstack, csr_matrix
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: numpy/scipy not available. ML features will not work.")

try:
    from feature_builder import extract_urls, url_numeric_features, text_numeric_features, metadata_numeric_features
except ImportError as e:
    print(f"Warning: Could not import feature_builder: {e}")
    # Define dummy functions or raise error
    raise

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_artifacts')

class MLScorer:
    def __init__(self, config):
        self.config = config
        self.model = None
        self.tfidf = None
        self.scaler = None
        self._load_artifacts()
    
    def _load_artifacts(self):
        model_path = os.path.join(MODEL_DIR, 'rf_model.joblib')
        tfidf_path = os.path.join(MODEL_DIR, 'tfidf.joblib')
        scaler_path = os.path.join(MODEL_DIR, 'scaler.joblib')
        
        if all(os.path.exists(p) for p in [model_path, tfidf_path, scaler_path]):
            self.model = joblib.load(model_path)
            self.tfidf = joblib.load(tfidf_path)
            self.scaler = joblib.load(scaler_path)
    
    def available(self):
        return self.model is not None and self.tfidf is not None and self.scaler is not None
    
    def predict_score(self, text, urls, metadata):
        if not self.available():
            return 0.0
        
        # Build features
        urls_list = urls if urls else extract_urls(text)
        url_feats = url_numeric_features(
            urls_list,
            self.config['url_analysis']['suspicious_tlds'],
            self.config['url_analysis']['url_shorteners'],
            []
        ).reshape(1, -1)
        
        txt_feats = text_numeric_features(text).reshape(1, -1)
        meta_feats = metadata_numeric_features(metadata).reshape(1, -1)
        
        # Transform text with TF-IDF
        X_text = self.tfidf.transform([text])
        
        # Scale numeric features
        numeric = np.hstack([url_feats, txt_feats, meta_feats])
        numeric_scaled = self.scaler.transform(numeric)
        X_numeric_sparse = csr_matrix(numeric_scaled)
        
        # Combine features
        X = hstack([X_text, X_numeric_sparse])
        
        # Predict probability
        proba = self.model.predict_proba(X)[0, 1]
        return round(proba * 100.0, 2)