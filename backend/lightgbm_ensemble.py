"""
LightGBM-based ensemble model for combining Text, CNN, and GNN scores
for more accurate phishing detection.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, Tuple
import warnings

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    warnings.warn("LightGBM not available. Install with: pip install lightgbm")

class LightGBMEnsemble:
    """
    LightGBM-based ensemble model for phishing detection.
    Combines Text, CNN, and GNN scores with additional features for better accuracy.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.model_path = model_path or "lightgbm_phishing_model.txt"
        self.feature_names = [
            'text_score', 'cnn_score', 'gnn_score',
            'text_cnn_diff', 'text_gnn_diff', 'cnn_gnn_diff',
            'max_score', 'min_score', 'score_std',
            'has_https', 'domain_length', 'url_length',
            'suspicious_keywords_count', 'domain_age_risk'
        ]
        self.is_trained = False
        
    def create_features(self, text_score: float, cnn_score: float, gnn_score: float, 
                       url: str = "", domain: str = "", additional_features: Dict = None) -> np.ndarray:
        """
        Create feature vector from individual model scores and additional features.
        """
        features = np.zeros(len(self.feature_names))
        
        # Basic model scores
        features[0] = text_score
        features[1] = cnn_score
        features[2] = gnn_score
        
        # Score differences (important for ensemble learning)
        features[3] = abs(text_score - cnn_score)  # text_cnn_diff
        features[4] = abs(text_score - gnn_score)  # text_gnn_diff
        features[5] = abs(cnn_score - gnn_score)   # cnn_gnn_diff
        
        # Score statistics
        scores = [text_score, cnn_score, gnn_score]
        features[6] = max(scores)  # max_score
        features[7] = min(scores)  # min_score
        features[8] = np.std(scores) if len(scores) > 1 else 0.0  # score_std
        
        # URL/Domain features
        features[9] = 1.0 if url and url.startswith('https://') else 0.0  # has_https
        features[10] = len(domain) if domain else 0.0  # domain_length
        features[11] = len(url) if url else 0.0  # url_length
        
        # Suspicious keywords in URL/domain
        suspicious_keywords = ['secure', 'login', 'verify', 'account', 'bank', 'payment', 
                              'crypto', 'wallet', 'support', 'update', 'alert']
        text_to_check = (url + " " + domain).lower()
        features[12] = sum(1 for keyword in suspicious_keywords if keyword in text_to_check)
        
        # Domain age risk (from additional features)
        if additional_features and 'domain_age_days' in additional_features:
            age_days = additional_features.get('domain_age_days', 0)
            if age_days is None or age_days < 30:
                features[13] = 1.0  # High risk for new domains
            elif age_days < 365:
                features[13] = 0.5  # Medium risk
            else:
                features[13] = 0.0  # Low risk for old domains
        else:
            features[13] = 0.5  # Default medium risk if unknown
        
        return features
    
    def train(self, training_data: pd.DataFrame, target_column: str = 'is_phishing'):
        """
        Train the LightGBM model on historical data.
        """
        if not HAS_LIGHTGBM:
            raise ImportError("LightGBM not available. Install with: pip install lightgbm")
        
        # Prepare features
        X = training_data[self.feature_names].values
        y = training_data[target_column].values
        
        # Create LightGBM dataset
        train_data = lgb.Dataset(X, label=y, feature_name=self.feature_names)
        
        # LightGBM parameters optimized for phishing detection
        params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.9,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'verbose': -1,
            'random_state': 42,
            'min_data_in_leaf': 20,
            'min_sum_hessian_in_leaf': 1e-3,
            'lambda_l1': 0.1,
            'lambda_l2': 0.1
        }
        
        # Train the model
        self.model = lgb.train(
            params,
            train_data,
            num_boost_round=100,
            valid_sets=[train_data],
            callbacks=[lgb.early_stopping(10), lgb.log_evaluation(0)]
        )
        
        self.is_trained = True
        
        # Save the model
        self.model.save_model(self.model_path)
        print(f"LightGBM model trained and saved to {self.model_path}")
        
        return self.model
    
    def load_model(self, model_path: Optional[str] = None):
        """
        Load a pre-trained LightGBM model.
        """
        if not HAS_LIGHTGBM:
            raise ImportError("LightGBM not available. Install with: pip install lightgbm")
        
        path = model_path or self.model_path
        if os.path.exists(path):
            self.model = lgb.Booster(model_file=path)
            self.is_trained = True
            print(f"LightGBM model loaded from {path}")
            return True
        return False
    
    def predict(self, text_score: float, cnn_score: float, gnn_score: float,
                url: str = "", domain: str = "", additional_features: Dict = None) -> Dict[str, Any]:
        """
        Predict phishing probability using the trained LightGBM model.
        """
        if not self.is_trained or self.model is None:
            # Fallback to simple ensemble if model not trained
            return self._fallback_prediction(text_score, cnn_score, gnn_score)
        
        # Create features
        features = self.create_features(text_score, cnn_score, gnn_score, url, domain, additional_features)
        features = features.reshape(1, -1)
        
        # Predict
        probability = self.model.predict(features)[0]
        
        # Determine label based on probability
        if probability >= 0.7:
            label = "phish"
        elif probability >= 0.4:
            label = "suspicious"
        else:
            label = "legit"
        
        return {
            "score": float(probability),
            "label": label,
            "probability": float(probability),
            "model_type": "lightgbm_ensemble"
        }
    
    def _fallback_prediction(self, text_score: float, cnn_score: float, gnn_score: float) -> Dict[str, Any]:
        """
        Fallback prediction using weighted ensemble when LightGBM is not available.
        """
        # Weighted ensemble with better calibration
        weights = {"text": 0.5, "cnn": 0.3, "gnn": 0.2}  # Balanced weights with text priority
        
        # Apply domain-specific adjustments
        # If GNN score is very high (>0.8), reduce its weight
        if gnn_score > 0.8:
            weights = {"text": 0.6, "cnn": 0.3, "gnn": 0.1}
        
        weighted_score = (weights["text"] * text_score + 
                         weights["cnn"] * cnn_score + 
                         weights["gnn"] * gnn_score)
        
        # Apply intelligent calibration - much more conservative
        # If all models agree on low risk, be very conservative
        low_risk_count = sum(1 for score in [text_score, cnn_score, gnn_score] if score < 0.2)
        if low_risk_count >= 2:
            weighted_score = weighted_score * 0.2  # Reduce score by 80%
        
        # If any model is very low, reduce overall score
        very_low_count = sum(1 for score in [text_score, cnn_score, gnn_score] if score < 0.1)
        if very_low_count >= 1:
            weighted_score = weighted_score * 0.3  # Reduce score by 70%
        
        # Use a much gentler sigmoid transformation
        calibrated_score = 1 / (1 + np.exp(-2 * (weighted_score - 0.3)))
        
        # Moderate thresholds for better accuracy
        if calibrated_score >= 0.7:
            label = "phish"
        elif calibrated_score >= 0.4:
            label = "suspicious"
        else:
            label = "legit"
        
        return {
            "score": float(calibrated_score),
            "label": label,
            "probability": float(calibrated_score),
            "model_type": "weighted_ensemble_fallback"
        }
    
    def create_training_data_from_csv(self, csv_path: str) -> pd.DataFrame:
        """
        Create training data from the aggregate_log.csv file.
        """
        if not os.path.exists(csv_path):
            return pd.DataFrame()
        
        df = pd.read_csv(csv_path)
        
        # Create features for each row
        features_list = []
        valid_rows = []
        
        for _, row in df.iterrows():
            try:
                # Safely convert scores to float, handling non-numeric values
                text_score = 0.0
                cnn_score = 0.0
                gnn_score = 0.0
                
                try:
                    text_score = float(row.get('text_score', 0))
                except (ValueError, TypeError):
                    text_score = 0.0
                
                try:
                    cnn_score = float(row.get('cnn_score', 0))
                except (ValueError, TypeError):
                    cnn_score = 0.0
                
                try:
                    gnn_score = float(row.get('gnn_score', 0))
                except (ValueError, TypeError):
                    gnn_score = 0.0
                
                url = str(row.get('url', ''))
                domain = str(row.get('domain', ''))
                label = str(row.get('label', 'low'))
                
                # Skip rows with invalid labels
                if label not in ['high', 'medium', 'low']:
                    continue
                
                # Create features
                features = self.create_features(text_score, cnn_score, gnn_score, url, domain)
                features_list.append(features)
                valid_rows.append(row)
                
            except Exception as e:
                # Skip problematic rows
                continue
        
        if not features_list:
            return pd.DataFrame()
        
        # Create DataFrame
        feature_df = pd.DataFrame(features_list, columns=self.feature_names)
        
        # Create valid rows DataFrame
        valid_df = pd.DataFrame(valid_rows)
        
        # Add target variable based on label
        valid_df['is_phishing'] = valid_df['label'].map({'high': 1, 'medium': 0.5, 'low': 0})
        
        # Combine features with target
        result_df = pd.concat([feature_df, valid_df[['is_phishing', 'label', 'url', 'domain']].reset_index(drop=True)], axis=1)
        
        return result_df

# Global instance
lightgbm_ensemble = LightGBMEnsemble()

def combine_scores_with_lightgbm(text_score: float, cnn_score: float = 0.0, gnn_score: float = 0.0,
                                url: str = "", domain: str = "", additional_features: Dict = None) -> Dict[str, Any]:
    """
    Combine scores using LightGBM ensemble model.
    """
    return lightgbm_ensemble.predict(text_score, cnn_score, gnn_score, url, domain, additional_features)
