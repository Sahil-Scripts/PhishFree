"""
Training script for LightGBM ensemble model using historical data.
"""

import os
import pandas as pd
import numpy as np
from lightgbm_ensemble import LightGBMEnsemble
import json

def create_training_data():
    """
    Create training data from aggregate_log.csv with proper labels.
    """
    csv_path = "aggregate_log.csv"
    
    if not os.path.exists(csv_path):
        print(f"CSV file {csv_path} not found!")
        return None
    
    # Read the CSV
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} records from {csv_path}")
    
    # Create the ensemble instance
    ensemble = LightGBMEnsemble()
    
    # Create training data
    training_data = ensemble.create_training_data_from_csv(csv_path)
    
    if training_data.empty:
        print("No training data created!")
        return None
    
    print(f"Created training data with {len(training_data)} samples")
    print(f"Features: {list(training_data.columns)}")
    
    # Show label distribution
    label_counts = training_data['label'].value_counts()
    print(f"Label distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count} ({count/len(training_data)*100:.1f}%)")
    
    return training_data

def create_synthetic_training_data():
    """
    Create synthetic training data to improve model performance.
    """
    print("Creating synthetic training data...")
    
    # Define patterns for different types of content
    synthetic_data = []
    
    # Legitimate websites (low risk)
    legitimate_patterns = [
        {"text_score": 0.1, "cnn_score": 0.2, "gnn_score": 0.1, "url": "https://www.google.com", "domain": "google.com", "label": "low"},
        {"text_score": 0.2, "cnn_score": 0.3, "gnn_score": 0.1, "url": "https://www.github.com", "domain": "github.com", "label": "low"},
        {"text_score": 0.15, "cnn_score": 0.25, "gnn_score": 0.1, "url": "https://www.linkedin.com", "domain": "linkedin.com", "label": "low"},
        {"text_score": 0.1, "cnn_score": 0.2, "gnn_score": 0.1, "url": "https://www.microsoft.com", "domain": "microsoft.com", "label": "low"},
        {"text_score": 0.2, "cnn_score": 0.3, "gnn_score": 0.1, "url": "https://www.apple.com", "domain": "apple.com", "label": "low"},
        {"text_score": 0.1, "cnn_score": 0.2, "gnn_score": 0.1, "url": "https://www.amazon.com", "domain": "amazon.com", "label": "low"},
        {"text_score": 0.15, "cnn_score": 0.25, "gnn_score": 0.1, "url": "https://www.facebook.com", "domain": "facebook.com", "label": "low"},
        {"text_score": 0.1, "cnn_score": 0.2, "gnn_score": 0.1, "url": "https://www.twitter.com", "domain": "twitter.com", "label": "low"},
        {"text_score": 0.2, "cnn_score": 0.3, "gnn_score": 0.1, "url": "https://www.youtube.com", "domain": "youtube.com", "label": "low"},
        {"text_score": 0.1, "cnn_score": 0.2, "gnn_score": 0.1, "url": "https://www.spotify.com", "domain": "spotify.com", "label": "low"},
    ]
    
    # Suspicious content (medium risk)
    suspicious_patterns = [
        {"text_score": 0.4, "cnn_score": 0.5, "gnn_score": 0.3, "url": "http://suspicious-site.net", "domain": "suspicious-site.net", "label": "medium"},
        {"text_score": 0.5, "cnn_score": 0.4, "gnn_score": 0.4, "url": "http://weird-domain.org", "domain": "weird-domain.org", "label": "medium"},
        {"text_score": 0.3, "cnn_score": 0.6, "gnn_score": 0.3, "url": "http://strange-content.com", "domain": "strange-content.com", "label": "medium"},
        {"text_score": 0.6, "cnn_score": 0.3, "gnn_score": 0.4, "url": "http://unusual-site.tk", "domain": "unusual-site.tk", "label": "medium"},
        {"text_score": 0.4, "cnn_score": 0.5, "gnn_score": 0.5, "url": "http://questionable.net", "domain": "questionable.net", "label": "medium"},
    ]
    
    # Phishing content (high risk)
    phishing_patterns = [
        {"text_score": 0.8, "cnn_score": 0.7, "gnn_score": 0.8, "url": "http://secure-bank-login.example", "domain": "secure-bank-login.example", "label": "high"},
        {"text_score": 0.9, "cnn_score": 0.8, "gnn_score": 0.7, "url": "http://fake-paypal-verify.com", "domain": "fake-paypal-verify.com", "label": "high"},
        {"text_score": 0.7, "cnn_score": 0.9, "gnn_score": 0.8, "url": "http://crypto-wallet-recovery.org", "domain": "crypto-wallet-recovery.org", "label": "high"},
        {"text_score": 0.8, "cnn_score": 0.7, "gnn_score": 0.9, "url": "http://account-suspended-alert.net", "domain": "account-suspended-alert.net", "label": "high"},
        {"text_score": 0.9, "cnn_score": 0.8, "gnn_score": 0.8, "url": "http://payment-verification-urgent.com", "domain": "payment-verification-urgent.com", "label": "high"},
        {"text_score": 0.7, "cnn_score": 0.8, "gnn_score": 0.7, "url": "http://login-security-check.org", "domain": "login-security-check.org", "label": "high"},
        {"text_score": 0.8, "cnn_score": 0.7, "gnn_score": 0.8, "url": "http://bitcoin-investment-opportunity.net", "domain": "bitcoin-investment-opportunity.net", "label": "high"},
        {"text_score": 0.9, "cnn_score": 0.8, "gnn_score": 0.7, "url": "http://urgent-account-update.com", "domain": "urgent-account-update.com", "label": "high"},
    ]
    
    # Combine all patterns
    all_patterns = legitimate_patterns + suspicious_patterns + phishing_patterns
    
    # Create DataFrame
    synthetic_df = pd.DataFrame(all_patterns)
    
    # Add additional features
    ensemble = LightGBMEnsemble()
    features_list = []
    
    for _, row in synthetic_df.iterrows():
        features = ensemble.create_features(
            text_score=row['text_score'],
            cnn_score=row['cnn_score'],
            gnn_score=row['gnn_score'],
            url=row['url'],
            domain=row['domain']
        )
        features_list.append(features)
    
    # Create feature DataFrame
    feature_df = pd.DataFrame(features_list, columns=ensemble.feature_names)
    
    # Add target variable
    synthetic_df['is_phishing'] = synthetic_df['label'].map({'high': 1, 'medium': 0.5, 'low': 0})
    
    # Combine features with target
    result_df = pd.concat([feature_df, synthetic_df[['is_phishing', 'label', 'url', 'domain']]], axis=1)
    
    print(f"Created {len(result_df)} synthetic training samples")
    print(f"Synthetic data label distribution:")
    label_counts = result_df['label'].value_counts()
    for label, count in label_counts.items():
        print(f"  {label}: {count} ({count/len(result_df)*100:.1f}%)")
    
    return result_df

def train_model():
    """
    Train the LightGBM model.
    """
    print("Starting LightGBM model training...")
    
    # Create ensemble instance
    ensemble = LightGBMEnsemble()
    
    # Get real training data
    real_data = create_training_data()
    
    # Get synthetic training data
    synthetic_data = create_synthetic_training_data()
    
    # Combine real and synthetic data
    if real_data is not None and not real_data.empty:
        training_data = pd.concat([real_data, synthetic_data], ignore_index=True)
        print(f"Combined training data: {len(training_data)} samples")
    else:
        training_data = synthetic_data
        print(f"Using only synthetic training data: {len(training_data)} samples")
    
    # Remove duplicates
    training_data = training_data.drop_duplicates()
    print(f"After removing duplicates: {len(training_data)} samples")
    
    # Check if we have enough data
    if len(training_data) < 10:
        print("Not enough training data! Need at least 10 samples.")
        return False
    
    # Show final label distribution
    print(f"Final training data label distribution:")
    label_counts = training_data['label'].value_counts()
    for label, count in label_counts.items():
        print(f"  {label}: {count} ({count/len(training_data)*100:.1f}%)")
    
    # Train the model
    try:
        model = ensemble.train(training_data, target_column='is_phishing')
        print("LightGBM model trained successfully!")
        
        # Test the model
        print("\nTesting the trained model...")
        
        # Test with legitimate site
        test_result = ensemble.predict(
            text_score=0.2, cnn_score=0.3, gnn_score=0.1,
            url="https://www.google.com", domain="google.com"
        )
        print(f"Google test: score={test_result['score']:.3f}, label={test_result['label']}")
        
        # Test with suspicious site
        test_result = ensemble.predict(
            text_score=0.6, cnn_score=0.5, gnn_score=0.4,
            url="http://suspicious-site.net", domain="suspicious-site.net"
        )
        print(f"Suspicious test: score={test_result['score']:.3f}, label={test_result['label']}")
        
        # Test with phishing site
        test_result = ensemble.predict(
            text_score=0.8, cnn_score=0.7, gnn_score=0.8,
            url="http://secure-bank-login.example", domain="secure-bank-login.example"
        )
        print(f"Phishing test: score={test_result['score']:.3f}, label={test_result['label']}")
        
        return True
        
    except Exception as e:
        print(f"Training failed: {e}")
        return False

if __name__ == "__main__":
    print("LightGBM Model Training Script")
    print("=" * 50)
    
    success = train_model()
    
    if success:
        print("\nTraining completed successfully!")
        print("The trained model will be used automatically by the ensemble.")
    else:
        print("\nTraining failed!")
        print("The system will continue using the fallback weighted ensemble.")
