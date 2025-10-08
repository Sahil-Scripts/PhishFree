#!/usr/bin/env python3
"""
Quick training script for the text model to reduce false positives.
This creates a simple dataset and trains the RoBERTa model for phishing detection.
"""

import os
import pandas as pd
import numpy as np
from llm_model import TextModel
import torch

def create_training_data():
    """Create a balanced training dataset with phishing and legitimate examples."""
    
    # Phishing examples (label=1)
    phishing_examples = [
        "Dear Customer, verify your account immediately at http://secure-bank-login.example/",
        "Urgent: Your account will be suspended. Click here to verify: http://fake-bank.com",
        "Invoice attached: Invoice_8472.pdf. Please pay at http://example-payments.test/",
        "Your password has expired. Reset now at http://password-reset-fake.com",
        "Congratulations! You've won $1000. Claim your prize at http://fake-lottery.com",
        "Security Alert: Unusual login detected. Verify your identity at http://fake-security.com",
        "Your payment failed. Update your card details at http://fake-payment.com",
        "Account locked due to suspicious activity. Unlock at http://fake-unlock.com",
        "Tax refund available. Claim at http://fake-tax-refund.com",
        "Your subscription expired. Renew at http://fake-renewal.com"
    ]
    
    # Legitimate examples (label=0)
    legitimate_examples = [
        "Hi team, meeting tomorrow at 10am. Agenda attached.",
        "Thanks for your email. I'll get back to you soon.",
        "The quarterly report is ready for review.",
        "Please find the attached document for your reference.",
        "Looking forward to our collaboration on this project.",
        "The conference call is scheduled for next Tuesday.",
        "I've reviewed your proposal and it looks good.",
        "Can we schedule a follow-up meeting for next week?",
        "The project deadline has been extended to next month.",
        "Please confirm your attendance for the team meeting.",
        "Your order has been shipped and will arrive tomorrow.",
        "Thank you for your purchase. Your receipt is attached.",
        "The software update is now available for download.",
        "Your monthly newsletter is ready to read.",
        "We're excited to announce our new product launch."
    ]
    
    # Create DataFrame
    data = []
    for text in phishing_examples:
        data.append({"text": text, "label": 1})
    for text in legitimate_examples:
        data.append({"text": text, "label": 0})
    
    df = pd.DataFrame(data)
    
    # Shuffle the data
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Split into train/validation (80/20)
    train_size = int(0.8 * len(df))
    train_df = df[:train_size]
    val_df = df[train_size:]
    
    # Save to CSV files
    train_df.to_csv("train_data.csv", index=False)
    val_df.to_csv("val_data.csv", index=False)
    
    print(f"Created training dataset:")
    print(f"  Total examples: {len(df)}")
    print(f"  Phishing examples: {len(phishing_examples)}")
    print(f"  Legitimate examples: {len(legitimate_examples)}")
    print(f"  Training set: {len(train_df)}")
    print(f"  Validation set: {len(val_df)}")
    
    return "train_data.csv", "val_data.csv"

def train_model():
    """Train the text model with the created dataset."""
    
    print("Creating training data...")
    train_csv, val_csv = create_training_data()
    
    print("Initializing model...")
    model = TextModel(model_name="roberta-base")
    
    print("Starting training...")
    try:
        model.finetune(
            train_csv=train_csv,
            val_csv=val_csv,
            output_dir="./roberta_phish",
            batch_size=4,  # Smaller batch size for stability
            epochs=3,
            lr=1e-5  # Lower learning rate for stability
        )
        print("✅ Training completed successfully!")
        print("Model saved to: ./roberta_phish")
        
        # Test the trained model
        print("\nTesting trained model:")
        test_texts = [
            "Dear Customer, verify your account immediately",
            "Hi team, meeting tomorrow at 10am",
            "Your password has expired. Reset now",
            "Thanks for your email. I'll get back to you soon"
        ]
        
        for text in test_texts:
            result = model.predict(text)
            score = result["score"]
            label = "PHISHING" if score > 0.5 else "LEGITIMATE"
            print(f"  '{text[:50]}...' -> {label} (score: {score:.3f})")
            
    except Exception as e:
        print(f"❌ Training failed: {e}")
        return False
    
    # Clean up temporary files
    try:
        os.remove(train_csv)
        os.remove(val_csv)
        print("Cleaned up temporary files.")
    except:
        pass
    
    return True

if __name__ == "__main__":
    print("🚀 Starting text model training...")
    success = train_model()
    if success:
        print("\n🎉 Training completed! Your model should now give more accurate scores.")
        print("Restart your backend server to use the trained model.")
    else:
        print("\n❌ Training failed. Check the error messages above.")
