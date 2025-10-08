#!/usr/bin/env python3
"""
Test script to verify CNN and GNN models are working properly.
"""

import requests
import json
import base64

def test_models():
    base_url = "http://localhost:5000"
    
    # Test data
    test_data = {
        "text": "Verify your account immediately at http://fake-bank.com/login",
        "domain": "fake-bank.com",
        "url": "http://fake-bank.com/login"
    }
    
    print("Testing multi-analysis endpoint...")
    print(f"Test data: {test_data}")
    
    try:
        response = requests.post(f"{base_url}/analyze/multi", json=test_data)
        if response.status_code == 200:
            result = response.json()
            print("\n=== Analysis Results ===")
            print(f"Overall Score: {result.get('score', 'N/A')}")
            print(f"Label: {result.get('label', 'N/A')}")
            print(f"Text Score: {result.get('components_raw', {}).get('text', 'N/A')}")
            print(f"CNN Score: {result.get('components_raw', {}).get('cnn', 'N/A')}")
            print(f"GNN Score: {result.get('components_raw', {}).get('gnn', 'N/A')}")
            print(f"Components Run: {result.get('components_run', {})}")
            print(f"Text Reasons: {result.get('text_reasons', [])}")
            print(f"CNN Reasons: {result.get('cnn_reasons', [])}")
            print(f"GNN Reasons: {result.get('gnn_reasons', [])}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error testing models: {e}")
    
    print("\nTesting dashboard data...")
    try:
        response = requests.get(f"{base_url}/aggregate/report?format=json")
        if response.status_code == 200:
            data = response.json()
            print(f"Total records: {len(data)}")
            if data:
                latest = data[-1]
                print(f"Latest record: {latest}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error testing dashboard: {e}")

if __name__ == "__main__":
    test_models()
