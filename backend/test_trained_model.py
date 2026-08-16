"""
Test script to verify the trained model works correctly.
"""
import os
import joblib
import pandas as pd
import numpy as np
from ml.dynamic_risk_engine import DynamicRiskEngine

def test_model_loading_and_prediction():
    """Test that we can load the trained model and make predictions."""
    model_path = "models/dynamic_risk_model_xgboost.joblib"
    
    if not os.path.exists(model_path):
        print(f"Model file not found: {model_path}")
        return False
    
    # Load the model
    engine = DynamicRiskEngine()
    engine.load_model(model_path)
    
    print(f"Model loaded successfully. Type: {engine.model_type}")
    print(f"Features: {engine.feature_names}")
    print(f"Is trained: {engine.is_trained}")
    
    # Create a sample feature vector (same order as training)
    sample_data = pd.DataFrame({
        'cvss_normalized': [0.8],  # CVSS 8.0
        'epss_score': [0.9],
        'epss_logit': [np.log(0.9 + 1e-6)],
        'kev': [1],
        'asset_criticality_norm': [0.8],  # 4/5
        'internet_exposure': [1],
        'data_sensitivity_encoded': [0.75],  # confidential
        'exploit_available': [1],
        'exploit_maturity_encoded': [1.0],  # weaponized
        'days_since_published': [np.log1p(30)],  # 30 days
        'days_since_modified': [np.log1p(5)],   # 5 days
        'threat_velocity_score': [0.7],
        'dark_web_mentions_log': [np.log1p(10)],
        'exploit_code_available': [1],
        'business_impact_log': [np.log1p(1000000)],  # $1M
        'asset_type_encoded': [0.1],  # frequency encoded
        'cwe_freq_encoded': [0.05],
        'cvss_epss_interaction': [0.8 * 0.9],
        'kev_cvss_interaction': [1 * 0.8],
        'exploit_cvss_interaction': [1 * 0.8],
        'asset_exposure_interaction': [0.8 * 1],
        'epss_momentum': [0.0]
    })
    
    # Ensure columns are in the same order as training
    sample_data = sample_data[engine.feature_names]
    
    # Make prediction
    risk_score = engine.predict_risk_score(sample_data)
    prob_exploited = engine.predict_proba(sample_data)[:, 1]
    
    print(f"Predicted risk score (0-100): {risk_score[0]:.2f}")
    print(f"Probability of exploitation: {prob_exploited[0]:.4f}")
    
    # Get explanation
    explanation = engine.explain_prediction(sample_data)
    print(f"Expected value (base rate): {explanation['expected_value']:.4f}")
    print("Top 5 contributing features:")
    for feat, contrib in list(explanation['contributions'][0].items())[:5]:
        print(f"  {feat}: {contrib:.4f}")
    
    # Validate outputs are in expected ranges
    assert 0 <= risk_score[0] <= 100, f"Risk score out of range: {risk_score[0]}"
    assert 0 <= prob_exploited[0] <= 1, f"Probability out of range: {prob_exploited[0]}"
    
    print("\n✅ All tests passed!")
    return True

if __name__ == "__main__":
    test_model_loading_and_prediction()