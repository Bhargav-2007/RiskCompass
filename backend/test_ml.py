"""
Test script for the Dynamic Risk Engine ML components
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'ml'))

from dynamic_risk_engine import DynamicRiskEngine, PredictiveExploitabilityModel
import pandas as pd
import numpy as np

def test_dynamic_risk_engine():
    """Test the DynamicRiskEngine class"""
    print("Testing DynamicRiskEngine...")
    
    # Initialize engine
    engine = DynamicRiskEngine(model_type="xgboost")
    
    # Create sample vulnerability data
    sample_data = pd.DataFrame({
        'cve_id': ['CVE-2023-001', 'CVE-2023-002', 'CVE-2023-003'],
        'cvss_v3_score': [7.5, 9.0, 4.2],
        'epss_score': [0.65, 0.85, 0.25],
        'kev': [False, True, False],
        'asset_criticality': [0.8, 0.9, 0.3],
        'internet_exposure': [True, True, False],
        'data_sensitivity': ['confidential', 'restricted', 'public'],
        'business_impact_usd': [2500000, 5000000, 500000],
        'exploit_available': [False, True, False],
        'exploit_maturity': ['none', 'functional', 'none'],
        'threat_velocity_score': [0.6, 0.9, 0.2],
        'dark_web_mentions': [0, 0, 0],
        'exploit_code_available': [False, True, False],
        'days_since_published': [45, 15, 120],
        'days_since_modified': [45, 15, 120],
        'asset_type': ['server', 'web-app', 'database'],
        'cwe_id': ['CWE-79', 'CWE-89', 'CWE-20']
    })
    
    # Test feature engineering
    print("  Testing feature engineering...")
    features = engine.prepare_features(sample_data)
    print(f"  Features shape: {features.shape}")
    print(f"  Feature columns: {list(features.columns)}")
    
    # Test training (with small dataset for speed)
    print("  Testing model training...")
    try:
        # Create mock target variable (risk scores 0-100)
        y = np.array([75.0, 90.0, 30.0])  # Corresponding risk scores
        engine.train(features, y, validation_split=0.33)
        print("  Model training completed")
        
        # Test prediction
        print("  Testing prediction...")
        predictions = engine.predict(features)
        print(f"  Predictions: {predictions}")
        print(f"  Prediction shape: {predictions.shape}")
        
        # Test SHAP explanation
        print("  Testing SHAP explanation...")
        explanations = engine.explain_prediction(features[:1])  # Explain first sample
        print(f"  Expected value: {explanations['expected_value']}")
        
        print("✓ DynamicRiskEngine tests passed")
        return True
        
    except Exception as e:
        print(f"❌ DynamicRiskEngine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_predictive_exploitability_model():
    """Test the PredictiveExploitabilityModel class"""
    print("\nTesting PredictiveExploitabilityModel...")
    
    try:
        model = PredictiveExploitabilityModel()
        
        # Test with sample data
        days_since_publish = [10, 30, 60, 90, 180]
        epss_scores = [0.1, 0.3, 0.5, 0.7, 0.9]
        
        # Test prediction function
        prob_30 = model.predict_exploitation_probability(30, 0.5)
        prob_60 = model.predict_exploitation_probability(60, 0.7)
        
        print(f"  30-day exploitation probability (EPSS=0.5): {prob_30:.3f}")
        print(f"  60-day exploitation probability (EPSS=0.7): {prob_60:.3f}")
        
        # Validate probabilities are in range
        assert 0 <= prob_30 <= 1, f"Probability out of range: {prob_30}"
        assert 0 <= prob_60 <= 1, f"Probability out of range: {prob_60}"
        
        print("✓ PredictiveExploitabilityModel tests passed")
        return True
        
    except Exception as e:
        print(f"❌ PredictiveExploitabilityModel test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_integration():
    """Test integration between components"""
    print("\nTesting component integration...")
    
    try:
        # Create sample data
        data = pd.DataFrame({
            'cve_id': ['CVE-2023-001', 'CVE-2023-002'],
            'cvss_v3_score': [8.0, 6.0],
            'epss_score': [0.7, 0.4],
            'kev': [True, False],
            'publish_date': ['2023-01-01', '2023-01-15'],
            'asset_criticality': [0.9, 0.5],
            'internet_exposure': [True, False],
            'data_sensitivity': ['restricted', 'internal'],
            'business_impact': [3000000, 800000],
            'exploit_available': [True, False],
            'threat_activity': [0.8, 0.3],
            'vuln_age_days': [20, 50]
        })
        
        # Initialize engines
        risk_engine = DynamicRiskEngine(model_type="xgboost")
        exploit_model = PredictiveExploitabilityModel()
        
        # Prepare features
        features = risk_engine.prepare_features(data)
        
        # Train risk engine (mock targets)
        y_mock = np.array([85.0, 45.0])
        risk_engine.train(features, y_mock, validation_split=0.5)
        
        # Get risk predictions
        risk_scores = risk_engine.predict(features)
        
        # Get exploit predictions
        exploit_probs = []
        for i, row in data.iterrows():
            days = row['vuln_age_days']
            epss = row['epss_score']
            prob = exploit_model.predict_exploitation_probability(days, epss)
            exploit_probs.append(prob)
        
        print(f"  Risk scores: {risk_scores}")
        print(f"  Exploit probabilities: {[f'{p:.3f}' for p in exploit_probs]}")
        
        # Validate outputs
        assert len(risk_scores) == len(data), "Risk score count mismatch"
        assert all(0 <= score <= 100 for score in risk_scores), "Risk score out of range"
        assert all(0 <= prob <= 1 for prob in exploit_probs), "Exploit probability out of range"
        
        print("✓ Integration tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Running ML Engine Tests...\n")
    
    success = True
    success &= test_dynamic_risk_engine()
    success &= test_predictive_exploitability_model()
    success &= test_integration()
    
    if success:
        print("\n🎉 All ML tests passed!")
    else:
        print("\n❌ Some ML tests failed!")
        sys.exit(1)