"""
Dynamic Risk Engine for Vulnerability Prioritization
Implements XGBoost/LightGBM models for calculating dynamic risk scores.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import joblib
import logging
from sklearn.model_selection import train_test_split, TimeSeriesSplit
from sklearn.metrics import roc_auc_score, precision_recall_curve, f1_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import lightgbm as lgb
import shap

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DynamicRiskEngine:
    """
    Engine for training and serving dynamic risk models.
    Supports both XGBoost and LightGBM.
    """
    
    def __init__(self, model_type: str = 'xgboost', model_params: Optional[Dict] = None):
        """
        Initialize the risk engine.
        
        Args:
            model_type: 'xgboost' or 'lightgbm'
            model_params: Dictionary of model hyperparameters
        """
        self.model_type = model_type.lower()
        self.model_params = model_params or self._get_default_params()
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False
        
    def _get_default_params(self) -> Dict:
        """Get default hyperparameters for each model type."""
        if self.model_type == 'xgboost':
            return {
                'objective': 'binary:logistic',
                'eval_metric': 'auc',
                'max_depth': 6,
                'learning_rate': 0.1,
                'n_estimators': 100,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42
            }
        elif self.model_type == 'lightgbm':
            return {
                'objective': 'binary',
                'metric': 'auc',
                'max_depth': 6,
                'learning_rate': 0.1,
                'n_estimators': 100,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42
            }
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Engineer features from raw vulnerability and asset data.
        
        Expected input columns:
        - cvss_v3_score or cvss_score, epss_score, kev (bool)
        - asset_criticality, internet_exposure (bool), data_sensitivity (categorical)
        - exploit_available (bool), exploit_maturity (categorical)
        - days_since_published, days_since_modified
        - threat_velocity_score, dark_web_mentions, exploit_code_available
        - asset_business_importance, asset_type (categorical)
        - CWE (categorical), CVSS vector components (optional)
        
        Returns:
            DataFrame with engineered features ready for modeling
        """
        features = df.copy()
        
        # Handle CVSS score field naming (support both v3 and generic)
        cvss_col = None
        if 'cvss_v3_score' in features.columns:
            cvss_col = 'cvss_v3_score'
        elif 'cvss_v4_score' in features.columns:
            cvss_col = 'cvss_v4_score'
        elif 'cvss_score' in features.columns:
            cvss_col = 'cvss_score'
        else:
            raise ValueError("No CVSS score field found. Expected one of: cvss_v3_score, cvss_v4_score, cvss_score")
        
        # 1. CVSS transformations
        features['cvss_normalized'] = features[cvss_col] / 10.0  # 0-1 scale
        
        # 2. EPSS transformations (already 0-1, but handle missing)
        features['epss_score'] = features['epss_score'].fillna(0.0)
        features['epss_logit'] = np.log(features['epss_score'] + 1e-6)  # Avoid log(0)
        
        # 3. KEV as binary
        features['kev'] = features['kev'].astype(int)
        
        # 4. Asset criticality (normalize 1-5 to 0-1)
        features['asset_criticality_norm'] = features['asset_criticality'] / 5.0
        
        # 5. Exposure features
        features['internet_exposure'] = features['internet_exposure'].astype(int)
        
        # 6. Data sensitivity (ordinal encoding)
        sensitivity_map = {'public': 0, 'internal': 0.25, 'confidential': 0.5, 'restricted': 1.0}
        features['data_sensitivity_encoded'] = features['data_sensitivity'].map(sensitivity_map).fillna(0.0)
        
        # 7. Exploit availability
        features['exploit_available'] = features['exploit_available'].astype(int)
        
        # 8. Exploit maturity (ordinal)
        maturity_map = {'none': 0, 'proof-of-concept': 0.33, 'functional': 0.66, 'weaponized': 1.0}
        features['exploit_maturity_encoded'] = features['exploit_maturity'].map(maturity_map).fillna(0.0)
        
        # 9. Vulnerability age features
        features['days_since_published'] = np.log1p(features['days_since_published'].fillna(365*10))  # Cap at 10 years
        features['days_since_modified'] = np.log1p(features['days_since_modified'].fillna(365*10))
        
        # 10. Threat intelligence features
        features['threat_velocity_score'] = features['threat_velocity_score'].fillna(0.0)
        features['dark_web_mentions_log'] = np.log1p(features['dark_web_mentions'].fillna(0))
        features['exploit_code_available'] = features['exploit_code_available'].astype(int)
        
        # 11. Business impact (if available)
        if 'business_impact_usd' in features.columns:
            features['business_impact_log'] = np.log1p(features['business_impact_usd'].fillna(0))
        
        # 12. Asset type encoding (one-hot or frequency)
        # For simplicity, we'll use frequency encoding here
        asset_type_freq = features['asset_type'].value_counts(normalize=True)
        features['asset_type_encoded'] = features['asset_type'].map(asset_type_freq).fillna(0.0)
        
        # 13. CWE encoding (top 20 CWEs + 'other')
        top_cwes = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-22', 'CWE-352', 'CWE-434', 'CWE-611', 
                   'CWE-264', 'CWE-287', 'CWE-352', 'CWE-200', 'CWE-269', 'CWE-276', 'CWE-284',
                   'CWE-20', 'CWE-252', 'CWE-254', 'CWE-285', 'CWE-286', 'CWE-288']
        features['cwe_encoded'] = features['cwe_id'].apply(
            lambda x: x if x in top_cwes else 'other'
        )
        # Frequency encode
        cwe_freq = features['cwe_encoded'].value_counts(normalize=True)
        features['cwe_freq_encoded'] = features['cwe_encoded'].map(cwe_freq).fillna(0.0)
        
        # 14. Interaction features (important for risk)
        features['cvss_epss_interaction'] = features['cvss_normalized'] * features['epss_score']
        features['kev_cvss_interaction'] = features['kev'] * features['cvss_normalized']
        features['exploit_cvss_interaction'] = features['exploit_available'] * features['cvss_normalized']
        features['asset_exposure_interaction'] = features['asset_criticality_norm'] * features['internet_exposure']
        
        # 15. Temporal trends (if we have historical EPSS)
        # This would require joining with historical EPSS data - simplified here
        features['epss_momentum'] = 0.0  # Placeholder: would be (current_epss - past_epss) / time_diff
        
        # Select final feature set
        feature_cols = [
            'cvss_normalized', 'epss_score', 'epss_logit', 'kev',
            'asset_criticality_norm', 'internet_exposure', 'data_sensitivity_encoded',
            'exploit_available', 'exploit_maturity_encoded',
            'days_since_published', 'days_since_modified',
            'threat_velocity_score', 'dark_web_mentions_log', 'exploit_code_available',
            'business_impact_log', 'asset_type_encoded', 'cwe_freq_encoded',
            'cvss_epss_interaction', 'kev_cvss_interaction', 'exploit_cvss_interaction',
            'asset_exposure_interaction', 'epss_momentum'
        ]
        
        # Ensure all columns exist
        for col in feature_cols:
            if col not in features.columns:
                features[col] = 0.0  # Default value
                
        return features[feature_cols]
    
    def train(self, X: pd.DataFrame, y: pd.Series, 
              validation_data: Optional[Tuple[pd.DataFrame, pd.Series]] = None,
              categorical_features: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Train the risk model.
        
        Args:
            X: Feature DataFrame
            y: Target binary series (1 = exploited, 0 = not exploited)
            validation_data: Tuple of (X_val, y_val) for early stopping
            categorical_features: List of categorical column names (for LightGBM)
            
        Returns:
            Dictionary with training metrics
        """
        logger.info(f"Training {self.model_type} model with {X.shape[0]} samples and {X.shape[1]} features")
        
        # Store feature names for later use
        self.feature_names = list(X.columns)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        X_scaled = pd.DataFrame(X_scaled, columns=self.feature_names, index=X.index)
        
        if validation_data:
            X_val, y_val = validation_data
            X_val_scaled = self.scaler.transform(X_val)
            X_val_scaled = pd.DataFrame(X_val_scaled, columns=self.feature_names, index=X_val.index)
        
        if self.model_type == 'xgboost':
            dtrain = xgb.DMatrix(X_scaled, label=y)
            if validation_data:
                dval = xgb.DMatrix(X_val_scaled, label=y_val)
                watchlist = [(dtrain, 'train'), (dval, 'val')]
                self.model = xgb.train(
                    self.model_params,
                    dtrain,
                    num_boost_round=self.model_params.get('n_estimators', 100),
                    evals=watchlist,
                    early_stopping_rounds=50,
                    verbose_eval=False
                )
            else:
                self.model = xgb.train(
                    self.model_params,
                    dtrain,
                    num_boost_round=self.model_params.get('n_estimators', 100)
                )
                
        elif self.model_type == 'lightgbm':
            if categorical_features is None:
                categorical_features = 'auto'
            train_data = lgb.Dataset(X_scaled, label=y, categorical_feature=categorical_features)
            if validation_data:
                val_data = lgb.Dataset(X_val_scaled, label=y_val, categorical_feature=categorical_features, reference=train_data)
                self.model = lgb.train(
                    self.model_params,
                    train_data,
                    num_boost_round=self.model_params.get('n_estimators', 100),
                    valid_sets=[train_data, val_data],
                    early_stopping_rounds=50,
                    verbose_eval=False
                )
            else:
                self.model = lgb.train(
                    self.model_params,
                    train_data,
                    num_boost_round=self.model_params.get('n_estimators', 100)
                )
        
        self.is_trained = True
        
        # Calculate training metrics
        train_pred = self.predict_proba(X)[:, 1]  # Probability of positive class
        train_auc = roc_auc_score(y, train_pred)
        
        metrics = {
            'train_auc': train_auc,
            'train_samples': X.shape[0],
            'feature_count': X.shape[1]
        }
        
        if validation_data:
            val_pred = self.predict_proba(X_val)[:, 1]
            val_auc = roc_auc_score(y_val, val_pred)
            metrics['val_auc'] = val_auc
            
        logger.info(f"Training completed. Metrics: {metrics}")
        return metrics
    
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict exploitation probabilities.
        
        Args:
            X: Feature DataFrame (must have same columns as training data)
            
        Returns:
            Array of shape (n_samples, 2) with [prob_not_exploited, prob_exploited]
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before making predictions")
        
        # Ensure columns match
        if list(X.columns) != self.feature_names:
            logger.warning("Feature columns don't match training data. Attempting to align.")
            # Reindex to match training columns, filling missing with 0
            X = X.reindex(columns=self.feature_names, fill_value=0.0)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        X_scaled = pd.DataFrame(X_scaled, columns=self.feature_names, index=X.index)
        
        if self.model_type == 'xgboost':
            dtest = xgb.DMatrix(X_scaled)
            probs = self.model.predict(dtest)
        elif self.model_type == 'lightgbm':
            probs = self.model.predict(X_scaled)
        
        # Return probabilities for both classes
        return np.vstack([1 - probs, probs]).T
    
    def predict_risk_score(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict risk scores on 0-100 scale.
        
        Args:
            X: Feature DataFrame
            
        Returns:
            Array of risk scores (0-100)
        """
        probs = self.predict_proba(X)[:, 1]  # Probability of exploitation
        # Convert to 0-100 scale (can calibrate as needed)
        risk_scores = probs * 100
        return risk_scores
    
    def explain_prediction(self, X: pd.DataFrame, 
                          shap_values: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        Generate SHAP explanations for predictions.
        
        Args:
            X: Feature DataFrame (single sample or batch)
            shap_values: Precomputed SHAP values (optional)
            
        Returns:
            Dictionary with feature contributions and expected value
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before generating explanations")
        
        # Ensure columns match
        if list(X.columns) != self.feature_names:
            X = X.reindex(columns=self.feature_names, fill_value=0.0)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        X_scaled = pd.DataFrame(X_scaled, columns=self.feature_names, index=X.index)
        
        if shap_values is None:
            # Compute SHAP values
            if self.model_type == 'xgboost':
                explainer = shap.TreeExplainer(self.model)
            elif self.model_type == 'lightgbm':
                explainer = shap.TreeExplainer(self.model)
            shap_values = explainer.shap_values(X_scaled)
            # For binary classification, shap_values is a list of two arrays [class0, class1]
            # We want the explanation for the positive class (exploited)
            if isinstance(shap_values, list):
                shap_values = shap_values[1]
        
        # Get feature contributions for each sample
        contributions = []
        for i in range(X_scaled.shape[0]):
            sample_contrib = dict(zip(self.feature_names, shap_values[i]))
            # Sort by absolute contribution
            sorted_contrib = dict(sorted(sample_contrib.items(), 
                                       key=lambda x: abs(x[1]), reverse=True))
            contributions.append(sorted_contrib)
        
        expected_value = self.model.predict_proba(X_scaled)[:, 1].mean() if hasattr(self.model, 'predict_proba') else 0.5
        
        return {
            'expected_value': expected_value,
            'contributions': contributions,
            'feature_names': self.feature_names
        }
    
    def save_model(self, filepath: str):
        """Save the trained model and scaler."""
        if not self.is_trained:
            raise RuntimeError("No trained model to save")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'model_type': self.model_type,
            'model_params': self.model_params,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load a trained model and scaler."""
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.model_type = model_data['model_type']
        self.model_params = model_data['model_params']
        self.is_trained = model_data['is_trained']
        logger.info(f"Model loaded from {filepath}")

class PredictiveExploitabilityModel:
    """
    Model for predicting exploitation probability over time (30/60/90 days).
    Uses time-series forecasting techniques.
    """
    
    def __init__(self, model_type: str = 'prophet'):
        """
        Args:
            model_type: 'prophet', 'arima', or 'lstm'
        """
        self.model_type = model_type
        self.model = None
        self.is_trained = False
        
    def prepare_time_series(self, df: pd.DataFrame, 
                           cve_id: str,
                           date_column: str = 'epss_date',
                           value_column: str = 'epss_score') -> pd.DataFrame:
        """
        Prepare time series data for a specific CVE.
        
        Args:
            df: DataFrame with historical EPSS scores (or other temporal metrics)
            cve_id: CVE identifier to filter
            date_column: Name of date column
            value_column: Name of value column to forecast
            
        Returns:
            DataFrame with 'ds' (date) and 'y' (value) columns for Prophet
        """
        # Filter for specific CVE
        cve_data = df[df['cve_id'] == cve_id].copy()
        
        if cve_data.empty:
            raise ValueError(f"No data found for CVE {cve_id}")
        
        # Prepare for Prophet
        ts_data = cve_data[[date_column, value_column]].copy()
        ts_data = ts_data.rename(columns={date_column: 'ds', value_column: 'y'})
        ts_data = ts_data.sort_values('ds')
        
        return ts_data
    
    def train(self, time_series_data: pd.DataFrame):
        """
        Train the time-series model.
        
        Args:
            time_series_data: DataFrame with 'ds' and 'y' columns
        """
        if self.model_type == 'prophet':
            try:
                from prophet import Prophet
                self.model = Prophet(
                    yearly_seasonality=False,
                    weekly_seasonality=False,
                    daily_seasonality=False,
                    seasonality_mode='additive'
                )
                self.model.fit(time_series_data)
                self.is_trained = True
                logger.info("Prophet model trained successfully")
            except ImportError:
                logger.error("Prophet not installed. Install with: pip install prophet")
                raise
        elif self.model_type == 'arima':
            try:
                import statsmodels.api as sm
                # Auto ARIMA order selection would be better in practice
                self.model = sm.tsa.ARIMA(time_series_data['y'], order=(1,1,1))
                self.model = self.model.fit()
                self.is_trained = True
                logger.info("ARIMA model trained successfully")
            except ImportError:
                logger.error("Statsmodels not installed. Install with: pip install statsmodels")
                raise
        elif self.model_type == 'lstm':
            # LSTM implementation would go here (using TensorFlow/Keras or PyTorch)
            logger.warning("LSTM implementation not shown in this example")
            # Placeholder
            self.is_trained = True
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def predict(self, steps: int = 30) -> np.ndarray:
        """
        Predict future values.
        
        Args:
            steps: Number of time steps to forecast ahead
            
        Returns:
            Array of predicted values
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before making predictions")
        
        if self.model_type == 'prophet':
            future = self.model.make_future_dataframe(periods=steps)
            forecast = self.model.predict(future)
            # Return the last 'steps' predictions
            return forecast['yhat'].tail(steps).values
        elif self.model_type == 'arima':
            forecast = self.model.forecast(steps=steps)
            return forecast
        elif self.model_type == 'lstm':
            # Placeholder
            return np.zeros(steps)
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
    
    def predict_exploitability(self, 
                              current_epss: float,
                              days_since_published: int,
                             kev: bool,
                              threat_velocity: float,
                              horizon: str = '30d') -> float:
        """
        Predict exploitation probability for a specific time horizon.
        This is a simplified version - in practice would use the time-series model
        combined with other features.
        
        Args:
            current_epss: Current EPSS score
            days_since_published: Days since vulnerability publication
            kev: Whether in KEV catalog
            threat_velocity: Real-time threat velocity score
            horizon: '30d', '60d', or '90d'
            
        Returns:
            Predicted exploitation probability (0-1)
        """
        # This is a simplified heuristic - replace with actual time-series model output
        base_prob = current_epss
        
        # Adjust for KEV (major booster)
        if kev:
            base_prob = min(base_prob * 2.0, 0.95)
        
        # Adjust for threat velocity
        base_prob = base_prob * (1.0 + threat_velocity)
        
        # Adjust for age (older vulns have lower exploit probability unless in KEV)
        age_factor = np.exp(-days_since_published / 365.0)  # Decay over year
        if not kev:
            base_prob = base_prob * age_factor
        
        # Horizon adjustment (longer horizon = higher cumulative probability)
        horizon_days = {'30d': 30, '60d': 60, '90d': 90}[horizon]
        time_factor = min(horizon_days / 30.0, 3.0)  # Cap at 3x
        
        final_prob = min(base_prob * (1.0 + (time_factor - 1.0) * 0.5), 0.99)
        return final_prob

# Example usage
if __name__ == "__main__":
    # Example: Training the dynamic risk engine
    print("Dynamic Risk Engine Example")
    
    # Create sample data (in practice, load from database)
    np.random.seed(42)
    n_samples = 1000
    
    sample_data = pd.DataFrame({
        'cve_id': [f'CVE-2023-{i:05d}' for i in range(n_samples)],
        'cvss_score': np.random.uniform(0, 10, n_samples),
        'epss_score': np.random.uniform(0, 1, n_samples),
        'kev': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
        'asset_criticality': np.random.randint(1, 6, n_samples),
        'internet_exposure': np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),
        'data_sensitivity': np.random.choice(['public', 'internal', 'confidential', 'restricted'], n_samples),
        'exploit_available': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),
        'exploit_maturity': np.random.choice(['none', 'proof-of-concept', 'functional', 'weaponized'], n_samples),
        'days_since_published': np.random.exponential(365, n_samples),
        'days_since_modified': np.random.exponential(180, n_samples),
        'threat_velocity_score': np.random.uniform(0, 1, n_samples),
        'dark_web_mentions': np.random.poisson(5, n_samples),
        'exploit_code_available': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
        'business_impact_usd': np.random.lognormal(15, 2, n_samples),  # Log-normal for financial impact
        'asset_type': np.random.choice(['server', 'web-app', 'database', 'cloud-storage', 'api'], n_samples),
        'cwe_id': np.random.choice(['CWE-79', 'CWE-89', 'CWE-20', 'CWE-22', 'CWE-352', 'CWE-other'], n_samples),
        # Target: whether exploited in the wild (for training)
        'exploited': np.random.choice([0, 1], n_samples, p=[0.85, 0.15])  # 15% exploited
    })
    
    # Initialize engine
    engine = DynamicRiskEngine(model_type='xgboost')
    
    # Prepare features
    features = engine.prepare_features(sample_data)
    print(f"Prepared {features.shape[1]} features")
    print(f"Feature names: {list(features.columns)}")
    
    # Split data
    X = features
    y = sample_data['exploited']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train model
    metrics = engine.train(X_train, y_train, validation_data=(X_test, y_test))
    print(f"Training metrics: {metrics}")
    
    # Make predictions
    risk_scores = engine.predict_risk_score(X_test)
    print(f"Sample risk scores: {risk_scores[:5]}")
    
    # Get explanations for first sample
    explanation = engine.explain_prediction(X_test.iloc[[0]])
    print(f"Expected value: {explanation['expected_value']:.3f}")
    print("Top 5 contributing features:")
    for feat, contrib in list(explanation['contributions'][0].items())[:5]:
        print(f"  {feat}: {contrib:.4f}")
    
    # Save model
    engine.save_model('dynamic_risk_model.joblib')
    
    # Example: Predictive exploitability model
    print("\nPredictive Exploitability Model Example")
    pred_model = PredictiveExploitabilityModel(model_type='prophet')
    
    # Create sample time-series data for a CVE
    dates = pd.date_range(start='2023-01-01', end='2023-12-31', freq='7d')  # Weekly
    epss_values = np.clip(np.random.beta(2, 5, len(dates)) + np.linspace(0, 0.3, len(dates)), 0, 1)
    ts_data = pd.DataFrame({
        'cve_id': 'CVE-2023-12345',
        'epss_date': dates,
        'epss_score': epss_values
    })
    
    # Prepare time series for Prophet
    try:
        prepared_ts = pred_model.prepare_time_series(ts_data, 'CVE-2023-12345')
        print(f"Prepared time series with {len(prepared_ts)} points")
        
        # Train model (would work with prophet installed)
        # pred_model.train(prepared_ts)
        # forecast_30d = pred_model.predict(steps=30)
        # print(f"30-day EPSS forecast: {forecast_30d[-5:]}")
        
        # Simplified prediction function
        exploit_30d = pred_model.predict_exploitability(
            current_epss=epss_values[-1],
            days_since_published=365,
            kev=True,
            threat_velocity=0.7,
            horizon='30d'
        )
        print(f"Predicted 30-day exploitation probability: {exploit_30d:.3f}")
    except Exception as e:
        print(f"Time-series modeling skipped (Prophet not installed): {e}")