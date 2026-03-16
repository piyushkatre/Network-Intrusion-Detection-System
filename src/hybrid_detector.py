import numpy as np
import joblib
import time
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from llm_detector import LLMDetector


class HybridDetector:
    def __init__(self, 
                 model_path: str,
                 scaler_path: str,
                 label_encoder_path: str,
                 feature_columns_path: str,
                 confidence_threshold: float = 0.85,
                 llm_provider: str = "openai",
                 llm_enabled: bool = True):
        """
        Initialize hybrid detector.
        
        Args:
            model_path: Path to trained ML model (.pkl)
            scaler_path: Path to feature scaler (.pkl)
            label_encoder_path: Path to label encoder (.pkl)
            feature_columns_path: Path to feature columns (.npy)
            confidence_threshold: Confidence below which LLM is used (0.0-1.0)
            llm_provider: LLM provider ('openai' or 'anthropic')
            llm_enabled: Whether to enable LLM analysis
        """
        # Load ML components
        self.ml_model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.label_encoder = joblib.load(label_encoder_path)
        self.feature_columns = np.load(feature_columns_path, allow_pickle=True).tolist()
        
        # Configuration
        self.confidence_threshold = confidence_threshold
        self.llm_enabled = llm_enabled
        
        # Initialize LLM detector if enabled
        self.llm_detector = None
        if llm_enabled:
            try:
                self.llm_detector = LLMDetector(provider=llm_provider)
                print(f" LLM detector initialized ({llm_provider})")
            except Exception as e:
                print(f" LLM initialization failed: {e}")
                print("  Continuing with ML-only mode")
                self.llm_enabled = False
        
        # Performance tracking
        self.stats = {
            'total_predictions': 0,
            'ml_only': 0,
            'llm_assisted': 0,
            'ml_time_total': 0.0,
            'llm_time_total': 0.0
        }
    
    def predict(self, features: np.ndarray, use_llm: bool = True) -> Dict:
        """
        Predict using hybrid approach.
        
        Args:
            features: Raw feature array (will be scaled internally)
            use_llm: Whether to use LLM for low-confidence predictions
            
        Returns:
            Dictionary with prediction, confidence, explanation, etc.
        """
        start_time = time.time()
        
        # Validate input
        if len(features) != len(self.feature_columns):
            raise ValueError(
                f"Expected {len(self.feature_columns)} features, got {len(features)}"
            )
        
        # Scale features
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        # ML prediction
        ml_start = time.time()
        ml_prediction_code = self.ml_model.predict(features_scaled)[0]
        ml_probabilities = self.ml_model.predict_proba(features_scaled)[0]
        ml_confidence = float(max(ml_probabilities))
        ml_time = time.time() - ml_start
        
        # Decode prediction
        try:
            ml_prediction = self.label_encoder.inverse_transform([ml_prediction_code])[0]
        except Exception:
            ml_prediction = "BENIGN" if ml_prediction_code == 0 else "ATTACK"
        
        # Update stats
        self.stats['total_predictions'] += 1
        self.stats['ml_time_total'] += ml_time
        
        # Determine if LLM analysis is needed
        use_llm_analysis = (
            use_llm and 
            self.llm_enabled and 
            self.llm_detector is not None and
            ml_confidence < self.confidence_threshold
        )
        
        result = {
            'prediction': ml_prediction,
            'confidence': ml_confidence,
            'ml_confidence': ml_confidence,
            'probabilities': ml_probabilities.tolist(),
            'is_attack': ml_prediction.upper() not in ['BENIGN', 'NORMAL'],
            'method': 'ml_only',
            'ml_time_ms': ml_time * 1000,
            'total_time_ms': (time.time() - start_time) * 1000
        }
        
        # LLM analysis for low-confidence predictions
        if use_llm_analysis:
            llm_start = time.time()
            try:
                llm_result = self.llm_detector.analyze_traffic(features, self.feature_columns)
                llm_time = time.time() - llm_start
                
                # Combine ML and LLM results
                result.update({
                    'method': 'hybrid',
                    'llm_prediction': llm_result['classification'],
                    'llm_confidence': llm_result['confidence'],
                    'llm_reasoning': llm_result['reasoning'],
                    'llm_indicators': llm_result.get('indicators', []),
                    'llm_attack_type': llm_result.get('attack_type'),
                    'llm_time_ms': llm_time * 1000,
                    'total_time_ms': (time.time() - start_time) * 1000
                })
                
                # Use LLM prediction if it has higher confidence
                if llm_result['confidence'] > ml_confidence:
                    result['prediction'] = llm_result['classification']
                    result['confidence'] = llm_result['confidence']
                    result['is_attack'] = llm_result['classification'].upper() == 'ATTACK'
                
                self.stats['llm_assisted'] += 1
                self.stats['llm_time_total'] += llm_time
                
            except Exception as e:
                result['llm_error'] = str(e)
                result['method'] = 'ml_fallback'
        
        if result['method'] == 'ml_only':
            self.stats['ml_only'] += 1
        
        return result
    
    def predict_with_explanation(self, features: np.ndarray) -> Dict:
        """
        Predict and generate explanation using LLM.
        
        Args:
            features: Raw feature array
            
        Returns:
            Dictionary with prediction and detailed explanation
        """
        # Get base prediction
        result = self.predict(features, use_llm=True)
        
        # Generate explanation if LLM is available
        if self.llm_enabled and self.llm_detector is not None:
            try:
                explanation = self.llm_detector.explain_prediction(
                    features,
                    self.feature_columns,
                    result['prediction'],
                    result['ml_confidence']
                )
                result['explanation'] = explanation
            except Exception as e:
                result['explanation'] = f"Explanation unavailable: {str(e)}"
        else:
            result['explanation'] = f"Classified as {result['prediction']} with {result['confidence']:.1%} confidence"
        
        return result
    
    def batch_predict(self, features_list: List[np.ndarray], use_llm: bool = True) -> List[Dict]:
        """
        Predict multiple samples.
        
        Args:
            features_list: List of feature arrays
            use_llm: Whether to use LLM for low-confidence predictions
            
        Returns:
            List of prediction dictionaries
        """
        results = []
        for features in features_list:
            result = self.predict(features, use_llm=use_llm)
            results.append(result)
        return results
    
    def get_performance_stats(self) -> Dict:
        """
        Get performance statistics.
        
        Returns:
            Dictionary with performance metrics
        """
        stats = self.stats.copy()
        
        if stats['total_predictions'] > 0:
            stats['ml_only_percentage'] = (stats['ml_only'] / stats['total_predictions']) * 100
            stats['llm_assisted_percentage'] = (stats['llm_assisted'] / stats['total_predictions']) * 100
            stats['avg_ml_time_ms'] = (stats['ml_time_total'] / stats['total_predictions']) * 1000
            
            if stats['llm_assisted'] > 0:
                stats['avg_llm_time_ms'] = (stats['llm_time_total'] / stats['llm_assisted']) * 1000
            else:
                stats['avg_llm_time_ms'] = 0.0
        
        stats['llm_enabled'] = self.llm_enabled
        stats['confidence_threshold'] = self.confidence_threshold
        
        return stats
    
    def set_confidence_threshold(self, threshold: float):
        """
        Update confidence threshold.
        
        Args:
            threshold: New threshold (0.0-1.0)
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self.confidence_threshold = threshold
    
    def enable_llm(self, enabled: bool = True):
        """
        Enable or disable LLM analysis.
        
        Args:
            enabled: Whether to enable LLM
        """
        if enabled and self.llm_detector is None:
            raise ValueError("LLM detector not initialized")
        self.llm_enabled = enabled
