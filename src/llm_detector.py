import os
import json
import numpy as np
from typing import Dict, List, Optional, Tuple
from traffic_converter import TrafficConverter


class LLMDetector:
    """
    LLM-based network intrusion detector with semantic understanding.
    Supports OpenAI, Anthropic, GitHub Models (Llama 3.3), and local models.
    """
    
    def __init__(self, provider: str = "openai", api_key: Optional[str] = None, model: Optional[str] = None):
        """
        Initialize LLM detector.
        
        Args:
            provider: LLM provider ('openai', 'anthropic', 'github', or 'local')
            api_key: API key for the provider (if None, reads from environment)
            model: Specific model to use (if None, uses default)
        """
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        self.traffic_converter = TrafficConverter()
        
        # Initialize LLM client based on provider
        if self.provider == "openai":
            self.model = model or "gpt-4o-mini"  # Cost-effective model
            self._init_openai()
        elif self.provider == "anthropic":
            self.model = model or "claude-3-haiku-20240307"  # Fast and cheap
            self._init_anthropic()
        elif self.provider == "github":
            self.model = model or "meta-llama-3.3-70b-instruct"  # GitHub Models - Llama 3.3
            self._init_github()
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        # Prompt templates
        self.detection_prompt = """You are a cybersecurity expert analyzing network traffic for intrusion detection.

Network Traffic Description:
{traffic_description}

Task: Analyze this network traffic and determine if it represents:
1. BENIGN - Normal, legitimate network activity
2. ATTACK - Malicious or suspicious activity

Provide your analysis in the following JSON format:
{{
    "classification": "BENIGN" or "ATTACK",
    "confidence": 0.0 to 1.0,
    "attack_type": "type of attack if applicable, or null",
    "reasoning": "brief explanation of your decision",
    "indicators": ["list", "of", "suspicious", "indicators"]
}}

Be precise and focus on actual security indicators."""

        self.explanation_prompt = """You are a cybersecurity expert explaining network intrusion detection results.

Network Traffic:
{traffic_description}

ML Model Prediction: {prediction}
ML Model Confidence: {confidence:.2%}

Task: Provide a clear, concise explanation of why this traffic was classified as {prediction}.
Focus on the key indicators and patterns that led to this classification.
Use simple language that a network administrator would understand.

Explanation:"""
    
    def _init_openai(self):
        """Initialize OpenAI client."""
        try:
            from openai import OpenAI
            if not self.api_key:
                raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
            self.client = OpenAI(api_key=self.api_key)
        except ImportError:
            raise ImportError("OpenAI package not installed. Run: pip install openai")
    
    def _init_anthropic(self):
        """Initialize Anthropic client."""
        try:
            from anthropic import Anthropic
            if not self.api_key:
                raise ValueError("Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable.")
            self.client = Anthropic(api_key=self.api_key)
        except ImportError:
            raise ImportError("Anthropic package not installed. Run: pip install anthropic")
    
    def _init_github(self):
        """Initialize GitHub Models client (uses OpenAI-compatible API)."""
        try:
            from openai import OpenAI
            if not self.api_key:
                raise ValueError("GitHub API key not found. Set GITHUB_API_KEY environment variable.")
            # GitHub Models uses OpenAI-compatible API
            self.client = OpenAI(
                base_url="https://models.inference.ai.azure.com",
                api_key=self.api_key
            )
        except ImportError:
            raise ImportError("OpenAI package not installed. Run: pip install openai")
    
    def analyze_traffic(self, features: np.ndarray, feature_names: List[str]) -> Dict:
        """
        Analyze network traffic using LLM.
        
        Args:
            features: Array of numeric feature values
            feature_names: List of feature names
            
        Returns:
            Dictionary with classification, confidence, reasoning, etc.
        """
        # Convert features to natural language
        traffic_description = self.traffic_converter.features_to_description(features, feature_names)
        
        # Create prompt
        prompt = self.detection_prompt.format(traffic_description=traffic_description)
        
        # Get LLM response
        try:
            response_text = self._call_llm(prompt)
            result = self._parse_detection_response(response_text)
            result['traffic_description'] = traffic_description
            return result
        except Exception as e:
            # Fallback response on error
            return {
                'classification': 'UNKNOWN',
                'confidence': 0.0,
                'attack_type': None,
                'reasoning': f'LLM analysis failed: {str(e)}',
                'indicators': [],
                'error': str(e)
            }
    
    def explain_prediction(self, features: np.ndarray, feature_names: List[str], 
                          ml_prediction: str, ml_confidence: float) -> str:
        """
        Generate natural language explanation for ML prediction.
        
        Args:
            features: Array of numeric feature values
            feature_names: List of feature names
            ml_prediction: Prediction from ML model ('BENIGN' or 'ATTACK')
            ml_confidence: Confidence score from ML model
            
        Returns:
            Natural language explanation
        """
        traffic_description = self.traffic_converter.features_to_description(features, feature_names)
        
        prompt = self.explanation_prompt.format(
            traffic_description=traffic_description,
            prediction=ml_prediction,
            confidence=ml_confidence
        )
        
        try:
            explanation = self._call_llm(prompt)
            return explanation.strip()
        except Exception as e:
            return f"Unable to generate explanation: {str(e)}"
    
    def _call_llm(self, prompt: str, max_tokens: int = 500) -> str:
        """
        Call the LLM API.
        
        Args:
            prompt: Prompt to send to LLM
            max_tokens: Maximum tokens in response
            
        Returns:
            LLM response text
        """
        if self.provider == "openai":
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in network intrusion detection."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.1  # Low temperature for consistent, factual responses
            )
            return response.choices[0].message.content
        
        elif self.provider == "github":
            # GitHub Models uses OpenAI-compatible API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in network intrusion detection."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.1
            )
            return response.choices[0].message.content
        
        elif self.provider == "anthropic":
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.1,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _parse_detection_response(self, response_text: str) -> Dict:
        """
        Parse LLM detection response.
        
        Args:
            response_text: Raw LLM response
            
        Returns:
            Parsed detection result
        """
        try:
            # Try to extract JSON from response
            # Handle cases where LLM adds extra text around JSON
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx != -1 and end_idx > start_idx:
                json_text = response_text[start_idx:end_idx]
                result = json.loads(json_text)
                
                # Validate required fields
                required_fields = ['classification', 'confidence', 'reasoning']
                for field in required_fields:
                    if field not in result:
                        raise ValueError(f"Missing required field: {field}")
                
                # Normalize classification
                result['classification'] = result['classification'].upper()
                if result['classification'] not in ['BENIGN', 'ATTACK']:
                    result['classification'] = 'UNKNOWN'
                
                # Ensure confidence is float between 0 and 1
                result['confidence'] = max(0.0, min(1.0, float(result['confidence'])))
                
                return result
            else:
                raise ValueError("No JSON found in response")
        
        except Exception as e:
            # Fallback: try to extract classification from text
            response_lower = response_text.lower()
            if 'attack' in response_lower or 'malicious' in response_lower:
                classification = 'ATTACK'
                confidence = 0.7
            elif 'benign' in response_lower or 'normal' in response_lower:
                classification = 'BENIGN'
                confidence = 0.7
            else:
                classification = 'UNKNOWN'
                confidence = 0.0
            
            return {
                'classification': classification,
                'confidence': confidence,
                'attack_type': None,
                'reasoning': response_text[:200],  # First 200 chars
                'indicators': [],
                'parse_error': str(e)
            }
