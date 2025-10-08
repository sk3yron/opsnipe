#!/usr/bin/env python3
"""
Prediction Module
Make predictions on new contracts (Multi-Chain Support)
"""

import json
import sys
import argparse
import subprocess
from typing import Dict, Optional, List, Tuple
import joblib
import pandas as pd
import numpy as np
import yaml

from feature_extraction import OpcodeFeatureExtractor
from train import HoneypotMLTrainer


class HoneypotPredictor:
    """Make predictions on contract bytecode"""
    
    def __init__(self, model_path: str = "./data/models/honeypot_detector.pkl"):
        print(f"Loading model from {model_path}...", file=sys.stderr)
        
        # Load model
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.metrics = model_data.get('metrics', {})
        
        # Feature importance (if available)
        self.feature_importance = None
        if 'feature_importance' in model_data and model_data['feature_importance']:
            self.feature_importance = pd.DataFrame(model_data['feature_importance'])
        
        # Initialize feature extractor
        self.extractor = OpcodeFeatureExtractor()
        
        print("✓ Model loaded successfully", file=sys.stderr)
    
    def predict(self, bytecode: str) -> Dict:
        """
        Predict if bytecode is a honeypot
        
        Returns:
            dict with keys:
                - is_honeypot: bool
                - confidence: float (0-1)
                - risk_score: int (0-100)
                - risk_level: str (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
                - top_risk_features: list of (feature, value, description) tuples
        """
        # Extract features
        features = self.extractor.extract_all_features(bytecode)
        
        # Create DataFrame with correct feature order
        X = pd.DataFrame([features])
        
        # Ensure all features are present
        for feature in self.feature_names:
            if feature not in X.columns:
                X[feature] = 0
        
        X = X[self.feature_names]
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        probabilities = self.model.predict_proba(X_scaled)[0]
        
        honeypot_probability = probabilities[1]
        
        # Calculate risk score (0-100)
        risk_score = int(honeypot_probability * 100)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        elif risk_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
        
        # Identify top risk features
        top_risk_features = self._identify_risk_features(features, X.iloc[0])
        
        return {
            'is_honeypot': bool(prediction == 1),
            'confidence': float(honeypot_probability),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'safe_probability': float(probabilities[0]),
            'honeypot_probability': float(honeypot_probability),
            'top_risk_features': top_risk_features,
            'model_metrics': {
                'test_accuracy': self.metrics.get('test_accuracy', 'N/A'),
                'roc_auc': self.metrics.get('roc_auc', 'N/A')
            }
        }
    
    def _identify_risk_features(self, raw_features: Dict, scaled_features: pd.Series) -> List[Tuple[str, float, str]]:
        """Identify features contributing most to honeypot risk"""
        risk_features = []
        
        # High-risk feature patterns
        high_risk_indicators = {
            'has_blacklist_functions': 'Blacklist mechanism detected',
            'has_approve_no_transferfrom': 'Broken ERC20: approve without transferFrom',
            'missing_transfer': 'Missing transfer function',
            'delegatecall_to_storage_pattern': 'DELEGATECALL to storage address',
            'conditional_selfdestruct': 'Conditional self-destruct',
            'fee_storage_manipulation': 'Dynamic fee manipulation',
            'has_pause_mechanism': 'Pausable contract',
            'hidden_owner_checks': 'Hidden ownership checks',
            'max_jumpi_before_transfer': 'Complex transfer conditions',
            'revert_to_return_ratio': 'High revert ratio',
            'computed_storage_writes': 'Computed storage manipulation',
        }
        
        for feature, description in high_risk_indicators.items():
            if feature in raw_features and raw_features[feature] > 0:
                risk_features.append((
                    feature, 
                    raw_features[feature], 
                    description
                ))
        
        # Sort by value (descending)
        risk_features.sort(key=lambda x: x[1], reverse=True)
        
        # Return top 10
        return risk_features[:10]
    
    def predict_from_address(self, address: str, chain: str = 'pulsechain') -> Dict:
        """
        Fetch bytecode from blockchain and predict
        
        Args:
            address: Contract address
            chain: 'ethereum' or 'pulsechain' (where to fetch from)
        
        Returns:
            Prediction dict with additional 'fetched_from_chain' key
        """
        print(f"Fetching bytecode for {address} from {chain}...", file=sys.stderr)
        
        # Load chain config
        try:
            with open('config.yaml', 'r') as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            return {'error': 'config.yaml not found'}
        
        if chain not in config['chains']:
            return {'error': f'Unknown chain: {chain}. Available: {list(config["chains"].keys())}'}
        
        rpc_url = config['chains'][chain]['rpc_urls'][0]
        
        try:
            result = subprocess.run(
                ['cast', 'code', address, '--rpc-url', rpc_url],
                capture_output=True,
                text=True,
                timeout=20
            )
            
            if result.returncode == 0:
                bytecode = result.stdout.strip()
                if bytecode and bytecode != '0x':
                    # Predict (chain doesn't matter - bytecode is bytecode!)
                    prediction = self.predict(bytecode)
                    prediction['fetched_from_chain'] = chain
                    prediction['address'] = address
                    prediction['bytecode_length'] = len(bytecode)
                    return prediction
                else:
                    return {'error': f'Not a contract or empty bytecode on {chain}'}
            else:
                return {'error': f'Failed to fetch bytecode: {result.stderr}'}
        
        except subprocess.TimeoutExpired:
            return {'error': f'Timeout fetching bytecode from {chain} RPC'}
        except FileNotFoundError:
            return {'error': 'cast command not found. Install Foundry: https://getfoundry.sh'}
        except Exception as e:
            return {'error': f'Error: {str(e)}'}


def format_output(result: Dict, format: str = 'human') -> str:
    """Format prediction result for output"""
    
    if 'error' in result:
        if format == 'json' or format == 'json-compact':
            return json.dumps({'error': result['error']})
        else:
            return f"Error: {result['error']}"
    
    if format == 'json':
        return json.dumps(result, indent=2)
    
    elif format == 'json-compact':
        return json.dumps(result)
    
    elif format == 'score-only':
        # For bash script integration: just return risk score
        return str(result['risk_score'])
    
    elif format == 'bash':
        # Bash-friendly format: KEY=VALUE
        output = []
        output.append(f"ML_RISK_SCORE={result['risk_score']}")
        output.append(f"ML_RISK_LEVEL={result['risk_level']}")
        output.append(f"ML_IS_HONEYPOT={int(result['is_honeypot'])}")
        output.append(f"ML_CONFIDENCE={result['confidence']:.4f}")
        if 'fetched_from_chain' in result:
            output.append(f"ML_CHAIN={result['fetched_from_chain']}")
        return '\n'.join(output)
    
    else:  # human-readable
        lines = []
        lines.append("\n" + "="*62)
        lines.append("  ML HONEYPOT DETECTION RESULTS")
        lines.append("="*62)
        
        # Address and chain info
        if 'address' in result:
            lines.append(f"\nContract: {result['address']}")
        if 'fetched_from_chain' in result:
            chain_name = result['fetched_from_chain'].upper()
            lines.append(f"Chain: {chain_name}")
        if 'bytecode_length' in result:
            lines.append(f"Bytecode Size: {result['bytecode_length']} bytes")
        
        # Risk assessment
        risk_level = result['risk_level']
        risk_score = result['risk_score']
        
        if risk_level == 'CRITICAL':
            color = '\033[0;31m'  # Red
            symbol = '⛔'
        elif risk_level == 'HIGH':
            color = '\033[1;31m'  # Bright red
            symbol = '⚠️ '
        elif risk_level == 'MEDIUM':
            color = '\033[1;33m'  # Yellow
            symbol = '⚠️ '
        elif risk_level == 'LOW':
            color = '\033[0;36m'  # Cyan
            symbol = 'ℹ️ '
        else:
            color = '\033[0;32m'  # Green
            symbol = '✓'
        
        nc = '\033[0m'  # No color
        
        lines.append("\n" + "-"*62)
        lines.append(f"{color}Risk Level: {symbol} {risk_level}{nc}")
        lines.append(f"{color}Risk Score: {risk_score}/100{nc}")
        lines.append("-"*62)
        
        lines.append(f"\nConfidence: {result['confidence']:.1%}")
        lines.append(f"Honeypot Probability: {result['honeypot_probability']:.1%}")
        lines.append(f"Safe Probability: {result['safe_probability']:.1%}")
        
        # Model performance
        if result['model_metrics']['test_accuracy'] != 'N/A':
            lines.append(f"\nModel Performance:")
            lines.append(f"  Test Accuracy: {result['model_metrics']['test_accuracy']:.1%}")
            lines.append(f"  ROC AUC: {result['model_metrics']['roc_auc']:.3f}")
        
        # Risk features
        if result['top_risk_features']:
            lines.append("\n" + "="*62)
            lines.append("TOP RISK INDICATORS")
            lines.append("="*62)
            for i, (feature, value, description) in enumerate(result['top_risk_features'], 1):
                lines.append(f"\n{i}. {description}")
                lines.append(f"   ({feature} = {value})")
        else:
            lines.append("\n✓ No significant risk indicators detected")
        
        lines.append("\n" + "="*62)
        
        # Verdict
        if result['is_honeypot']:
            lines.append(f"{color}VERDICT: LIKELY HONEYPOT - HIGH RISK{nc}")
            lines.append("="*62)
            lines.append("\n⚠️  The ML model predicts this contract is likely a honeypot.")
            lines.append("⚠️  DO NOT interact with this contract.")
            lines.append("⚠️  DO NOT buy this token.")
        elif risk_score >= 40:
            lines.append(f"{color}VERDICT: SUSPICIOUS - CAUTION ADVISED{nc}")
            lines.append("="*62)
            lines.append("\n⚠️  The model detected concerning patterns.")
            lines.append("⚠️  Verify source code before interacting.")
            lines.append("⚠️  Test with tiny amounts if you proceed.")
        else:
            lines.append(f"{color}VERDICT: APPEARS SAFE{nc}")
            lines.append("="*62)
            lines.append("\n✓ The model did not detect significant honeypot patterns.")
            lines.append("ℹ️  However, always verify source code.")
            lines.append("ℹ️  Test with small amounts first.")
            lines.append("ℹ️  This is not financial advice - DYOR!")
        
        lines.append("\n" + "="*62 + "\n")
        
        return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='ML-based honeypot detection for smart contracts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze PulseChain contract (default)
  %(prog)s 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
  
  # Analyze Ethereum contract
  %(prog)s 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --chain ethereum
  
  # Analyze bytecode directly (chain-agnostic)
  %(prog)s --bytecode 0x6080604052...
  
  # JSON output for automation
  %(prog)s 0x... --format json
  
  # Bash script integration
  eval $(%(prog)s 0x... --format bash)
  echo "Risk score: $ML_RISK_SCORE"
  if [ "$ML_IS_HONEYPOT" -eq 1 ]; then
      echo "HONEYPOT DETECTED!"
  fi
  
  # Just get risk score (0-100)
  %(prog)s 0x... --format score-only
  
  # Quiet mode (no stderr)
  %(prog)s 0x... --quiet
        """
    )
    
    parser.add_argument('address', nargs='?', help='Contract address to analyze')
    parser.add_argument('--bytecode', help='Analyze bytecode directly (no RPC call)')
    parser.add_argument('--chain', choices=['ethereum', 'pulsechain'],
                       default='pulsechain',
                       help='Blockchain to fetch contract from (default: pulsechain)')
    parser.add_argument('--model', default='./data/models/honeypot_detector.pkl',
                       help='Path to model file (default: ./data/models/honeypot_detector.pkl)')
    parser.add_argument('--format', choices=['human', 'json', 'json-compact', 'bash', 'score-only'],
                       default='human', 
                       help='Output format (default: human)')
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress stderr output (progress messages)')
    
    args = parser.parse_args()
    
    # Suppress stderr if quiet
    if args.quiet:
        sys.stderr = open('/dev/null', 'w')
    
    # Validate input
    if not args.address and not args.bytecode:
        parser.print_help()
        sys.exit(1)
    
    try:
        # Load predictor
        predictor = HoneypotPredictor(args.model)
        
        # Make prediction
        if args.bytecode:
            result = predictor.predict(args.bytecode)
        else:
            result = predictor.predict_from_address(args.address, args.chain)
        
        # Output result
        output = format_output(result, args.format)
        print(output)
        
        # Exit code based on result
        if 'error' in result:
            sys.exit(2)  # Error
        elif result.get('risk_score', 0) >= 60:
            sys.exit(1)  # High risk
        else:
            sys.exit(0)  # Safe or low risk
    
    except FileNotFoundError as e:
        if 'honeypot_detector.pkl' in str(e):
            print(f"Error: Model file not found: {args.model}", file=sys.stderr)
            print("Train a model first: python3 src/train.py", file=sys.stderr)
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()