#!/usr/bin/env python3
"""
Model Evaluation and Testing
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
import argparse

from train import HoneypotMLTrainer
from predict import HoneypotPredictor
from data_collection import DataCollector


def evaluate_on_test_set(predictor: HoneypotPredictor, test_data_path: str):
    """Evaluate model on a test set"""
    
    print("="*60)
    print("EVALUATING ON TEST SET")
    print("="*60)
    
    # Load test data
    collector = DataCollector()
    samples = collector.load_dataset(test_data_path)
    
    results = []
    correct = 0
    total = 0
    
    print(f"\nTesting on {len(samples)} contracts...")
    
    from tqdm import tqdm
    for sample in tqdm(samples):
        prediction = predictor.predict(sample.bytecode)
        
        is_correct = (prediction['is_honeypot'] == bool(sample.label))
        
        results.append({
            'address': sample.address,
            'true_label': sample.label,
            'predicted_label': int(prediction['is_honeypot']),
            'risk_score': prediction['risk_score'],
            'confidence': prediction['confidence'],
            'correct': is_correct
        })
        
        if is_correct:
            correct += 1
        total += 1
    
    # Calculate metrics
    accuracy = correct / total
    
    df = pd.DataFrame(results)
    
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print(f"\nAccuracy: {accuracy:.2%} ({correct}/{total})")
    
    # Per-class accuracy
    for label in [0, 1]:
        label_name = "Safe" if label == 0 else "Honeypot"
        subset = df[df['true_label'] == label]
        if len(subset) > 0:
            class_acc = subset['correct'].mean()
            print(f"{label_name} Accuracy: {class_acc:.2%} ({subset['correct'].sum()}/{len(subset)})")
    
    # Misclassifications
    misclassified = df[~df['correct']]
    if len(misclassified) > 0:
        print(f"\n{len(misclassified)} Misclassifications:")
        for _, row in misclassified.iterrows():
            true_label = "Safe" if row['true_label'] == 0 else "Honeypot"
            pred_label = "Safe" if row['predicted_label'] == 0 else "Honeypot"
            print(f"  {row['address']}: True={true_label}, Predicted={pred_label} (score={row['risk_score']})")
    
    return df


def compare_with_baseline(bytecode: str):
    """Compare ML predictions with rule-based baseline"""
    
    # Your bash script logic as baseline
    # This is a simplified version
    baseline_score = 0
    
    code = bytecode.replace('0x', '').upper()
    
    # Critical patterns from bash script
    if 'FE575A87' in code or '0ECB93C0' in code:  # Blacklist
        baseline_score += 60
    
    if 'A9059CBB' not in code:  # Missing transfer
        baseline_score += 70
    
    if '095EA7B3' in code and '23B872DD' not in code:  # Approve without transferFrom
        baseline_score += 80
    
    # ML prediction
    predictor = HoneypotPredictor()
    ml_result = predictor.predict(bytecode)
    
    print("\n" + "="*60)
    print("BASELINE vs ML COMPARISON")
    print("="*60)
    print(f"\nRule-based (Bash) Score: {baseline_score}/100")
    print(f"ML Model Score: {ml_result['risk_score']}/100")
    print(f"\nDifference: {abs(baseline_score - ml_result['risk_score'])} points")
    
    if ml_result['risk_score'] > baseline_score:
        print("\nML detected additional risk factors:")
        for feature, value, desc in ml_result['top_risk_features'][:5]:
            print(f"  • {desc}")
    elif baseline_score > ml_result['risk_score']:
        print("\nRule-based system is more conservative")
    else:
        print("\nBoth systems agree on risk level")


def main():
    parser = argparse.ArgumentParser(description='Evaluate honeypot detection model')
    parser.add_argument('--test-data', help='Path to test dataset JSON')
    parser.add_argument('--compare', help='Compare baseline vs ML on bytecode')
    parser.add_argument('--model', default='./data/models/honeypot_detector.pkl')
    
    args = parser.parse_args()
    
    if args.test_data:
        predictor = HoneypotPredictor(args.model)
        results = evaluate_on_test_set(predictor, args.test_data)
        
        # Save results
        output_path = Path("./data/models/evaluation_results.csv")
        results.to_csv(output_path, index=False)
        print(f"\n✓ Results saved to {output_path}")
    
    elif args.compare:
        compare_with_baseline(args.compare)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()