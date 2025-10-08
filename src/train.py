#!/usr/bin/env python3
"""
Model Training Module
Train ML models for honeypot detection
"""

import json
import yaml
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Tuple, Any
import joblib

from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, roc_curve, f1_score
)
from sklearn.ensemble import RandomForestClassifier

import xgboost as xgb
import lightgbm as lgb
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline as ImbPipeline

import matplotlib.pyplot as plt
import seaborn as sns

from feature_extraction import OpcodeFeatureExtractor, FeatureEngineering
from data_collection import DataCollector


class HoneypotMLTrainer:
    """Train and evaluate honeypot detection models"""
    
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.feature_extractor = OpcodeFeatureExtractor(config_path)
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = None
        self.metrics = {}
        
        # Setup paths
        self.model_path = Path(self.config['output']['model_path'])
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
    
    def load_and_process_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Load raw data and extract features"""
        print("Loading raw data...")
        raw_data_path = self.config['data']['raw_data_path']
        
        with open(raw_data_path, 'r') as f:
            data = json.load(f)
        
        samples = data['samples']
        print(f"Loaded {len(samples)} samples")
        
        # Extract features
        print("\nExtracting features...")
        features_list = []
        labels = []
        
        from tqdm import tqdm
        for sample in tqdm(samples):
            try:
                features = self.feature_extractor.extract_all_features(sample['bytecode'])
                features_list.append(features)
                labels.append(sample['label'])
            except Exception as e:
                print(f"Error processing {sample['address']}: {e}")
        
        # Create DataFrame
        df = pd.DataFrame(features_list)
        y = pd.Series(labels)
        
        # Feature engineering
        print("\nEngineering additional features...")
        df = FeatureEngineering.create_interaction_features(df)
        df = FeatureEngineering.create_ratio_features(df)
        
        # Handle missing values
        df = df.fillna(0)
        
        # Save processed data
        processed_path = self.config['data']['processed_data_path']
        df['label'] = y
        df.to_csv(processed_path, index=False)
        print(f"✓ Processed data saved to {processed_path}")
        
        self.feature_names = df.drop('label', axis=1).columns.tolist()
        
        return df.drop('label', axis=1), y
    
    def balance_dataset(self, X: pd.DataFrame, y: pd.Series) -> Tuple[pd.DataFrame, pd.Series]:
        """Balance dataset using SMOTE"""
        print("\nBalancing dataset...")
        print(f"Original class distribution:\n{y.value_counts()}")
        
        # Use SMOTE for oversampling minority class
        smote = SMOTE(random_state=self.config['model']['random_state'])
        X_balanced, y_balanced = smote.fit_resample(X, y)
        
        print(f"Balanced class distribution:\n{pd.Series(y_balanced).value_counts()}")
        
        return pd.DataFrame(X_balanced, columns=X.columns), pd.Series(y_balanced)
    
    def create_model(self, algorithm: str = None):
        """Create model based on config"""
        if algorithm is None:
            algorithm = self.config['model']['algorithm']
        
        print(f"\nCreating {algorithm} model...")
        
        if algorithm == 'xgboost':
            params = self.config['model']['xgboost']
            self.model = xgb.XGBClassifier(
                n_estimators=params['n_estimators'],
                max_depth=params['max_depth'],
                learning_rate=params['learning_rate'],
                subsample=params['subsample'],
                colsample_bytree=params['colsample_bytree'],
                scale_pos_weight=params['scale_pos_weight'],
                random_state=self.config['model']['random_state'],
                use_label_encoder=False,
                eval_metric='logloss'
            )
        
        elif algorithm == 'lightgbm':
            self.model = lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.05,
                class_weight='balanced',
                random_state=self.config['model']['random_state']
            )
        
        elif algorithm == 'random_forest':
            params = self.config['model']['random_forest']
            self.model = RandomForestClassifier(
                n_estimators=params['n_estimators'],
                max_depth=params['max_depth'],
                min_samples_split=params['min_samples_split'],
                class_weight=params['class_weight'],
                random_state=self.config['model']['random_state'],
                n_jobs=-1
            )
        
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        return self.model
    
    def train(self, X: pd.DataFrame, y: pd.Series):
        """Train the model"""
        print("\n" + "="*60)
        print("TRAINING MODEL")
        print("="*60)
        
        # Split data
        test_size = self.config['model']['test_size']
        random_state = self.config['model']['random_state']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"\nTrain set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Scale features
        print("\nScaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        print(f"\nTraining {self.config['model']['algorithm']}...")
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        print("\n" + "="*60)
        print("EVALUATION")
        print("="*60)
        
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        
        print(f"\nAccuracy:")
        print(f"  Train: {train_score:.4f}")
        print(f"  Test:  {test_score:.4f}")
        
        # Cross-validation
        cv_folds = self.config['model']['cv_folds']
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=cv, scoring='f1')
        
        print(f"\nCross-Validation F1 Score:")
        print(f"  Mean: {cv_scores.mean():.4f}")
        print(f"  Std:  {cv_scores.std():.4f}")
        
        # Detailed metrics
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        print("\n" + "-"*60)
        print("Classification Report:")
        print("-"*60)
        print(classification_report(y_test, y_pred, target_names=['Safe', 'Honeypot']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        print(f"\nTrue Negatives:  {cm[0][0]}")
        print(f"False Positives: {cm[0][1]}")
        print(f"False Negatives: {cm[1][0]}")
        print(f"True Positives:  {cm[1][1]}")
        
        # ROC AUC
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC AUC Score: {roc_auc:.4f}")
        
        # Store metrics
        self.metrics = {
            'train_accuracy': float(train_score),
            'test_accuracy': float(test_score),
            'cv_f1_mean': float(cv_scores.mean()),
            'cv_f1_std': float(cv_scores.std()),
            'roc_auc': float(roc_auc),
            'confusion_matrix': cm.tolist(),
            'classification_report': classification_report(
                                y_test, y_pred, target_names=['Safe', 'Honeypot'], output_dict=True
            )
        }
        
        # Feature importance
        self.analyze_feature_importance(X.columns)
        
        # Save test set for later analysis
        self.X_test = X_test
        self.y_test = y_test
        self.y_pred = y_pred
        self.y_pred_proba = y_pred_proba
        
        return self.model
    
    def analyze_feature_importance(self, feature_names):
        """Analyze and display feature importance"""
        print("\n" + "="*60)
        print("FEATURE IMPORTANCE")
        print("="*60)
        
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            importances = np.abs(self.model.coef_[0])
        else:
            print("Model doesn't support feature importance")
            return
        
        # Create importance DataFrame
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\nTop 20 Most Important Features:")
        print(importance_df.head(20).to_string(index=False))
        
        # Save to file
        importance_path = self.config['output']['feature_importance_path']
        importance_df.to_csv(importance_path, index=False)
        print(f"\n✓ Feature importance saved to {importance_path}")
        
        self.feature_importance = importance_df
        
        return importance_df
    
    def plot_results(self, output_dir: str = "./data/models/plots"):
        """Generate visualization plots"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print("\n" + "="*60)
        print("GENERATING PLOTS")
        print("="*60)
        
        # 1. Confusion Matrix
        plt.figure(figsize=(8, 6))
        cm = confusion_matrix(self.y_test, self.y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Safe', 'Honeypot'],
                    yticklabels=['Safe', 'Honeypot'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(output_dir / 'confusion_matrix.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved confusion_matrix.png")
        plt.close()
        
        # 2. ROC Curve
        plt.figure(figsize=(8, 6))
        fpr, tpr, _ = roc_curve(self.y_test, self.y_pred_proba)
        roc_auc = roc_auc_score(self.y_test, self.y_pred_proba)
        
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.3f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / 'roc_curve.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved roc_curve.png")
        plt.close()
        
        # 3. Precision-Recall Curve
        plt.figure(figsize=(8, 6))
        precision, recall, _ = precision_recall_curve(self.y_test, self.y_pred_proba)
        
        plt.plot(recall, precision, color='blue', lw=2)
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / 'precision_recall_curve.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved precision_recall_curve.png")
        plt.close()
        
        # 4. Feature Importance (Top 20)
        if hasattr(self, 'feature_importance'):
            plt.figure(figsize=(10, 8))
            top_features = self.feature_importance.head(20)
            plt.barh(range(len(top_features)), top_features['importance'])
            plt.yticks(range(len(top_features)), top_features['feature'])
            plt.xlabel('Importance')
            plt.title('Top 20 Feature Importance')
            plt.gca().invert_yaxis()
            plt.tight_layout()
            plt.savefig(output_dir / 'feature_importance.png', dpi=300, bbox_inches='tight')
            print(f"✓ Saved feature_importance.png")
            plt.close()
        
        # 5. Prediction Distribution
        plt.figure(figsize=(10, 5))
        
        plt.subplot(1, 2, 1)
        plt.hist(self.y_pred_proba[self.y_test == 0], bins=30, alpha=0.7, 
                label='Safe (actual)', color='green')
        plt.hist(self.y_pred_proba[self.y_test == 1], bins=30, alpha=0.7, 
                label='Honeypot (actual)', color='red')
        plt.xlabel('Predicted Probability (Honeypot)')
        plt.ylabel('Frequency')
        plt.title('Prediction Distribution by True Label')
        plt.legend()
        plt.grid(alpha=0.3)
        
        plt.subplot(1, 2, 2)
        plt.scatter(range(len(self.y_test)), self.y_pred_proba, 
                   c=self.y_test, cmap='RdYlGn_r', alpha=0.6, s=20)
        plt.axhline(y=0.5, color='black', linestyle='--', linewidth=1)
        plt.xlabel('Sample Index')
        plt.ylabel('Predicted Probability (Honeypot)')
        plt.title('Predictions vs True Labels')
        plt.colorbar(label='True Label')
        plt.grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / 'prediction_distribution.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved prediction_distribution.png")
        plt.close()
        
        print(f"\n✓ All plots saved to {output_dir}")
    
    def save_model(self):
        """Save trained model and metadata"""
        print("\n" + "="*60)
        print("SAVING MODEL")
        print("="*60)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'feature_importance': self.feature_importance.to_dict() if hasattr(self, 'feature_importance') else None,
            'metrics': self.metrics,
            'config': self.config,
            'version': '1.0.0'
        }
        
        joblib.dump(model_data, self.model_path)
        print(f"✓ Model saved to {self.model_path}")
        
        # Save metrics separately
        metrics_path = self.config['output']['metrics_path']
        with open(metrics_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"✓ Metrics saved to {metrics_path}")
        
        # Print model summary
        print("\n" + "-"*60)
        print("MODEL SUMMARY")
        print("-"*60)
        print(f"Algorithm: {self.config['model']['algorithm']}")
        print(f"Features: {len(self.feature_names)}")
        print(f"Test Accuracy: {self.metrics['test_accuracy']:.4f}")
        print(f"ROC AUC: {self.metrics['roc_auc']:.4f}")
        print(f"F1 Score (Honeypot): {self.metrics['classification_report']['Honeypot']['f1-score']:.4f}")
        print("-"*60)
    
    @classmethod
    def load_model(cls, model_path: str):
        """Load a saved model"""
        model_data = joblib.load(model_path)
        
        instance = cls(config_path='config.yaml')
        instance.model = model_data['model']
        instance.scaler = model_data['scaler']
        instance.feature_names = model_data['feature_names']
        instance.metrics = model_data['metrics']
        
        if 'feature_importance' in model_data and model_data['feature_importance']:
            instance.feature_importance = pd.DataFrame(model_data['feature_importance'])
        
        print(f"✓ Model loaded from {model_path}")
        return instance


def main():
    """Main training pipeline"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train honeypot detection model')
    parser.add_argument('--config', default='config.yaml', help='Config file')
    parser.add_argument('--algorithm', choices=['xgboost', 'lightgbm', 'random_forest'],
                       help='Override algorithm from config')
    parser.add_argument('--no-balance', action='store_true', 
                       help='Skip dataset balancing')
    parser.add_argument('--no-plots', action='store_true',
                       help='Skip plot generation')
    parser.add_argument('--load-processed', action='store_true',
                       help='Load already processed features')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("HONEYPOT DETECTION MODEL TRAINING")
    print("="*60)
    
    # Initialize trainer
    trainer = HoneypotMLTrainer(args.config)
    
    # Load and process data
    if args.load_processed:
        print("\nLoading processed data...")
        processed_path = trainer.config['data']['processed_data_path']
        df = pd.read_csv(processed_path)
        X = df.drop('label', axis=1)
        y = df['label']
        trainer.feature_names = X.columns.tolist()
    else:
        X, y = trainer.load_and_process_data()
    
    print(f"\nDataset shape: {X.shape}")
    print(f"Features: {len(X.columns)}")
    print(f"Class distribution:\n{y.value_counts()}")
    
    # Balance dataset
    if not args.no_balance:
        X, y = trainer.balance_dataset(X, y)
    
    # Create and train model
    algorithm = args.algorithm if args.algorithm else None
    trainer.create_model(algorithm)
    trainer.train(X, y)
    
    # Generate plots
    if not args.no_plots:
        trainer.plot_results()
    
    # Save model
    trainer.save_model()
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"\nModel ready for deployment: {trainer.model_path}")
    print("\nTo use the model:")
    print("  python src/predict.py <contract_address>")
    print("\nTo integrate with bash script:")
    print("  See integration examples in predict.py")
    print()


if __name__ == "__main__":
    main()