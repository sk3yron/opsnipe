#!/usr/bin/env python3
"""
Model Training Module
Train ML models for honeypot detection (Multi-Chain Support)
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

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

from feature_extraction import OpcodeFeatureExtractor, FeatureEngineering
from data_collection import MultiChainDataCollector, ContractSample


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
        """Load raw data and extract features from merged multi-chain dataset"""
        print("\n" + "="*60)
        print("LOADING AND PROCESSING DATA")
        print("="*60)
        
        # Use MERGED dataset (contains both chains)
        raw_data_path = self.config['data'].get('raw_data_merged', './data/raw/contracts_merged.json')
        
        if not Path(raw_data_path).exists():
            print(f"\n❌ Merged dataset not found at {raw_data_path}")
            print("\nTo create merged dataset, run:")
            print("  python3 src/data_collection.py --both")
            print("\nOr merge existing datasets:")
            print("  python3 src/data_collection.py --merge-only")
            raise FileNotFoundError(f"Merged dataset not found: {raw_data_path}")
        
        print(f"\n📂 Loading from: {raw_data_path}")
        
        with open(raw_data_path, 'r') as f:
            data = json.load(f)
        
        # Validate merged dataset
        if data['metadata'].get('type') != 'multi_chain_merged':
            print(f"\n⚠️  Warning: Dataset type is '{data['metadata'].get('type')}', expected 'multi_chain_merged'")
        
        samples = data['samples']
        metadata = data['metadata']
        
        print(f"\n✓ Loaded {len(samples)} samples")
        print(f"  Chains: {', '.join(metadata.get('chains', ['unknown']))}")
        print(f"  Merge date: {metadata.get('merge_date', 'unknown')}")
        
        # Display chain breakdown
        if 'chain_breakdown' in metadata:
            print("\n" + "-"*60)
            print("CHAIN BREAKDOWN")
            print("-"*60)
            for chain, stats in metadata['chain_breakdown'].items():
                print(f"\n{chain.upper()}:")
                print(f"  Total samples: {stats['total']}")
                print(f"  Safe contracts: {stats['safe']}")
                print(f"  Honeypots: {stats['honeypot']}")
        
        print("\n" + "-"*60)
        print(f"COMBINED DATASET")
        print("-"*60)
        print(f"  Total samples: {metadata['total_samples']}")
        print(f"  Safe contracts: {metadata['safe_count']}")
        print(f"  Honeypots: {metadata['honeypot_count']}")
        if 'duplicate_addresses' in metadata:
            print(f"  Duplicate addresses across chains: {metadata['duplicate_addresses']}")
        
        # Check for sufficient data
        if len(samples) < 20:
            print(f"\n⚠️  WARNING: Only {len(samples)} samples. Need at least 20 for training.")
            print("   Add more contracts using:")
            print("   python3 src/data_collection.py --chain [ethereum|pulsechain] --add-safe/--add-honeypot 0x... 'Name'")
        
        if metadata['safe_count'] < 5 or metadata['honeypot_count'] < 5:
            print(f"\n⚠️  WARNING: Imbalanced dataset!")
            print(f"   Safe: {metadata['safe_count']}, Honeypot: {metadata['honeypot_count']}")
            print("   Need at least 5 of each class for meaningful training.")
        
        # Extract features (chain-agnostic - bytecode is bytecode!)
        print("\n" + "="*60)
        print("EXTRACTING FEATURES FROM BYTECODE")
        print("="*60)
        print("(This may take a few minutes...)\n")
        
        features_list = []
        labels = []
        sample_metadata = []
        
        from tqdm import tqdm
        for sample in tqdm(samples, desc="Processing contracts"):
            try:
                features = self.feature_extractor.extract_all_features(sample['bytecode'])
                features_list.append(features)
                labels.append(sample['label'])
                
                # Keep metadata for analysis
                sample_metadata.append({
                    'address': sample['address'],
                    'chain': sample['chain'],
                    'name': sample.get('name', 'Unknown'),
                    'bytecode_hash': sample.get('bytecode_hash', 'N/A')
                })
            except Exception as e:
                print(f"\n⚠️  Error processing {sample['address']} ({sample['chain']}): {e}")
                continue
        
        if not features_list:
            raise ValueError("No features extracted! Check your bytecode data.")
        
        print(f"\n✓ Successfully extracted features from {len(features_list)}/{len(samples)} contracts")
        
        # Create DataFrame
        df = pd.DataFrame(features_list)
        y = pd.Series(labels)
        
        # Add metadata columns (for tracking, not for training)
        df['_chain'] = [m['chain'] for m in sample_metadata]
        df['_address'] = [m['address'] for m in sample_metadata]
        df['_name'] = [m['name'] for m in sample_metadata]
        
        print(f"\n✓ Created feature matrix: {df.shape}")
        print(f"  Features extracted: {len(df.columns) - 3}")  # -3 for metadata columns
        
        # Feature engineering
        print("\n" + "-"*60)
        print("FEATURE ENGINEERING")
        print("-"*60)
        
        print("  • Creating interaction features...")
        df = FeatureEngineering.create_interaction_features(df)
        
        print("  • Creating ratio features...")
        df = FeatureEngineering.create_ratio_features(df)
        
        print(f"  ✓ Total features after engineering: {len(df.columns) - 3}")
        
        # Handle missing values
        missing_count = df.isnull().sum().sum()
        if missing_count > 0:
            print(f"\n  Filling {missing_count} missing values with 0...")
            df = df.fillna(0)
        
        # Handle infinite values
        inf_count = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
        if inf_count > 0:
            print(f"  Replacing {inf_count} infinite values...")
            df = df.replace([np.inf, -np.inf], 0)
        
        # Save processed data
        processed_path = self.config['data']['processed_data_path']
        Path(processed_path).parent.mkdir(parents=True, exist_ok=True)
        
        df['label'] = y
        df.to_csv(processed_path, index=False)
        print(f"\n✓ Processed data saved to {processed_path}")
        
        # Remove metadata columns before training
        metadata_cols = ['label', '_chain', '_address', '_name']
        existing_metadata_cols = [col for col in metadata_cols if col in df.columns]
        df_features = df.drop(existing_metadata_cols, axis=1)
        
        self.feature_names = df_features.columns.tolist()
        
        # Store metadata for later analysis
        self.sample_metadata = sample_metadata
        
        return df_features, y
    
    def balance_dataset(self, X: pd.DataFrame, y: pd.Series) -> Tuple[pd.DataFrame, pd.Series]:
        """Balance dataset using SMOTE"""
        print("\n" + "="*60)
        print("BALANCING DATASET")
        print("="*60)
        
        print(f"\nOriginal class distribution:")
        for label, count in y.value_counts().items():
            label_name = "Safe" if label == 0 else "Honeypot"
            print(f"  {label_name}: {count} samples ({count/len(y)*100:.1f}%)")
        
        # Check if balancing is needed
        class_counts = y.value_counts()
        minority_class = class_counts.min()
        majority_class = class_counts.max()
        imbalance_ratio = majority_class / minority_class
        
        print(f"\nImbalance ratio: {imbalance_ratio:.2f}:1")
        
        if imbalance_ratio < 1.5:
            print("  ℹ️  Dataset is fairly balanced, skipping SMOTE")
            return X, y
        
        if minority_class < 2:
            print("  ⚠️  Not enough minority samples for SMOTE, skipping balancing")
            return X, y
        
        # Use SMOTE for oversampling minority class
        try:
            smote = SMOTE(random_state=self.config['model']['random_state'], k_neighbors=min(minority_class-1, 5))
            X_balanced, y_balanced = smote.fit_resample(X, y)
            
            print(f"\n✓ Balanced using SMOTE")
            print(f"\nNew class distribution:")
            for label, count in pd.Series(y_balanced).value_counts().items():
                label_name = "Safe" if label == 0 else "Honeypot"
                print(f"  {label_name}: {count} samples ({count/len(y_balanced)*100:.1f}%)")
            
            return pd.DataFrame(X_balanced, columns=X.columns), pd.Series(y_balanced)
        
        except Exception as e:
            print(f"\n⚠️  SMOTE failed: {e}")
            print("  Continuing with original dataset...")
            return X, y
    
    def create_model(self, algorithm: str = None):
        """Create model based on config"""
        if algorithm is None:
            algorithm = self.config['model']['algorithm']
        
        print(f"\nCreating {algorithm.upper()} model...")
        
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
                random_state=self.config['model']['random_state'],
                verbose=-1
            )
        
        elif algorithm == 'random_forest':
            params = self.config['model']['random_forest']
            self.model = RandomForestClassifier(
                n_estimators=params['n_estimators'],
                max_depth=params['max_depth'],
                min_samples_split=params['min_samples_split'],
                class_weight=params['class_weight'],
                random_state=self.config['model']['random_state'],
                n_jobs=-1,
                verbose=0
            )
        
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        
        print(f"✓ {algorithm.upper()} model created")
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
        
        print(f"\nDataset split:")
        print(f"  Training set: {len(X_train)} samples ({len(X_train)/len(X)*100:.1f}%)")
        print(f"  Test set: {len(X_test)} samples ({len(X_test)/len(X)*100:.1f}%)")
        
        # Scale features
        print("\nScaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        print("  ✓ StandardScaler fitted and applied")
        
        # Train model
        print(f"\nTraining {self.config['model']['algorithm'].upper()}...")
        self.model.fit(X_train_scaled, y_train)
        print("  ✓ Model training complete")
        
        # Evaluate
        print("\n" + "="*60)
        print("EVALUATION RESULTS")
        print("="*60)
        
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        
        print(f"\nAccuracy:")
        print(f"  Training: {train_score:.1%}")
        print(f"  Test:     {test_score:.1%}")
        
        # Check for overfitting
        if train_score - test_score > 0.15:
            print(f"\n  ⚠️  Large train/test gap ({train_score-test_score:.1%}) - possible overfitting!")
            print("     Consider: reducing model complexity, adding more data, or regularization")
        
        # Cross-validation
        cv_folds = self.config['model']['cv_folds']
        print(f"\nRunning {cv_folds}-fold cross-validation...")
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=cv, scoring='f1')
        
        print(f"  F1 Score (CV):")
        print(f"    Mean: {cv_scores.mean():.1%}")
        print(f"    Std:  {cv_scores.std():.3f}")
        
        # Detailed metrics
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        print("\n" + "-"*60)
        print("CLASSIFICATION REPORT")
        print("-"*60)
        print(classification_report(y_test, y_pred, target_names=['Safe', 'Honeypot'], digits=3))
        
        print("-"*60)
        print("CONFUSION MATRIX")
        print("-"*60)
        cm = confusion_matrix(y_test, y_pred)
        print(f"\n                Predicted")
        print(f"                Safe  Honeypot")
        print(f"Actual  Safe      {cm[0][0]:>4}    {cm[0][1]:>4}")
        print(f"        Honeypot  {cm[1][0]:>4}    {cm[1][1]:>4}")
        
        print(f"\nTrue Negatives:  {cm[0][0]} (correctly identified safe)")
        print(f"False Positives: {cm[0][1]} (safe flagged as honeypot)")
        print(f"False Negatives: {cm[1][0]} (honeypot missed)")
        print(f"True Positives:  {cm[1][1]} (correctly identified honeypot)")
        
        # ROC AUC
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\n" + "-"*60)
        print(f"ROC AUC Score: {roc_auc:.4f}")
        print("-"*60)
        
        # Interpret ROC AUC
        if roc_auc >= 0.9:
            print("  🌟 Excellent discrimination!")
        elif roc_auc >= 0.8:
            print("  ✓ Good discrimination")
        elif roc_auc >= 0.7:
            print("  ℹ️  Acceptable discrimination")
        elif roc_auc >= 0.6:
            print("  ⚠️  Poor discrimination - add more training data")
        else:
            print("  ❌ Very poor - model barely better than random guessing")
        
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
        print("FEATURE IMPORTANCE ANALYSIS")
        print("="*60)
        
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            importances = np.abs(self.model.coef_[0])
        else:
            print("  ℹ️  Model doesn't support feature importance")
            return
        
        # Create importance DataFrame
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': importances
        }).sort_values('importance', ascending=False)
        
        print("\nTop 20 Most Important Features:")
        print("-"*60)
        for i, row in importance_df.head(20).iterrows():
            print(f"  {row['feature']:<40} {row['importance']:.6f}")
        
        # Save to file
        importance_path = self.config['output']['feature_importance_path']
        Path(importance_path).parent.mkdir(parents=True, exist_ok=True)
        importance_df.to_csv(importance_path, index=False)
        print(f"\n✓ Full feature importance saved to {importance_path}")
        
        self.feature_importance = importance_df
        
        return importance_df
    
    def plot_results(self, output_dir: str = "./data/models/plots"):
        """Generate visualization plots"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print("\n" + "="*60)
        print("GENERATING VISUALIZATION PLOTS")
        print("="*60)
        
        # Set style
        sns.set_style("whitegrid")
        
        # 1. Confusion Matrix
        plt.figure(figsize=(8, 6))
        cm = confusion_matrix(self.y_test, self.y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Safe', 'Honeypot'],
                    yticklabels=['Safe', 'Honeypot'],
                    cbar_kws={'label': 'Count'})
        plt.title('Confusion Matrix', fontsize=14, fontweight='bold')
        plt.ylabel('True Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        plt.savefig(output_dir / 'confusion_matrix.png', dpi=300, bbox_inches='tight')
        print(f"  ✓ confusion_matrix.png")
        plt.close()
        
        # 2. ROC Curve
        plt.figure(figsize=(8, 6))
        fpr, tpr, _ = roc_curve(self.y_test, self.y_pred_proba)
        roc_auc = roc_auc_score(self.y_test, self.y_pred_proba)
        
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.3f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12)
        plt.ylabel('True Positive Rate', fontsize=12)
        plt.title('Receiver Operating Characteristic (ROC) Curve', fontsize=14, fontweight='bold')
        plt.legend(loc="lower right", fontsize=10)
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / 'roc_curve.png', dpi=300, bbox_inches='tight')
        print(f"  ✓ roc_curve.png")
        plt.close()
        
        # 3. Precision-Recall Curve
        plt.figure(figsize=(8, 6))
        precision, recall, _ = precision_recall_curve(self.y_test, self.y_pred_proba)
        
        plt.plot(recall, precision, color='blue', lw=2)
        plt.xlabel('Recall', fontsize=12)
        plt.ylabel('Precision', fontsize=12)
        plt.title('Precision-Recall Curve', fontsize=14, fontweight='bold')
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_dir / 'precision_recall_curve.png', dpi=300, bbox_inches='tight')
        print(f"  ✓ precision_recall_curve.png")
        plt.close()
        
        # 4. Feature Importance (Top 20)
        if hasattr(self, 'feature_importance'):
            plt.figure(figsize=(10, 8))
            top_features = self.feature_importance.head(20)
            colors = plt.cm.viridis(np.linspace(0, 0.8, len(top_features)))
            plt.barh(range(len(top_features)), top_features['importance'], color=colors)
            plt.yticks(range(len(top_features)), top_features['feature'], fontsize=9)
            plt.xlabel('Importance', fontsize=12)
            plt.title('Top 20 Feature Importance', fontsize=14, fontweight='bold')
            plt.gca().invert_yaxis()
            plt.tight_layout()
            plt.savefig(output_dir / 'feature_importance.png', dpi=300, bbox_inches='tight')
            print(f"  ✓ feature_importance.png")
            plt.close()
        
        # 5. Prediction Distribution
        plt.figure(figsize=(12, 5))
        
        plt.subplot(1, 2, 1)
        plt.hist(self.y_pred_proba[self.y_test == 0], bins=30, alpha=0.7, 
                label='Safe (actual)', color='green', edgecolor='black')
        plt.hist(self.y_pred_proba[self.y_test == 1], bins=30, alpha=0.7, 
                label='Honeypot (actual)', color='red', edgecolor='black')
        plt.xlabel('Predicted Probability (Honeypot)', fontsize=11)
        plt.ylabel('Frequency', fontsize=11)
        plt.title('Prediction Distribution by True Label', fontsize=12, fontweight='bold')
        plt.legend(fontsize=10)
        plt.grid(alpha=0.3)
        
        plt.subplot(1, 2, 2)
        scatter = plt.scatter(range(len(self.y_test)), self.y_pred_proba, 
                   c=self.y_test, cmap='RdYlGn_r', alpha=0.6, s=30, edgecolors='black', linewidth=0.5)
        plt.axhline(y=0.5, color='black', linestyle='--', linewidth=1.5, label='Decision Threshold')
        plt.xlabel('Sample Index', fontsize=11)
        plt.ylabel('Predicted Probability (Honeypot)', fontsize=11)
        plt.title('Predictions vs True Labels', fontsize=12, fontweight='bold')
        cbar = plt.colorbar(scatter, label='True Label (0=Safe, 1=Honeypot)')
        plt.legend(fontsize=9)
        plt.grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(output_dir / 'prediction_distribution.png', dpi=300, bbox_inches='tight')
        print(f"  ✓ prediction_distribution.png")
        plt.close()
        
        print(f"\n✓ All plots saved to {output_dir}/")
    
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
            'version': '1.0.0',
            'algorithm': self.config['model']['algorithm'],
            'training_date': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        joblib.dump(model_data, self.model_path)
        print(f"✓ Model saved to {self.model_path}")
        print(f"  Size: {self.model_path.stat().st_size / 1024:.1f} KB")
        
        # Save metrics separately
        metrics_path = self.config['output']['metrics_path']
        Path(metrics_path).parent.mkdir(parents=True, exist_ok=True)
        with open(metrics_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"✓ Metrics saved to {metrics_path}")
        
        # Print model summary
        print("\n" + "="*60)
        print("MODEL SUMMARY")
        print("="*60)
        print(f"Algorithm: {self.config['model']['algorithm'].upper()}")
        print(f"Features: {len(self.feature_names)}")
        print(f"Training samples: {len(self.X_test) / self.config['model']['test_size']:.0f}")
        print(f"\nPerformance Metrics:")
        print(f"  Test Accuracy: {self.metrics['test_accuracy']:.1%}")
        print(f"  ROC AUC: {self.metrics['roc_auc']:.4f}")
        print(f"  F1 Score (Honeypot): {self.metrics['classification_report']['Honeypot']['f1-score']:.3f}")
        print(f"  Precision (Honeypot): {self.metrics['classification_report']['Honeypot']['precision']:.3f}")
        print(f"  Recall (Honeypot): {self.metrics['classification_report']['Honeypot']['recall']:.3f}")
        print("="*60)
    
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
        print(f"  Algorithm: {model_data.get('algorithm', 'unknown')}")
        print(f"  Training date: {model_data.get('training_date', 'unknown')}")
        print(f"  ROC AUC: {instance.metrics.get('roc_auc', 'N/A')}")
        
        return instance


def main():
    """Main training pipeline"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Train honeypot detection model on multi-chain data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train with default settings (XGBoost on merged dataset)
  %(prog)s
  
  # Try different algorithm
  %(prog)s --algorithm lightgbm
  %(prog)s --algorithm random_forest
  
  # Skip balancing for balanced datasets
  %(prog)s --no-balance
  
  # Load preprocessed features (faster)
  %(prog)s --load-processed
  
  # Skip plots (faster training)
  %(prog)s --no-plots
        """
    )
    
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    parser.add_argument('--algorithm', choices=['xgboost', 'lightgbm', 'random_forest'],
                       help='ML algorithm to use (overrides config)')
    parser.add_argument('--no-balance', action='store_true', 
                       help='Skip SMOTE dataset balancing')
    parser.add_argument('--no-plots', action='store_true',
                       help='Skip generating visualization plots')
    parser.add_argument('--load-processed', action='store_true',
                       help='Load already processed features (skip feature extraction)')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("  HONEYPOT DETECTION MODEL TRAINING")
    print("  Multi-Chain Bytecode Analysis")
    print("="*60)
    
    try:
        # Initialize trainer
        trainer = HoneypotMLTrainer(args.config)
        
        # Load and process data
        if args.load_processed:
            print("\n" + "="*60)
            print("LOADING PREPROCESSED DATA")
            print("="*60)
            processed_path = trainer.config['data']['processed_data_path']
            
            if not Path(processed_path).exists():
                print(f"\n❌ Preprocessed data not found at {processed_path}")
                print("Run without --load-processed to extract features first.")
                return
            
            df = pd.read_csv(processed_path)
            
            # Remove metadata columns if present
            metadata_cols = ['label', '_chain', '_address', '_name']
            existing_metadata = [col for col in metadata_cols if col in df.columns]
            
            if 'label' in df.columns:
                y = df['label']
                df = df.drop(existing_metadata, axis=1)
            else:
                print("❌ No 'label' column in processed data!")
                return
            
            trainer.feature_names = df.columns.tolist()
            X = df
            
            print(f"✓ Loaded {len(X)} samples with {len(X.columns)} features")
        else:
            X, y = trainer.load_and_process_data()
        
        print(f"\n" + "="*60)
        print(f"DATASET SUMMARY")
        print("="*60)
        print(f"  Shape: {X.shape}")
        print(f"  Features: {len(X.columns)}")
        print(f"  Samples: {len(X)}")
        print(f"\n  Class distribution:")
        for label, count in y.value_counts().items():
            label_name = "Safe" if label == 0 else "Honeypot"
            print(f"    {label_name}: {count} ({count/len(y)*100:.1f}%)")
        
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
        print("✅ TRAINING COMPLETE!")
        print("="*60)
        print(f"\n📦 Model saved to: {trainer.model_path}")
        print(f"\nTo use the model:")
        print(f"  # PulseChain contract")
        print(f"  python3 src/predict.py 0xYOUR_CONTRACT_ADDRESS")
        print(f"\n  # Ethereum contract")
        print(f"  python3 src/predict.py 0xYOUR_CONTRACT_ADDRESS --chain ethereum")
        print()
    
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure you've collected data first:")
        print("  python3 src/data_collection.py --both")
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())