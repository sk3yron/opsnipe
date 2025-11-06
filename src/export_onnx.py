import joblib
import numpy as np
from pathlib import Path
import json
import sys

def export_model_to_onnx(
    model_path: str = "./data/models/honeypot_detector.pkl",
    output_dir: str = "./data/models/onnx"
):
    """Export model to ONNX format"""
    
    print("="*60)
    print("EXPORTING MODEL TO ONNX")
    print("="*60)
    
    # Check if model exists
    if not Path(model_path).exists():
        print(f"\n❌ Model not found at {model_path}")
        print("Train the model first: python3 src/train.py")
        sys.exit(1)
    
    print(f"\n📂 Loading model from {model_path}...")
    model_data = joblib.load(model_path)
    
    xgb_model = model_data['model']
    scaler = model_data['scaler']
    feature_names = model_data['feature_names']
    
    print(f"✓ Model loaded")
    print(f"  Features: {len(feature_names)}")
    print(f"  Model type: {model_data.get('algorithm', 'unknown')}")
    
    # Install dependencies if needed
    try:
        import onnx
        import onnxmltools
        from onnxmltools.convert.common.data_types import FloatTensorType  # Use onnxmltools version
        from skl2onnx import convert_sklearn
    except ImportError:
        print("\n❌ Missing dependencies. Install with:")
        print("   pip install onnx onnxmltools skl2onnx")
        sys.exit(1)
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    n_features = len(feature_names)
    initial_type = [('float_input', FloatTensorType([None, n_features]))]
    
    # Export XGBoost model
    print("\n🔄 Exporting XGBoost model to ONNX...")
    try:
        onnx_model = onnxmltools.convert_xgboost(
            xgb_model,
            initial_types=initial_type,
            target_opset=12
        )
        
        model_onnx_path = output_dir / "honeypot_model.onnx"
        with open(model_onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        
        print(f"✓ Model: {model_onnx_path} ({model_onnx_path.stat().st_size / 1024:.1f} KB)")
    except Exception as e:
        print(f"❌ Failed to export XGBoost model: {e}")
        sys.exit(1)
    
    # Export StandardScaler - use skl2onnx's FloatTensorType for sklearn models
    print("\n🔄 Exporting StandardScaler to ONNX...")
    try:
        from skl2onnx.common.data_types import FloatTensorType as SklearnFloatTensorType
        
        scaler_initial_type = [('float_input', SklearnFloatTensorType([None, n_features]))]
        
        scaler_onnx = convert_sklearn(
            scaler,
            initial_types=scaler_initial_type,
            target_opset=12
        )
        
        scaler_onnx_path = output_dir / "scaler.onnx"
        with open(scaler_onnx_path, "wb") as f:
            f.write(scaler_onnx.SerializeToString())
        
        print(f"✓ Scaler: {scaler_onnx_path} ({scaler_onnx_path.stat().st_size / 1024:.1f} KB)")
    except Exception as e:
        print(f"❌ Failed to export scaler: {e}")
        sys.exit(1)
    
    # Export metadata
    print("\n🔄 Exporting metadata...")
    metadata = {
        'feature_names': feature_names,
        'n_features': n_features,
        'model_type': model_data.get('algorithm', 'xgboost'),
        'version': model_data.get('version', '1.0.0'),
        'training_date': model_data.get('training_date', 'unknown'),
        'metrics': {
            'test_accuracy': float(model_data.get('metrics', {}).get('test_accuracy', 0)) if isinstance(model_data.get('metrics', {}).get('test_accuracy'), (int, float)) else str(model_data.get('metrics', {}).get('test_accuracy', 'N/A')),
            'roc_auc': float(model_data.get('metrics', {}).get('roc_auc', 0)) if isinstance(model_data.get('metrics', {}).get('roc_auc'), (int, float)) else str(model_data.get('metrics', {}).get('roc_auc', 'N/A')),
        }
    }
    
    metadata_path = output_dir / "model_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"✓ Metadata: {metadata_path}")
    
    # Export feature importance for reference
    if 'feature_importance' in model_data and model_data['feature_importance']:
        import pandas as pd
        importance_df = pd.DataFrame(model_data['feature_importance'])
        importance_path = output_dir / "feature_importance.csv"
        importance_df.to_csv(importance_path, index=False)
        print(f"✓ Feature importance: {importance_path}")
    
    print("\n" + "="*60)
    print("✅ EXPORT COMPLETE")
    print("="*60)
    print(f"\nFiles created in {output_dir}:")
    for file in output_dir.glob("*"):
        size_kb = file.stat().st_size / 1024
        print(f"  • {file.name:<25} ({size_kb:>8.1f} KB)")
    
    print(f"\n📋 Next steps:")
    print(f"  1. Copy files to Rust project:")
    print(f"     cp {output_dir}/* ~/projects/honeypot-detector/models/")
    print(f"  2. Build with ML support:")
    print(f"     cd ~/projects/honeypot-detector")
    print(f"     cargo build --release --features ml-inference")
    print("="*60 + "\n")


if __name__ == "__main__":
    export_model_to_onnx()