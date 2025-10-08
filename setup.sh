#!/usr/bin/env bash

echo "Setting up Honeypot ML System..."

# Create directory structure
echo "Creating directories..."
mkdir -p data/{raw,processed,models,cache,models/plots}
mkdir -p src
mkdir -p notebooks

# Create .gitkeep files to preserve empty directories
touch data/raw/.gitkeep
touch data/processed/.gitkeep
touch data/models/.gitkeep
touch data/cache/.gitkeep

# Check Python installation
echo -e "\nChecking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.8+"
    exit 1
fi

echo "✓ Python3 found: $(python3 --version)"

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 not found. Please install pip"
    exit 1
fi

echo "✓ pip3 found"

# Install Python dependencies
if [ -f "requirements.txt" ]; then
    echo -e "\nInstalling Python dependencies..."
    pip3 install -r requirements.txt --user
    echo "✓ Dependencies installed"
else
    echo "⚠️  requirements.txt not found, skipping dependency installation"
fi

# Check for Foundry (cast)
if ! command -v cast &> /dev/null; then
    echo -e "\n⚠️  Foundry (cast) not found"
    echo "   For data collection, install Foundry:"
    echo "   curl -L https://foundry.paradigm.xyz | bash"
else
    echo "✓ Foundry (cast) found"
fi

# Create a sample config if it doesn't exist
if [ ! -f "config.yaml" ]; then
    echo -e "\n⚠️  config.yaml not found, creating default..."
    cat > config.yaml << 'EOF'
# Honeypot ML Configuration

data:
  rpc_url: "https://rpc.pulsechain.com"
  cache_dir: "./data/cache"
  raw_data_path: "./data/raw/contracts.json"
  processed_data_path: "./data/processed/features.csv"
  
collection:
  timeout: 15
  batch_size: 100
  max_retries: 3

features:
  dangerous_opcodes:
    DELEGATECALL: "F4"
    SELFDESTRUCT: "FF"
    CALLCODE: "F2"
    CREATE2: "F5"
    STATICCALL: "FA"
  
  critical_selectors:
    isBlacklisted: "FE575A87"
    isBlackListed: "0ECB93C0"
    blacklist: "59BF1ABE"
    addBlackList: "F9F92BE4"
    removeBlackList: "E4997DC5"
    transfer: "A9059CBB"
    transferFrom: "23B872DD"
    approve: "095EA7B3"
    mint: "40C10F19"
    burn: "42966C68"
    setFee: "69FE0E2D"
    pause: "8456CB59"
    unpause: "3F4BA83A"
  
  ngram_min: 2
  ngram_max: 4
  top_ngrams: 50

model:
  algorithm: "xgboost"
  test_size: 0.2
  cv_folds: 5
  random_state: 42
  
  xgboost:
    n_estimators: 300
    max_depth: 6
    learning_rate: 0.05
    subsample: 0.8
    colsample_bytree: 0.8
    scale_pos_weight: 3
  
  random_forest:
    n_estimators: 200
    max_depth: 10
    min_samples_split: 5
    class_weight: "balanced"

output:
  model_path: "./data/models/honeypot_detector.pkl"
  metrics_path: "./data/models/metrics.json"
  feature_importance_path: "./data/models/feature_importance.csv"
EOF
    echo "✓ Created default config.yaml"
fi

echo -e "\n============================================"
echo "✓ Setup complete!"
echo "============================================"
echo -e "\nNext steps:"
echo "  1. Collect training data:"
echo "     python3 src/data_collection.py"
echo ""
echo "  2. Train model:"
echo "     python3 src/train.py"
echo ""
echo "  3. Make predictions:"
echo "     python3 src/predict.py <address>"
echo ""