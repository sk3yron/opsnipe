# Honeypot ML Detector

Machine learning-based smart contract honeypot detection for PulseChain and Ethereum. Analyzes bytecode to identify malicious contracts.

## Features

- 🔍 Analyzes 100+ bytecode features
- 🤖 XGBoost/LightGBM/Random Forest models
- ⚡ Fast predictions (<1 second)
- 📊 Detects common honeypot patterns
- 🔗 Direct blockchain integration

## Quick Start

### Install

```bash
# Clone and setup
git clone <repo-url>
cd honeypot-ml
chmod +x setup.sh
./setup.sh
```

### Usage

```bash
# 1. Collect training data
python3 src/data_collection.py

# 2. Train model
python3 src/train.py

# 3. Analyze a contract
python3 src/predict.py 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
```

## Example Output

```
==============================================================
ML PREDICTION RESULTS
==============================================================

Risk Level: ⚠️  HIGH
Risk Score: 72/100

Confidence: 68.0%
Honeypot Probability: 68.0%

--------------------------------------------------------------
TOP RISK INDICATORS:
--------------------------------------------------------------
  • Blacklist mechanism detected
  • Hidden ownership checks
  • Conditional transfer restrictions

VERDICT: SUSPICIOUS - CAUTION ADVISED
==============================================================
```

## Current Performance

**With default dataset (~30-50 samples):**
- ROC AUC: **0.66-0.67** (moderate discrimination)
- Accuracy: ~60-70%

⚠️ **This is a starting point!** The model improves significantly with more training data.

### What does ROC AUC 0.66 mean?

- **0.5** = Random guessing
- **0.66** = Better than random, catches some patterns
- **0.8+** = Good performance (needs 200+ quality samples)
- **0.9+** = Excellent (needs 500+ samples + feature tuning)

## Improving Model Performance

### 1. Add More Training Data (Most Important!)

```bash
# Add verified honeypots
python3 src/data_collection.py --add-honeypot 0x... "Scam Name"

# Add verified safe contracts
python3 src/data_collection.py --add-safe 0x... "Token Name"
```

**Target:** 100+ honeypots, 100+ safe contracts for ROC AUC > 0.80

### 2. Use Better Algorithms

```bash
# Try different models
python3 src/train.py --algorithm lightgbm
python3 src/train.py --algorithm random_forest
```

### 3. Tune Hyperparameters

Edit `config.yaml`:
```yaml
model:
  xgboost:
    n_estimators: 500      # More trees
    max_depth: 8           # Deeper trees
    scale_pos_weight: 5    # Adjust for imbalance
```

### 4. Verify Data Quality

```bash
# Review collected data
cat data/raw/contracts.json | jq '.metadata'

# Remove mislabeled samples
# Check feature importance
cat data/models/feature_importance.csv
```

## Project Structure

```
honeypot-ml/
├── src/
│   ├── data_collection.py    # Collect contract data
│   ├── feature_extraction.py # Extract bytecode features
│   ├── train.py             # Train ML model
│   ├── predict.py           # Make predictions
│   └── evaluate.py          # Test model
├── data/
│   ├── raw/                 # Training data
│   ├── models/              # Trained models
│   └── cache/
├── config.yaml              # Settings
└── requirements.txt
```

## Detected Patterns

- ✅ Blacklist mechanisms
- ✅ Hidden ownership checks
- ✅ Transfer restrictions
- ✅ Dynamic fee manipulation
- ✅ Delegatecall exploits
- ✅ Broken ERC20 implementations
- ✅ Selfdestruct traps
- ⚠️ Novel patterns (requires more data)

## Command Options

### Prediction Formats

```bash
# Human-readable (default)
python3 src/predict.py 0x...

# JSON output
python3 src/predict.py 0x... --format json

# Just the risk score
python3 src/predict.py 0x... --format score-only

# Bash integration
eval $(python3 src/predict.py 0x... --format bash)
echo $ML_RISK_SCORE
```

### Training Options

```bash
# Use different algorithm
python3 src/train.py --algorithm lightgbm

# Skip plots (faster)
python3 src/train.py --no-plots
```

### Data Collection

```bash
# Add safe contract
python3 src/data_collection.py --add-safe 0x... "Token Name"

# Add honeypot
python3 src/data_collection.py --add-honeypot 0x... "Scam Name"
```

## Integration

### Python

```python
from predict import HoneypotPredictor

predictor = HoneypotPredictor()
result = predictor.predict_from_address("0x...")

if result['risk_score'] > 70:  # Adjust threshold
    print(f"⚠️ Risk: {result['risk_score']}/100")
```

### Bash

```bash
RISK=$(python3 src/predict.py 0x... --format score-only)

if [ "$RISK" -gt 70 ]; then
    echo "⚠️ HIGH RISK"
fi
```

## Requirements

- Python 3.8+
- Foundry (cast command)
- 4GB RAM

## How It Works

1. **Feature Extraction**: Analyzes bytecode for dangerous opcodes, function signatures, control flow patterns
2. **Training**: Uses SMOTE for class balancing, trains ensemble models with cross-validation
3. **Prediction**: Outputs risk score (0-100) with confidence and detected patterns

## Recommended Usage

Given current model performance, use as **supplementary tool**:

```bash
# 1. Run ML prediction
python3 src/predict.py 0x...

# 2. If risk > 60, investigate further:
#    - Check source code
#    - Look for verified contract
#    - Test with tiny amounts
#    - Use other honeypot detectors

# 3. Combine with rule-based checks
# 4. Never trust a single method
```

## Troubleshooting

**Low accuracy?**
- Collect 50+ more samples per class
- Check data quality (mislabeled contracts)
- Try different algorithms

**Model not improving?**
- Review feature importance
- Add domain-specific features
- Check for data leakage

**RPC timeout?**
```yaml
# In config.yaml
collection:
  timeout: 30
```

## Performance Expectations

| Training Samples | Expected ROC AUC | Use Case |
|-----------------|------------------|----------|
| 30-50 total | 0.65-0.70 | Learning/testing |
| 100-200 total | 0.75-0.85 | Supplementary tool |
| 500+ total | 0.85-0.95 | Primary detector |
| 1000+ total | 0.90+ | Production ready |

## Disclaimer

⚠️ **Use with caution - This is a learning tool**

- Current model has **moderate accuracy**
- Always verify source code
- Test with small amounts first
- Use multiple detection methods
- New honeypot patterns emerge constantly
- Not financial advice - DYOR

**The ML model is only as good as its training data.**

## Improving Your Dataset

### Where to find honeypots:
- [Honeypot.is](https://honeypot.is)
- Failed transactions on block explorers
- Community reports on social media
- Your own testing/research

### Where to find safe contracts:
- Top tokens by market cap
- Verified projects on CoinGecko/CMC
- Major DeFi protocols
- Official token contracts

### Label carefully:
```bash
# Always verify before adding
# Check multiple sources
# Review contract code if available
# Test on testnets when possible
```

## License

MIT License

---

**Questions?** Open an issue on GitHub

**Contributing?** More training samples needed! 🙏