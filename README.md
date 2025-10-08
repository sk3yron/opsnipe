```markdown
# 🕵️ Honeypot ML Detector

**Multi-chain machine learning honeypot detection for smart contracts.**  
Analyzes bytecode from **Ethereum** and **PulseChain** to identify malicious tokens before you lose funds.

---

## ✨ Features

- 🌐 **Multi-Chain Support** - Works on Ethereum AND PulseChain
- 🔍 **100+ Bytecode Features** - Deep opcode-level analysis
- 🤖 **Multiple ML Models** - XGBoost, LightGBM, Random Forest
- ⚡ **Fast Predictions** - Results in <1 second
- 📊 **Pattern Detection** - Identifies 10+ honeypot techniques
- 🔗 **Direct RPC Integration** - No API keys needed
- 🎨 **Multiple Output Formats** - Human, JSON, Bash-friendly

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- [Foundry](https://getfoundry.sh) (`cast` command)
- 4GB RAM recommended

### Installation

```bash
# Clone repository
git clone https://github.com/sk3yron/opsnipe
cd opsnipe

# Run setup script
chmod +x setup.sh
./setup.sh
```

---

## 📖 Usage

### **Step 1: Collect Training Data from Both Chains**

```bash
# Collect from BOTH Ethereum and PulseChain (recommended)
python3 src/data_collection.py --both

# Output:
# ✓ Ethereum: 8 samples collected
# ✓ PulseChain: 15 samples collected
# ✓ Merged dataset: 23 total samples
```

**Add more contracts manually:**

```bash
# Add Ethereum honeypot
python3 src/data_collection.py --chain ethereum \
    --add-honeypot 0x2e35b0b2e3e5b1b1a7a02c3b2a210515510d7a55 "MINIDOGE"

# Add PulseChain safe token
python3 src/data_collection.py --chain pulsechain \
    --add-safe 0xA1077a294dDE1B09bB078844df40758a5D0f9a27 "WPLS"

# Merge updated datasets
python3 src/data_collection.py --merge-only
```

---

### **Step 2: Train the Model**

```bash
# Train on merged dataset (both chains)
python3 src/train.py

# Output:
# ✓ Loaded 23 samples from 2 chains
# ✓ Extracted 110 features
# ✓ Model trained - ROC AUC: 0.85
```

**Try different algorithms:**

```bash
python3 src/train.py --algorithm lightgbm    # Fast, good for large datasets
python3 src/train.py --algorithm random_forest  # Good baseline
python3 src/train.py --algorithm xgboost      # Best performance (default)
```

---

### **Step 3: Analyze Contracts**

```bash
# Analyze PulseChain contract (default)
python3 src/predict.py 0xYOUR_CONTRACT_ADDRESS

# Analyze Ethereum contract
python3 src/predict.py 0xYOUR_CONTRACT_ADDRESS --chain ethereum

# Analyze bytecode directly (chain-agnostic)
python3 src/predict.py --bytecode 0x6080604052...
```

---

## 📊 Example Output

```
==============================================================
  ML HONEYPOT DETECTION RESULTS
==============================================================

Contract: 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39
Chain: PULSECHAIN
Bytecode Size: 12458 bytes

--------------------------------------------------------------
Risk Level: ⚠️  HIGH
Risk Score: 72/100
--------------------------------------------------------------

Confidence: 68.0%
Honeypot Probability: 68.0%
Safe Probability: 32.0%

==============================================================
TOP RISK INDICATORS
==============================================================

1. Blacklist mechanism detected
   (has_blacklist_functions = 1.0)

2. Hidden ownership checks
   (hidden_owner_checks = 3.0)

3. Complex transfer conditions
   (max_jumpi_before_transfer = 15.0)

==============================================================
VERDICT: SUSPICIOUS - CAUTION ADVISED
==============================================================

⚠️  The model detected concerning patterns.
⚠️  Verify source code before interacting.
⚠️  Test with tiny amounts if you proceed.

==============================================================
```

---

## 🏗️ Project Structure

```
opsnipe/
├── src/
│   ├── data_collection.py      # Multi-chain data collector
│   ├── feature_extraction.py   # Bytecode feature extraction
│   ├── train.py               # ML model training
│   ├── predict.py             # Prediction engine
│   └── evaluate.py            # Model evaluation
├── data/
│   ├── raw/
│   │   ├── contracts_ethereum.json     # Ethereum contracts
│   │   ├── contracts_pulsechain.json   # PulseChain contracts
│   │   └── contracts_merged.json       # Combined dataset
│   ├── processed/
│   │   └── features.csv               # Extracted features
│   ├── models/
│   │   ├── honeypot_detector.pkl      # Trained model
│   │   ├── metrics.json               # Performance metrics
│   │   └── plots/                     # Visualizations
│   └── cache/
├── config.yaml                # Configuration
├── requirements.txt           # Python dependencies
├── setup.sh                  # Installation script
└── README.md
```

---

## 🎯 Detected Honeypot Patterns

The model detects these malicious patterns:

| Pattern | Description | Risk Level |
|---------|-------------|-----------|
| **Blacklist Mechanism** | Can block specific wallets from selling | 🔴 Critical |
| **Hidden Owner Checks** | Transfer restrictions based on sender | 🔴 Critical |
| **Broken ERC20** | Missing or broken `transfer()`/`transferFrom()` | 🔴 Critical |
| **Dynamic Fees** | Manipulatable buy/sell taxes | 🟠 High |
| **Pausable Contract** | Owner can freeze all transfers | 🟠 High |
| **Delegatecall Exploits** | Can execute malicious code | 🔴 Critical |
| **Conditional Selfdestruct** | Contract can be destroyed | 🟠 High |
| **Computed Storage Writes** | Hidden state manipulation | 🟡 Medium |
| **High Revert Ratio** | Many failed operations | 🟡 Medium |
| **Complex Transfer Logic** | Excessive conditions before transfers | 🟠 High |

---

## 🔧 Advanced Usage

### **Multi-Chain Commands**

```bash
# Compare same address across chains
python3 src/data_collection.py --compare 0x2b591e99afE9f32eAA6214f7B7629768c40Eeb39

# Output:
# ✓ Contract exists on both chains
#    ethereum: 12458 bytes (hash: a3f5c8e9...)
#    pulsechain: 12458 bytes (hash: a3f5c8e9...)
#    ✓ Bytecode is IDENTICAL on both chains

# Verify chain connection
python3 src/data_collection.py --chain ethereum --verify

# Output:
# ✓ Connected to Ethereum Mainnet (Chain ID: 1)
```

---

### **Output Formats**

```bash
# Human-readable (default)
python3 src/predict.py 0x...

# JSON for automation
python3 src/predict.py 0x... --format json > result.json

# Compact JSON (single line)
python3 src/predict.py 0x... --format json-compact

# Just the risk score (0-100)
python3 src/predict.py 0x... --format score-only

# Bash variables
eval $(python3 src/predict.py 0x... --format bash)
echo "Risk: $ML_RISK_SCORE/100"
echo "Is Honeypot: $ML_IS_HONEYPOT"
echo "Chain: $ML_CHAIN"
```

---

### **Python Integration**

```python
from predict import HoneypotPredictor

# Initialize predictor
predictor = HoneypotPredictor()

# Analyze PulseChain contract
result = predictor.predict_from_address(
    "0xYOUR_ADDRESS",
    chain="pulsechain"
)

# Check risk
if result['risk_score'] > 70:
    print(f"🚨 HIGH RISK: {result['risk_score']}/100")
    print(f"Patterns: {result['top_risk_features']}")
else:
    print(f"✓ Low risk: {result['risk_score']}/100")

# Analyze bytecode directly
result = predictor.predict("0x6080604052...")
```

---

### **Bash Script Integration**

```bash
#!/bin/bash

# Function to check contract safety
check_contract() {
    local address=$1
    local chain=${2:-pulsechain}
    
    # Get ML prediction
    eval $(python3 src/predict.py "$address" --chain "$chain" --format bash --quiet)
    
    echo "Contract: $address"
    echo "Chain: $ML_CHAIN"
    echo "Risk Score: $ML_RISK_SCORE/100"
    echo "Risk Level: $ML_RISK_LEVEL"
    
    if [ "$ML_IS_HONEYPOT" -eq 1 ]; then
        echo "🚨 HONEYPOT DETECTED - DO NOT BUY!"
        return 1
    elif [ "$ML_RISK_SCORE" -gt 60 ]; then
        echo "⚠️  SUSPICIOUS - VERIFY BEFORE BUYING"
        return 1
    else
        echo "✓ Appears safe (but always DYOR)"
        return 0
    fi
}

# Usage
check_contract "0xYOUR_ADDRESS" "pulsechain"
```

---

## 📈 Model Performance

### **Current Performance (with default dataset)**

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **ROC AUC** | 0.66-0.70 | Moderate - catches some patterns |
| **Accuracy** | 60-70% | Better than random |
| **Training Samples** | ~30-50 | Small dataset |

⚠️ **This is a starting point!** Performance improves dramatically with more data.

### **ROC AUC Score Guide**

| Score | Meaning | Recommended Use |
|-------|---------|-----------------|
| **0.50** | Random guessing | ❌ Not usable |
| **0.60-0.70** | Weak discrimination | ⚠️ Supplementary tool only |
| **0.70-0.80** | Acceptable | ✓ Use with caution |
| **0.80-0.90** | Good | ✓ Reliable for most cases |
| **0.90+** | Excellent | ✓ Production ready |

### **Expected Performance vs Dataset Size**

| Training Samples | Expected ROC AUC | Use Case |
|-----------------|------------------|----------|
| 30-50 total | 0.65-0.70 | 🧪 Learning/testing only |
| 100-200 total | 0.75-0.85 | ⚠️ Supplementary tool |
| 500+ total | 0.85-0.95 | ✓ Primary detector |
| 1000+ total | 0.90+ | ✅ Production ready |

---

## 🔬 Improving Model Performance

### **1. Add More Training Data (MOST IMPORTANT!)**

```bash
# Target: 100+ honeypots, 100+ safe contracts

# Add Ethereum contracts
python3 src/data_collection.py --chain ethereum \
    --add-honeypot 0xSCAM_ADDRESS "Scam Name"

python3 src/data_collection.py --chain ethereum \
    --add-safe 0xLEGIT_ADDRESS "Token Name"

# Add PulseChain contracts
python3 src/data_collection.py --chain pulsechain \
    --add-honeypot 0xSCAM_ADDRESS "Scam Name"

python3 src/data_collection.py --chain pulsechain \
    --add-safe 0xLEGIT_ADDRESS "Token Name"

# Merge and retrain
python3 src/data_collection.py --merge-only
python3 src/train.py
```

**Where to find verified honeypots:**
- [Honeypot.is](https://honeypot.is) - Database of known scams
- [TokenSniffer](https://tokensniffer.com) - Token analysis
- Failed transactions on [Etherscan](https://etherscan.io) / [PulseScan](https://scan.pulsechain.com)
- Community reports on Twitter/Discord
- Your own research (ALWAYS verify!)

**Where to find safe contracts:**
- Top tokens on [CoinGecko](https://coingecko.com) / [CoinMarketCap](https://coinmarketcap.com)
- Major DeFi protocols (Uniswap, Aave, Curve, etc.)
- Verified contracts with public audits
- Official project repositories

---

### **2. Optimize Hyperparameters**

Edit `config.yaml`:

```yaml
model:
  xgboost:
    n_estimators: 500        # More trees (slower but better)
    max_depth: 8             # Deeper trees (risk overfitting)
    learning_rate: 0.03      # Smaller = slower but more accurate
    scale_pos_weight: 5      # Adjust if dataset is imbalanced
```

Then retrain:
```bash
python3 src/train.py
```

---

### **3. Validate Data Quality**

```bash
# Check dataset stats
cat data/raw/contracts_merged.json | jq '.metadata'

# Review feature importance
head -20 data/models/feature_importance.csv

# Look for mislabeled contracts
python3 src/evaluate.py --test-data data/raw/contracts_merged.json
```

---

### **4. Try Different Algorithms**

```bash
# Compare all three
python3 src/train.py --algorithm xgboost
python3 src/train.py --algorithm lightgbm
python3 src/train.py --algorithm random_forest

# Check which performed best
cat data/models/metrics.json | jq '.roc_auc'
```

---

## 🌐 Multi-Chain Configuration

The system supports multiple blockchain networks via `config.yaml`:

```yaml
chains:
  ethereum:
    name: "Ethereum Mainnet"
    chain_id: 1
    rpc_urls:
      - "https://eth.llamarpc.com"          # Primary
      - "https://rpc.ankr.com/eth"          # Backup
      - "https://ethereum.publicnode.com"   # Backup
  
  pulsechain:
    name: "PulseChain"
    chain_id: 369
    rpc_urls:
      - "https://rpc.pulsechain.com"        # Primary
      - "https://pulsechain.publicnode.com" # Backup
```

**Features:**
- ✅ Automatic RPC failover
- ✅ No API keys required (free public RPCs)
- ✅ Easy to add new chains
- ✅ Per-chain timeout settings

---

## 🔍 Troubleshooting

### **"Merged dataset not found"**

```bash
# Solution: Collect data first
python3 src/data_collection.py --both
```

### **"Model file not found"**

```bash
# Solution: Train model first
python3 src/train.py
```

### **RPC Timeout Errors**

```yaml
# Edit config.yaml - increase timeout
collection:
  timeout: 30  # Increase from 20 to 30 seconds
```

### **Low Model Accuracy**

1. **Add more training data** (most important!)
2. Check for mislabeled contracts
3. Try different algorithms
4. Reduce model complexity (prevent overfitting)

### **SMOTE Errors**

```bash
# If you get "Not enough neighbors" error:
python3 src/train.py --no-balance  # Skip SMOTE
```

### **Cast Command Not Found**

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

---

## ⚠️ Disclaimer

**IMPORTANT: This is a research/educational tool, not financial advice!**

- ✅ Use as a **supplementary screening tool**
- ❌ **DO NOT** rely on it as the sole decision factor
- ✅ Always verify contract source code
- ✅ Check for audits from reputable firms
- ✅ Test with tiny amounts first
- ✅ Use multiple honeypot detectors
- ❌ The model is only as good as its training data
- ❌ New honeypot techniques emerge constantly
- ❌ No guarantees - **DYOR (Do Your Own Research)**

**Not financial advice. Always invest responsibly.**

---

## 📚 How It Works

### **1. Feature Extraction**

The system analyzes bytecode to extract 100+ features:

- **Opcode frequencies** - Count of dangerous operations (DELEGATECALL, SELFDESTRUCT)
- **Function selectors** - Presence of blacklist/pause/fee functions
- **Control flow** - Complexity of JUMP/JUMPI patterns
- **N-grams** - Common bytecode sequences
- **Honeypot patterns** - 10+ known malicious patterns
- **Structural features** - Contract size, function density, metadata

### **2. Machine Learning**

Uses ensemble models to detect patterns:

1. **XGBoost** (default) - Gradient boosting, best overall performance
2. **LightGBM** - Fast, good for large datasets
3. **Random Forest** - Baseline, interpretable

**Training process:**
- Balances dataset with SMOTE (synthetic oversampling)
- 5-fold stratified cross-validation
- StandardScaler normalization
- ROC AUC optimization

### **3. Prediction**

Outputs comprehensive risk assessment:

- **Risk Score** (0-100) - Overall danger level
- **Confidence** - Model certainty
- **Top Risk Features** - What triggered the alert
- **Verdict** - Human-readable recommendation

---

## 🤝 Contributing

We need more training data! Here's how to help:

### **Submit Verified Contracts**

```bash
# 1. Fork the repo
# 2. Add contracts
python3 src/data_collection.py --chain ethereum \
    --add-honeypot 0xVERIFIED_SCAM "Name"

# 3. Submit PR with evidence:
#    - Transaction hash showing honeypot behavior
#    - Source code analysis
#    - Community reports
```

### **Improve Features**

- Add new honeypot pattern detection
- Optimize feature extraction speed
- Add support for more chains (BSC, Arbitrum, etc.)

### **Enhance Models**

- Implement SHAP explainability
- Add ensemble voting
- Create active learning pipeline

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file

---

## 🙏 Acknowledgments

- **Ethereum Foundation** - For EVM specifications
- **PulseChain** - For RPC infrastructure
- **Honeypot.is** - For honeypot research
- **Foundry Team** - For amazing blockchain tools

---

**Built with ❤️ by the OpSnipe team**

**⚡ Stay safe. DYOR. Don't get rekt. ⚡**