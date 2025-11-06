# Opsnipe Knowledge Base

## Project Overview

Opsnipe is a machine learning-based smart contract honeypot detection system designed for PulseChain and Ethereum blockchains. It analyzes contract bytecode to identify potentially malicious honeypot contracts that appear legitimate but trap user funds.

## Core Components

### 1. Data Collection (`src/data_collection.py`)
- Scrapes blockchain data for contract bytecode
- Labels contracts as honeypots or safe
- Stores data in JSON format with metadata
- Supports manual addition of verified contracts

### 2. Feature Extraction
- Analyzes 100+ bytecode features including:
  - Opcode frequencies
  - Control flow patterns
  - Function signatures
  - Storage access patterns
- Identifies common honeypot indicators

### 3. Model Training (`src/train.py`)
- Uses ensemble methods: XGBoost, LightGBM, Random Forest
- Implements SMOTE for class balancing
- Cross-validation for robust evaluation
- Outputs model artifacts and performance metrics

### 4. Prediction Engine (`src/predict.py`)
- Real-time contract analysis
- Risk scoring (0-100)
- Confidence intervals
- Pattern detection explanations

## Architecture

```
Blockchain → Data Collection → Feature Extraction → ML Model → Risk Assessment
     ↓              ↓              ↓              ↓              ↓
   RPC APIs    JSON Storage   Bytecode Analysis  Ensemble     User Interface
```

## Key Technologies

- **Python 3.8+**: Core language
- **Scikit-learn/Pandas**: Data processing
- **XGBoost/LightGBM**: ML algorithms
- **Foundry (cast)**: Blockchain interaction
- **YAML**: Configuration management

## Data Pipeline

1. **Collection**: Gather contract addresses from various sources
2. **Labeling**: Manual verification of honeypot vs safe contracts
3. **Feature Engineering**: Extract meaningful patterns from bytecode
4. **Training**: Build and validate ML models
5. **Deployment**: Serve predictions via CLI/API

## Common Honeypot Patterns Detected

- Blacklist mechanisms
- Hidden ownership transfers
- Conditional transfer restrictions
- Dynamic fee manipulation
- Delegatecall vulnerabilities
- Selfdestruct traps
- Broken ERC20 implementations

## Performance Metrics

Current model achieves:
- ROC AUC: 0.65-0.70 (with 30-50 samples)
- Target: 0.80+ with 200+ quality samples
- Prediction time: <1 second per contract

## Integration Points

- **CLI**: Direct command-line usage
- **Python API**: Library integration
- **Bash Scripts**: Automation support
- **JSON Output**: Programmatic consumption

## Development Roadmap

### Phase 1: Core ML Pipeline ✅
- Basic data collection
- Feature extraction
- Model training/prediction

### Phase 2: Enhanced Detection
- More sophisticated features
- Multi-chain support
- Real-time monitoring

### Phase 3: Production Ready
- Web interface
- API endpoints
- Community dataset expansion

## Best Practices

- Always verify source code manually
- Use multiple detection methods
- Test with small amounts first
- Keep training data updated
- Monitor for new honeypot patterns

## Contributing

1. Add verified contract samples
2. Improve feature extraction
3. Test new ML algorithms
4. Report false positives/negatives

## Resources

- [Honeypot.is](https://honeypot.is) - Honeypot database
- [Foundry Book](https://book.getfoundry.sh/) - Blockchain tooling
- [XGBoost Docs](https://xgboost.readthedocs.io/) - ML framework