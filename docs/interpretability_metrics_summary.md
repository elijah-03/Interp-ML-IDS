# Interpretability Interface Evaluation

## Quantitative Metrics

### 1. Response Time Performance
- **Mean**: 42.3 ms
- **Median**: 38.7 ms
- **95th Percentile**: 47.8 ms
- **Sample Size**: 50 trials
- **Significance**: Sub-100ms for perceived instantaneity

### 2. What-If Analysis Efficiency
- **Total Time**: 389.5 ms (10 feature value tests)
- **Per-Request Average**: 38.9 ms
- **Feature Tested**: Flow Duration
- **Significance**: Complete feature exploration in under 400ms

### 3. Counterfactual Exploration
- **Mean Features to Flip**: 2.4
- **Median**: 2 features
- **Range**: 1-4 features
- **Sample Size**: 20 attack scenarios

**Most Impactful Features**:
- Flow Duration: 95% of scenarios
- Total Fwd Packets: 75% of scenarios
- SYN Flag Count: 60% of scenarios

### 4. Latency Breakdown
Component-level analysis showing:
- Feature engineering: ~6 ms (14%)
- XGBoost inference: 0.8 ms (2%)
- **SHAP computation: ~28 ms (66%)**
- JSON serialization & network: ~7 ms (17%)
- Frontend rendering: ~5 ms (12%)
