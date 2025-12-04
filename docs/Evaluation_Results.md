# BridgeIDS Model Evaluation Results
**Date**: December 1, 2025  
**Model Version**: XGBoost with Balanced SMOTE  
**Evaluation Dataset**: CSE-CIC-IDS2018 (20% stratified sample)  
**Total Samples Evaluated**: 12,639,028 flows

---

## Overall Performance Metrics

| Metric | Value |
|--------|-------|
| **Overall Accuracy** | 99.96% |
| **Weighted F1-Score** | 0.9996 |
| **Macro F1-Score** | 0.8528 |
| **Total Samples** | 12,639,028 |

---

## Detailed Per-Class Performance

| Class | Precision | Recall | F1-Score | Support | Avg Confidence |
|-------|-----------|--------|----------|---------|----------------|
| **Benign** | 100.00% | 99.96% | 99.98% | 11,932,156 | 99.88% |
| **Bot/Infiltration** | 90.84% | 99.90% | 95.16% | 46,344 | 99.89% |
| **Brute Force** | 99.96% | 100.00% | 99.98% | 18,830 | 100.00% |
| **DDoS** | 99.99% | 100.00% | 100.00% | 274,760 | 100.00% |
| **DoS** | 99.98% | 100.00% | 99.99% | 366,885 | 99.99% |
| **Web Attack** | 9.03% | 100.00% | 16.56% | 53 | 99.98% |

---
## Notes:

### Web Attacks (53 samples)
- **Precision**: 9.03%
- **Recall**: 100.00%
- **F1-Score**: 16.56%
- **Precision/Recall Trade-off**
  - **100% recall**, all 53 web attacks were detected
  - **9.03% precision** results in ~10:1 false positive ratio (~481 FPs for 53 TPs)
  - **Cause**: Extreme data scarcity (only 0.0004% of dataset)

---

## Comparison with Previous Results

### Improvement Over Earlier Versions

| Metric | v1 (Old) | v2 (FINAL_EVAL) | v3 (Current) | Improvement |
|--------|----------|-----------------|--------------|-------------|
| **Overall Accuracy** | 97.66% | 99.62% | **99.96%** | +2.3% |
| **Brute Force Recall** | 100% | 100% | **100%** | ✓ Maintained |
| **Bot Precision** | 93.92% | 54.80% | **90.84%** | +36% vs v2 |
| **Web Attack Recall** | 0% | 0% | **100%** | +100% |
| **DDoS F1** | 76% | 94.29% | **100%** | +24% |
| **DoS F1** | 86.7% | 98.40% | **99.99%** | +13% |

---

## Technical Details

### Training Configuration
- **Sample Size**: 15% of CSE-CIC-IDS2018 (~2.1M rows)
- **Class Balancing**: Aggressive Benign downsampling + Balanced SMOTE
- **Train/Test Split**: 80/20 stratified
- **Model**: XGBoost with histogram optimization
- **Hyperparameters**:
  - Learning rate: 0.05
  - Max depth: 7
  - N estimators: 250
  - Regularization: L1=0.1, L2=1.0

### Evaluation Configuration
- **Sample Size**: 20% of CSE-CIC-IDS2018 (~12.6M rows)
- **Method**: Batch processing with chunk-based sampling
- **Hardware**: Consumer-grade CPU (AMD Ryzen 7)
- **Processing Time**: ~6 minutes for 12.6M samples

### Inference Performance
- **Single Flow**: 0.8 ms
- **Batch (1000 flows)**: 42 ms (average)
- **Throughput**: ~23,800 flows/second
- **Dashboard Latency**: <50 ms (real-time updates)

---

## Known Limitations

1. **Web Attack Precision**: Low precision (9.03%) due to extreme data scarcity.

2. **Single Dataset**: Evaluated only on CSE-CIC-IDS2018. Generalization to other datasets not yet validated.

3. **Static Training**: Model does not adapt to evolving attack patterns.

4. **Flow-Based Features**: Limited to network-layer features; cannot detect payload-based attacks.

---

### Future Improvements
1. **Web Attack Module**: Develop specialized classifier with DPI features
2. **Multi-Dataset Validation**: Test on UNSW-NB15, CIC-IDS2017
3. **Continual Learning**: Implement online learning for attack evolution
4. **Ensemble Approach**: Combine with complementary models 

---