import sys
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from imblearn.over_sampling import SMOTE
import time
import gc
import pandas as pd

# Import the functions from your scripts
try:
    from load_dataset import load_and_inspect
    from preprocess import preprocess
except ImportError:
    print(
        "Error: Could not import from 'load_dataset.py' or 'preprocess.py'.",
        file=sys.stderr,
    )
    sys.exit(1)

import resource


# Define memory limit function
def set_memory_limit(max_gb=28):
    """Set a hard memory limit to prevent system crashes (leave 4GB for OS)"""
    try:
        max_bytes = int(max_gb * 1024 * 1024 * 1024)
        resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
        print(f"✓ Memory limit set to {max_gb}GB to prevent system freeze")
    except Exception as e:
        print(f"⚠ Could not set memory limit: {e}")


# Call immediately
set_memory_limit(28)  # Leave 4GB for system

# Configuration
RANDOM_STATE = 42
SAMPLE_FRACTION = 0.15  # Keep 15% as before


def optimize_dtypes(df):
    """Downcast numeric types to save 50%+ memory"""
    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = df[col].astype("float32")
    for col in df.select_dtypes(include=["int64"]).columns:
        df[col] = df[col].astype("int32")
    return df


def chunked_smote(
    X_train, y_train, label_encoder, target_per_class=100000, benign_target=500000
):
    """
    Apply SMOTE in chunks to avoid memory overflow.
    Process each attack class separately, then combine.
    """
    print("\n--- CHUNKED SMOTE PROCESSING (Memory-Safe) ---")

    # Get class distribution
    unique, counts = np.unique(y_train, return_counts=True)
    class_counts = dict(zip(unique, counts))

    print("Class distribution before SMOTE:")
    for cls, count in zip(unique, counts):
        print(f"  {label_encoder.inverse_transform([cls])[0]}: {count:,}")

    # Separate by class
    benign_idx = list(label_encoder.classes_).index("Benign")

    # Store results
    X_resampled_list = []
    y_resampled_list = []

    # First, add all benign samples (already downsampled to 500K)
    benign_mask = y_train == benign_idx
    X_benign = X_train[benign_mask]
    y_benign = y_train[benign_mask]

    X_resampled_list.append(X_benign)
    y_resampled_list.append(y_benign)

    print(f"\n✓ Added Benign samples: {len(y_benign):,}")
    gc.collect()

    # Process each attack class separately
    for cls_idx, cls_name in enumerate(label_encoder.classes_):
        if cls_name == "Benign":
            continue

        current_count = class_counts.get(cls_idx, 0)

        # Special handling for Web Attack (too few samples)
        if cls_name == "Web Attack":
            target = min(10000, current_count * 50)  # Cap at 10K
        else:
            target = max(current_count, target_per_class)

        if current_count == 0:
            print(f"⚠ Skipping {cls_name}: no samples")
            continue

        print(f"\n--- Processing {cls_name} ---")
        print(f"  Current: {current_count:,}, Target: {target:,}")

        # Extract this class + benign for SMOTE context
        class_mask = y_train == cls_idx

        # Get samples for this class only
        X_class = X_train[class_mask]
        y_class = y_train[class_mask]

        if target > current_count:
            # Need to oversample
            try:
                # Use fewer neighbors if we don't have enough samples
                k_neighbors = min(5, current_count - 1) if current_count > 1 else 1

                smote = SMOTE(
                    sampling_strategy={cls_idx: target},
                    k_neighbors=k_neighbors,
                    random_state=RANDOM_STATE,
                )

                # SMOTE needs at least 2 classes, so temporarily add one benign sample
                X_temp = np.vstack([X_class, X_benign[:1]])
                y_temp = np.hstack([y_class, y_benign[:1]])

                X_smoted, y_smoted = smote.fit_resample(X_temp, y_temp)

                # Remove the temporary benign sample and extract only the attack class
                attack_mask = y_smoted == cls_idx
                X_class_smoted = X_smoted[attack_mask]
                y_class_smoted = y_smoted[attack_mask]

                X_resampled_list.append(X_class_smoted)
                y_resampled_list.append(y_class_smoted)

                print(f"  ✓ SMOTE applied: {current_count:,} → {len(y_class_smoted):,}")

                # Clean up
                del smote, X_temp, y_temp, X_smoted, y_smoted
                del X_class_smoted, y_class_smoted

            except Exception as e:
                print(f"  ⚠ SMOTE failed for {cls_name}: {e}")
                print(f"  Using original {current_count:,} samples")
                X_resampled_list.append(X_class)
                y_resampled_list.append(y_class)
        else:
            # No oversampling needed
            X_resampled_list.append(X_class)
            y_resampled_list.append(y_class)
            print(f"  ✓ No oversampling needed")

        # Aggressive garbage collection after each class
        del X_class, y_class
        gc.collect()

    # Combine all classes
    print("\n--- Combining all classes ---")
    X_train_resampled = np.vstack(X_resampled_list)
    y_train_resampled = np.hstack(y_resampled_list)

    # Clean up intermediate lists
    del X_resampled_list, y_resampled_list
    gc.collect()

    print(f"\n✓ Final dataset: {X_train_resampled.shape}")
    print("\nFinal class distribution:")
    unique, counts = np.unique(y_train_resampled, return_counts=True)
    for cls, count in zip(unique, counts):
        cls_name = label_encoder.inverse_transform([cls])[0]
        pct = (count / len(y_train_resampled)) * 100
        print(f"  {cls_name}: {count:,} ({pct:.1f}%)")

    return X_train_resampled, y_train_resampled


def train_models():
    """
    Loads, preprocesses, and trains XGBoost model with memory-safe approach.
    """

    # 1. Define data path
    DATASET_DIR = "/home/elijah/Documents/CPS373/Interp-ML-IDS/CSECICIDS2018_improved"

    try:
        # 2. Load Data
        print(f"--- Loading Data (Sample Fraction: {SAMPLE_FRACTION}) ---")
        raw_df = load_and_inspect(DATASET_DIR, sample_fraction=SAMPLE_FRACTION)

        if raw_df is None:
            print("Failed to load data.")
            return

        # OPTIMIZATION: Downcast types immediately
        print("Optimizing memory (downcasting types)...")
        raw_df = optimize_dtypes(raw_df)

        # 3. Preprocess
        print("--- Preprocessing Data ---")
        (
            X_train_orig,
            X_test,
            y_train_orig,
            y_test,
            X_train_preprocessed,
            y_train_preprocessed,
            feature_list,
            label_encoder,
            scaler,
        ) = preprocess(raw_df)

        # Free up memory from raw_df after preprocessing
        del raw_df
        gc.collect()

        # 4. Split training data into Train and Validation
        print("Splitting training data for validation...")
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train_preprocessed,
            y_train_preprocessed,
            test_size=0.2,
            random_state=RANDOM_STATE,
            stratify=y_train_preprocessed,
        )

        # Free up memory
        del X_train_preprocessed, y_train_preprocessed
        gc.collect()

        # 5. Aggressive Benign Downsampling
        print("\n--- STEP 1: Aggressive Benign Downsampling ---")
        print(f"Before downsampling: {X_train_split.shape}")

        benign_idx = list(label_encoder.classes_).index("Benign")
        benign_mask = y_train_split == benign_idx
        attack_mask = ~benign_mask

        benign_indices = np.where(benign_mask)[0]
        attack_indices = np.where(attack_mask)[0]

        benign_target = 500000
        print(
            f"Downsampling Benign from {len(benign_indices):,} to {benign_target:,}..."
        )

        if len(benign_indices) > benign_target:
            rng = np.random.RandomState(RANDOM_STATE)
            benign_sampled = rng.choice(
                benign_indices, size=benign_target, replace=False
            )
        else:
            benign_sampled = benign_indices

        # Combine
        combined_indices = np.concatenate([benign_sampled, attack_indices])
        np.random.shuffle(combined_indices)

        X_train_split = X_train_split.iloc[combined_indices].values  # Convert to numpy
        y_train_split = y_train_split.iloc[combined_indices].values

        print(f"After downsampling: {X_train_split.shape}")

        # Free memory
        del benign_indices, attack_indices, benign_sampled, combined_indices
        gc.collect()

        # 6. CHUNKED SMOTE (Memory-Safe)
        X_train_resampled, y_train_resampled = chunked_smote(
            X_train_split,
            y_train_split,
            label_encoder,
            target_per_class=100000,
            benign_target=500000,
        )

        # Free memory from original split
        del X_train_split, y_train_split
        gc.collect()

        # 7. Compute balanced sample weights
        print("\nComputing balanced sample weights...")
        sample_weights = compute_sample_weight(
            class_weight="balanced", y=y_train_resampled
        )

        # 8. XGBoost Configuration
        xgb_params = {
            "objective": "multi:softprob",
            "num_class": len(label_encoder.classes_),
            "tree_method": "hist",
            "device": "cpu",
            "learning_rate": 0.05,
            "max_depth": 7,
            "n_estimators": 250,
            "min_child_weight": 5,
            "gamma": 0.2,
            "subsample": 0.75,
            "colsample_bytree": 0.75,
            "reg_alpha": 0.1,
            "reg_lambda": 1.0,
            "n_jobs": -1,
            "random_state": RANDOM_STATE,
            "verbosity": 1,
        }

        print("\n--- Training XGBoost Model ---")
        start_time = time.time()
        xgb_model = XGBClassifier(**xgb_params)

        # Memory cleanup before training
        del X_train_orig, y_train_orig
        gc.collect()
        print(
            f"Memory cleanup done. Training on {X_train_resampled.shape[0]:,} samples..."
        )

        # Training
        xgb_model.fit(
            X_train_resampled,
            y_train_resampled,
            sample_weight=sample_weights,
            eval_set=[(X_val.values, y_val.values)],
            verbose=50,
        )
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds.")

        # Clear resampled data
        del X_train_resampled, y_train_resampled, sample_weights
        gc.collect()

        # 9. Benchmarking
        print("\n--- Benchmarking ---")
        latency_samples = X_test[:1000].values
        start_latency = time.time()
        xgb_model.predict(latency_samples)
        end_latency = time.time()

        if len(latency_samples) > 0:
            avg_latency_ms = (
                (end_latency - start_latency) / len(latency_samples)
            ) * 1000
            print(f"Average Inference Latency: {avg_latency_ms:.4f} ms per sample")

        # Evaluation
        print("Evaluating on Test Set...")
        y_pred = xgb_model.predict(X_test.values)

        report = classification_report(
            y_test,
            y_pred,
            target_names=[str(c) for c in label_encoder.classes_],
            output_dict=True,
        )
        print(
            classification_report(
                y_test, y_pred, target_names=[str(c) for c in label_encoder.classes_]
            )
        )

        print(f"Weighted F1-Score: {report['weighted avg']['f1-score']:.4f}")
        print(f"Weighted Precision: {report['weighted avg']['precision']:.4f}")
        print(f"Weighted Recall: {report['weighted avg']['recall']:.4f}")

        # 10. Save artifacts
        print("\nSaving artifacts...")
        joblib.dump(xgb_model, "xgb_model.joblib")
        joblib.dump(scaler, "scaler.joblib")
        joblib.dump(label_encoder, "label_encoder.joblib")
        joblib.dump(feature_list, "feature_list.joblib")

        print("✓ All artifacts saved successfully.")
        print(f"✓ Training completed in {training_time / 60:.1f} minutes")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    train_models()
