# ML Threat Model Research And Choice

## Goal

Replace the worm/forkbomb threshold classifier with a running ML model that can learn from process telemetry, reuse the current dashboard/healing API, and keep working when labeled data is limited.

## Researched Options

### Isolation Forest

Isolation Forest is designed for unsupervised anomaly detection. The original paper by Liu, Ting, and Zhou introduced it at ICDM 2008, and scikit-learn's implementation computes anomaly scores from an ensemble of randomized trees. Scikit-learn documents that lower `decision_function` scores are more abnormal and negative scores represent outliers.

Sources:
- https://research.monash.edu/en/publications/isolation-forest/
- https://scikit-learn.org/1.5/modules/generated/sklearn.ensemble.IsolationForest.html

Why it fits:
- It can train mostly on normal behavior.
- It does not require perfect labels.
- It is lightweight enough for a local Streamlit/Python defense dashboard.

Limitation:
- It detects abnormality, not semantic classes like `worm` vs `forkbomb`.

### Random Forest Classifier

Random Forest is a supervised ensemble classifier. Scikit-learn describes it as a meta-estimator that fits many decision trees on sub-samples and averages them to improve predictive accuracy and reduce overfitting.

Source:
- https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.RandomForestClassifier.html

Why it fits:
- Your logs already contain labels: `normal`, `suspicious`, `worm`, `forkbomb`.
- It handles mixed nonlinear feature interactions well.
- It provides class probabilities for dashboard confidence and worm score.

Limitation:
- It depends on label quality, so the current implementation augments logs with synthetic lab profiles.

### Scaling / Preprocessing

Scikit-learn notes that many estimators can behave poorly when feature scales differ greatly, and `StandardScaler` standardizes features by removing the mean and scaling to unit variance.

Source:
- https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html

Decision:
- Random Forest does not need scaling as strongly as distance/kernel methods.
- The first implementation avoids extra scaling complexity and keeps raw feature magnitudes meaningful to tree splits.

## Chosen Design

Use a hybrid model:

1. `RandomForestClassifier` predicts semantic class probabilities.
2. `IsolationForest` estimates anomaly probability for fallback and uncertainty support.
3. The live `WormClassifier` API returns:
   - `label`
   - `severity`
   - `worm_score`
   - `confidence`
   - ML probability signals for the dashboard/healing pipeline

This removes the old inference-time hard threshold tree from `analysis/worm_classifier.py`. The model is trained from:

- `logs/system_log.json`
- synthetic benign/suspicious/worm/forkbomb lab profiles

The persisted artifact is:

```text
analysis/models/threat_model.joblib
```

Runtime metadata is written to:

```text
analysis/models/threat_model.metadata.json
```

## Autonomous Runtime

`WormClassifier` now loads an `AutonomousThreatModel` manager. The manager:

- trains automatically if the model artifact is missing
- checks `logs/system_log.json` for size/mtime changes
- retrains in a background thread when telemetry changes
- keeps serving predictions from the current model while retraining
- writes model health metadata after every training pass

Autonomous retraining is enabled by default.

Disable it:

```bash
set SELF_HEALING_ML_AUTOTRAIN=0
```

Tune the retrain check interval in seconds:

```bash
set SELF_HEALING_ML_RETRAIN_SECONDS=300
```

## Fork-Bomb And Worm Detection Notes

Recent defensive references line up on the same practical idea: do not
terminate on one noisy metric. Fork bombs are best treated as process-tree
storms: fast child growth, repeated similar children, short-lived recursive
children, and a growing descendant tree. Worm-like behavior needs correlation:
replication/file velocity, persistence artifacts, sensitive credential access,
network fanout or localhost beaconing, and trust/risk degradation.

MITRE ATT&CK examples map the same way:

- Conficker used Windows autostart persistence through Registry Run keys /
  Startup Folder.
- Replication through removable media is detected by newly executed processes
  from newly mounted/removable locations plus follow-on network or discovery
  behavior.
- Persistence and credential access should be correlated with file path intent,
  not just a high file-event count.

Defensive decision:

- CPU-only and memory-only spikes can raise `resource_pressure`, but must not
  become termination-ready by themselves.
- Fork-bomb termination requires repeated process-tree evidence and correlated
  fork-bomb signals.
- File replication termination requires ownership of the file burst plus
  behavioral evidence, such as duplicate content, subtree fanout, persistence
  paths, or sensitive-access paths.
- Dashboard, IDE, remote-dev, and controller processes are hard protected so
  forced family-kill logic cannot terminate the operator interface.
- The persisted sklearn model is version-checked. If the runtime sklearn
  version or feature schema differs from metadata, the model is retrained
  instead of being loaded with compatibility warnings.

Primary references:

- https://attack.mitre.org/software/S0608/
- https://attack.mitre.org/techniques/T0847/
- https://attack.mitre.org/detectionstrategies/

## How To Train

```bash
python scripts/train_threat_model.py
```

Optional:

```bash
python scripts/train_threat_model.py --log logs/system_log.json --model analysis/models/threat_model.joblib
```

## Why Not Deep Learning Yet

This project currently has small, local telemetry with limited trusted labels. A neural model would add training cost and opacity without enough data to justify it. The tree ensemble gives a better first production step: fast, interpretable enough, and retrainable from the existing logs.
