import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import ml_threat_model


def main():
    parser = argparse.ArgumentParser(
        description="Train the self-healing model with CICIoT2023 CSV data."
    )
    parser.add_argument(
        "dataset",
        nargs="+",
        help="CICIoT2023 CSV file, extracted CSV directory, or glob pattern.",
    )
    parser.add_argument(
        "--log-path",
        default="logs/system_log.json",
        help="Runtime telemetry log to include during training.",
    )
    parser.add_argument(
        "--model-path",
        default=str(ml_threat_model.MODEL_PATH),
        help="Output model artifact path.",
    )
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=5000,
        help="Maximum rows to import from each CSV shard.",
    )
    parser.add_argument(
        "--max-rows-per-label",
        type=int,
        default=350,
        help="Maximum rows to import for each attack label per CSV shard.",
    )
    args = parser.parse_args()

    dataset_paths = ml_threat_model._expand_dataset_paths(args.dataset)
    if not dataset_paths:
        raise SystemExit(
            "No CSV files found. Pass the official CICIoT2023 CSV directory, "
            "a merged CSV file, or a glob such as data/CICIoT2023/CSV/*.csv."
        )

    external_rows = ml_threat_model.load_external_dataset_rows(
        dataset_paths,
        max_rows_per_dataset=args.max_rows_per_file,
        max_rows_per_label=args.max_rows_per_label,
    )
    label_counts = {}
    family_counts = {}
    for row in external_rows:
        label = row.get("external_attack_label") or row.get("label", "unknown")
        family = row.get("external_attack_family") or "unknown"
        label_counts[label] = label_counts.get(label, 0) + 1
        family_counts[family] = family_counts.get(family, 0) + 1

    print(
        json.dumps(
            {
                "csv_files": len(dataset_paths),
                "external_rows": len(external_rows),
                "attack_labels": label_counts,
                "attack_families": family_counts,
            },
            indent=2,
            sort_keys=True,
        )
    )

    model = ml_threat_model.train_and_save(
        log_path=args.log_path,
        model_path=Path(args.model_path),
        dataset_paths=dataset_paths,
        max_rows_per_dataset=args.max_rows_per_file,
        max_rows_per_label=args.max_rows_per_label,
    )
    print(
        json.dumps(
            {
                "model_path": str(args.model_path),
                "rows": model.report.get("rows"),
                "labels": model.report.get("labels"),
                "estimators": model.report.get("estimators"),
                "strategy": model.report.get("model_strategy"),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
