import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.ml_threat_model import MODEL_META_PATH, MODEL_PATH, train_and_save


def main():
    parser = argparse.ArgumentParser(
        description="Train the self-healing threat ML model."
    )
    parser.add_argument(
        "--log",
        default="logs/system_log.json",
        help="Process JSONL log used for supervised training."
    )
    parser.add_argument(
        "--model",
        default=str(MODEL_PATH),
        help="Destination joblib model path."
    )
    parser.add_argument(
        "--dataset",
        action="append",
        default=[],
        help=(
            "Optional research dataset CSV path. Can be repeated for "
            "CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15, CTU-13 NetFlow CSVs."
        )
    )
    args = parser.parse_args()

    model = train_and_save(
        log_path=args.log,
        model_path=args.model,
        dataset_paths=args.dataset,
    )

    print(
        json.dumps(
            {
                "model": args.model,
                "metadata": str(MODEL_META_PATH),
                "report": model.report
            },
            indent=2
        )
    )


if __name__ == "__main__":
    main()
