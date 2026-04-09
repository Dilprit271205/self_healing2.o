# Self-Healing Cyber Defense System

A lightweight Python-based cyber defense demo that monitors processes, network activity, and file events, then combines anomaly detection with a trust model to flag suspicious behavior. The project also includes a Streamlit dashboard for live inspection and visualization.

## What it does

- Monitors running processes with `psutil`
- Tracks network connections and file-system activity
- Extracts simple per-process features such as CPU, memory, connections, and file events
- Scores anomalies for CPU, file, and network behavior
- Updates a trust vector per process and maps it to actions like `normal`, `watchlist`, `restricted`, and `critical`
- Logs observations to `logs/system_log.json`
- Displays live metrics and trends in a Streamlit dashboard
- Includes simulation scripts for stressing the system or mimicking worm-like behavior

## Project layout

- `main.py` — main monitoring loop that collects telemetry, computes anomalies, updates trust, and logs results
- `dashboard.py` — Streamlit UI for live metrics, process trends, anomaly charts, and trust evolution
- `monitor/` — process, network, and file monitoring helpers
- `analysis/` — feature extraction, anomaly scoring, trust updates, and decision logic
- `utils/` — helpers for mapping connections and file events
- `logger/` — JSONL logging helper
- `stress.py` — CPU, memory, and file stress generator
- `worm_sim.py` — worm-like simulation that creates files, network activity, and processes
- `logs/` — runtime log output
- `worm_files/` — generated files from the worm simulation

## Requirements

The project uses Python 3 and these main packages:

- `psutil`
- `watchdog`
- `streamlit`
- `pandas`
- `requests`

## Setup

Create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install psutil watchdog streamlit pandas requests
```

## Run the monitor

Start the main self-healing monitor:

```bash
python main.py
```

This starts file monitoring in a background thread and continuously collects process and network data.

## Run the dashboard

In a separate terminal, launch the Streamlit dashboard:

```bash
streamlit run dashboard.py
```

The dashboard reads from `logs/system_log.json` and refreshes automatically.

## Optional simulations

Use the helper scripts to generate load or suspicious behavior:

```bash
python stress.py
python worm_sim.py
```

## Output format

The logger writes one JSON object per line to `logs/system_log.json`. Each record includes:

- Process features
- Anomaly scores
- Trust values
- Recommended actions
- A timestamp

## Notes

- The dashboard assumes the log file exists and may show no data until `main.py` has run long enough to write entries.
- `worm_sim.py` and `stress.py` are intentionally aggressive test tools; use them carefully on a machine you can safely load.
- `main.py` currently monitors the current directory recursively via file watching.

## License

No license file is included in the repository.
