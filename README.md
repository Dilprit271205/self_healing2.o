# Self-Healing Cyber Defense System

This project is a host-monitoring and response prototype. It collects process/network/file activity, builds per-process features, updates a hybrid trust score, decides an action, and logs everything for a live Streamlit dashboard.

## How the system works (high level)

1. `main.py` collects runtime telemetry each second.
2. `monitor/` modules gather process, network, and file-change signals.
3. `analysis/feature_extractor.py` builds worm-oriented and resource features.
4. `analysis/anomaly/` modules convert raw values into anomaly flags.
5. `analysis/trust/` modules update dynamic + static + final trust.
6. `analysis/decision/decision_engine.py` maps trust to actions.
7. `logger/logger.py` writes JSONL logs to `logs/`.
8. `dashboard.py` reads logs and visualizes health/risk in near real time.

## File-by-file explanation

### Root files

- `main.py`  
	Core runtime loop. Starts file monitoring in a daemon thread, groups processes into lineage entities, computes features and anomalies per process, updates trust, decides actions, and logs process/entity records. Contains:
	- `terminate_process_tree(pid)`: kills a PID and all descendants.
	- `should_kill_process(...)`: strict safeguard policy that only auto-kills explicit simulator targets (`worm_sim.py`/`stress.py`) with high worm score and safe ownership checks.
	- `is_idle_process(process)`: avoids trust collapse by skipping very idle processes.
	- `monitor_loop()`: orchestrates full detection/response pipeline.

- `dashboard.py`  
	Streamlit executive dashboard. Auto-refreshes every 3s, loads JSON logs, expands nested trust/anomaly fields, classifies each process (`normal`, `watchlist`, `critical`), calculates health score, and shows 3 tabs:
	- **Operations**: process trust table + top CPU consumers.
	- **Threat Intelligence**: process-family/entity growth view.
	- **Worm Lab**: worm/stress-specific signal board.

- `worm_sim.py`  
	Rabbit-worm style simulator for testing detection. Repeatedly spawns child CPU workers, creates temporary replication markers in system temp directory, runs up to `RUN_TIME`, then performs cleanup.

- `stress.py`  
	Controlled multi-vector stress generator (CPU, memory, file writes, network connects, subprocess spawning). Designed to produce anomalous pressure while keeping caps/rate-limits.

- `cleanup.py`  
	Utility script to recover after simulations:
	- deletes local temp files (`temp_*.txt`, `temp_stress.txt`),
	- kills known stress-related processes,
	- optional log clearing helper (`clear_logs`, commented by default).

- `README.md`  
	Project documentation (this file).

### `analysis/`

- `analysis/__init__.py`  
	Empty package marker.

- `analysis/feature_extractor.py`  
	Builds feature vectors from process telemetry + connection/file maps + static analysis. Maintains in-memory per-PID history for temporal signals. Important outputs include:
	- `f_proc_spawn`, `f_proc_tree`, `f_process_trend`
	- CPU/memory trends and spikes
	- `f_syscall_pattern`, `f_young_process`, suspicious-name flags
	- final `worm_score`
	- static file-derived trust features.

#### `analysis/anomaly/`

- `analysis/anomaly/__init__.py`  
	Empty package marker.

- `analysis/anomaly/cpu_anomaly.py`  
	Sliding-window CPU anomaly detector. Flags either sustained high average CPU or spike above threshold.

- `analysis/anomaly/file_anomaly.py`  
	File-event threshold checker. Returns anomaly when file-event count is above configured cutoff.

- `analysis/anomaly/network_anomaly.py`  
	Connection-count threshold checker. Returns anomaly when active connections exceed cutoff.

#### `analysis/static/`

- `analysis/static/__init__.py`  
	Empty package marker.

- `analysis/static/static_analyzer.py`  
	Extracts file metadata (`size`, `extension`, hidden flag, suspicious location) and converts static risk to static trust using static rules.

- `analysis/static/static_rules.py`  
	Rule-based static risk scoring. Adds risk for empty/very large files, hidden files, suspicious locations, and risky extensions; capped to `[0,1]`.

#### `analysis/trust/`

- `analysis/trust/__init__.py`  
	Empty package marker.

- `analysis/trust/trust_vector.py`  
	In-memory trust database (`trust_db`) and primitives to initialize/update dynamic components (`cpu`, `file`, `net`), set static trust, and compute weighted final trust.

- `analysis/trust/trust_update.py`  
	Main trust-update engine. Applies anomaly-driven penalties, clean-state recovery, correlated worm-signal penalties, static-trust influence, clamping, and returns full updated trust vector.

#### `analysis/decision/`

- `analysis/decision/__init__.py`  
	Empty package marker.

- `analysis/decision/decision_engine.py`  
	Converts `final_trust` into action levels:
	- `< 0.3` → `critical` + `kill_process`
	- `< 0.6` → `suspicious` + `restrict`
	- otherwise `normal` + `allow`
	Also returns trust-score breakdown for UI/log visibility.

### `monitor/`

- `monitor/__init__.py`  
	Empty package marker.

- `monitor/process_monitor.py`  
	Process collector using `psutil`. Performs one-time CPU sampler warmup and returns normalized process records (pid/ppid/name/cpu/memory/exe/create_time/threads/cmdline).

- `monitor/network_monitor.py`  
	Collects active `inet` connections and returns lightweight records (`pid`, `status`).

- `monitor/file_monitor.py`  
	`watchdog` observer wrapper. Tracks file create/modify/delete events and records counters through `utils.file_event_mapper`.

- `monitor/lineage.py`  
	Process family/entity tracker. Finds root parent for each process and groups descendants into entities; provides summaries and large-tree detection.

### `utils/`

- `utils/__init__.py`  
	Empty package marker.

- `utils/connection_mapper.py`  
	Aggregates network connection list into `{pid: connection_count}` map.

- `utils/file_event_mapper.py`  
	In-memory file-event counters. `record_file_event(pid)` increments counters; `get_file_map()` returns and resets counts per monitoring cycle.

### `logger/`

- `logger/__init__.py`  
	Empty package marker.

- `logger/logger.py`  
	Asynchronous JSONL logger using background writer threads and queues.
	- Writes process events to `logs/system_log.json`.
	- Writes entity events to `logs/entity_log.json`.
	- Adds ISO timestamp in `log_process()` / `log_entity()`.

### `logs/`

- `logs/system_log.json`  
	Runtime JSONL output for per-process monitoring records.

- `logs/entity_log.json`  
	Runtime JSONL output for process-lineage/entity summaries.

Both log files currently exist and are empty until the monitor runs.

## Runtime dependencies

Detected from imports in code:

- `psutil`
- `watchdog`
- `streamlit`
- `streamlit-autorefresh`
- `pandas`
- `plotly`

## Quick start

```bash
python3 -m venv venv
source venv/bin/activate
pip install psutil watchdog streamlit streamlit-autorefresh pandas plotly
python main.py
```

In another terminal:

```bash
source venv/bin/activate
streamlit run dashboard.py
```

Optional test workload:

```bash
python stress.py
python worm_sim.py
```
