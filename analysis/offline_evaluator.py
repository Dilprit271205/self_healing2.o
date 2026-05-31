import os
import time
import json
import random
import subprocess

import psutil

from analysis.extractor_engine import ExtractorEngine


def get_process_snapshot(pid):
    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "name": proc.name(),
            "cpu": proc.cpu_percent(interval=0.05),
            "memory": proc.memory_info().rss if proc.memory_info() is not None else 0,
            "threads": proc.num_threads(),
            "create_time": proc.create_time(),
            "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
            "exe": proc.exe() if proc.exe() else "",
        }
    except Exception:
        return None


def collect_samples(num_pos=3, num_neg=150):
    extractor = ExtractorEngine()

    positives = []
    negatives = []

    # spawn a few worm_sim and forkbomb_sim instances to collect positive samples
    procs = []
    for _ in range(max(1, num_pos - 1)):
        p = subprocess.Popen(["/usr/bin/env", "python3", "worm_sim.py"])  # background
        procs.append(p)
        time.sleep(0.5)

    # add one forkbomb positive sample when possible
    try:
        fb = subprocess.Popen(["/usr/bin/env", "python3", "forkbomb_sim.py"])  # background
        procs.append(fb)
    except Exception:
        pass

    time.sleep(1.0)

    for p in procs:
        snap = get_process_snapshot(p.pid)
        if snap:
            entity_map = {p.pid: [c.pid for c in psutil.Process(p.pid).children(recursive=True)]}
            features = extractor.extract(snap, entity_map, {})
            positives.append({"pid": p.pid, "score": features.get("worm_score", 0), "features": features})

    # cleanup positives
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass

    time.sleep(0.5)

    # collect negatives from current processes
    candidates = []
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            if proc.info["pid"] in (os.getpid(), os.getppid()):
                continue
            # skip python helper processes
            name = (proc.info.get("name") or "").lower()
            if "python" in name and "worm_sim" in name:
                continue
            candidates.append(proc.info["pid"])
        except Exception:
            continue

    random.shuffle(candidates)
    for pid in candidates[:num_neg]:
        snap = get_process_snapshot(pid)
        if not snap:
            continue
        try:
            entity_map = {pid: [c.pid for c in psutil.Process(pid).children(recursive=True)]}
        except Exception:
            entity_map = {pid: []}
        features = extractor.extract(snap, entity_map, {})
        negatives.append({"pid": pid, "score": features.get("worm_score", 0), "features": features})

    return positives, negatives


def sweep_threshold(positives, negatives, steps=200):
    scores = [s["score"] for s in positives + negatives]
    if not scores:
        return {"best_threshold": 0, "best_f1": 0.0, "metrics": []}

    lo = min(scores)
    hi = max(scores)
    if lo == hi:
        hi = lo + 1.0

    best = {"threshold": None, "f1": -1, "prec": 0, "rec": 0}
    metrics = []

    for i in range(steps + 1):
        thr = lo + (hi - lo) * (i / steps)
        tp = sum(1 for p in positives if p["score"] >= thr)
        fp = sum(1 for n in negatives if n["score"] >= thr)
        fn = sum(1 for p in positives if p["score"] < thr)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        metrics.append({"threshold": thr, "precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn})

        if f1 > best["f1"]:
            best.update({"threshold": thr, "f1": f1, "prec": prec, "rec": rec})

    return {"best_threshold": best["threshold"], "best_f1": best["f1"], "best_prec": best["prec"], "best_rec": best["rec"], "metrics": metrics}


def main():
    print("Collecting samples for offline evaluation...")
    positives, negatives = collect_samples()

    print(f"Collected {len(positives)} positives and {len(negatives)} negatives")

    result = sweep_threshold(positives, negatives)

    out = {
        "positives": positives,
        "negatives": negatives[:50],
        "result": result,
        "timestamp": time.time()
    }

    with open("analysis/offline_eval_results.json", "w") as fh:
        json.dump(out, fh, indent=2)

    print("Best threshold:", result.get("best_threshold"))
    print("Best F1:", result.get("best_f1"))
    print("Results written to analysis/offline_eval_results.json")


if __name__ == '__main__':
    main()
