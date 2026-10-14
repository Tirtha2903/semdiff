#!/usr/bin/env python3
"""
app.py — Local web dashboard for the Fault-Injection Cascade Analyzer.
Wraps fault_injector.py: runs it as a subprocess against a binary you
choose, reads back the JSON reports it writes, and shows them in a
browser UI with a run history. Runs ONLY on your own machine.

NOTE: output is captured via a log FILE, not pipes (capture_output=True).
Piping fault_injector.py's output directly deadlocks against Frida's
background threads — writing to a file sidesteps that entirely.
"""

import json
import os
import subprocess
import sys
import time
import uuid

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

HISTORY = []  # in-memory run history, newest first

FAULT_TYPES = ["bitflip", "register", "retaddr"]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/history")
def api_history():
    return jsonify(HISTORY)


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    args = data.get("args", "").strip()
    function = data.get("function", "nanosleep").strip() or "nanosleep"
    register = data.get("register", "rax").strip() or "rax"
    label = data.get("label", "").strip() or target

    if not target:
        return jsonify({"error": "Target binary path is required."}), 400

    run_id = str(uuid.uuid4())[:8]
    output_base = f"/tmp/fault_report_{run_id}"
    log_path = f"/tmp/fault_dashboard_log_{run_id}.txt"

    cmd = [
        sys.executable, "fault_injector.py",
        "--target", target,
        "--function", function,
        "--register", register,
        "--fault-type", "all",
        "--observe-seconds", "3",
        "--output", f"{output_base}.json",
    ]
    if args:
        cmd += ["--args"] + args.split()

    print(f"[dashboard] Launching: {' '.join(cmd)}", flush=True)
    started = time.time()
    try:
        with open(log_path, "w") as logf:
            proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, timeout=120)
        print(f"[dashboard] Finished in {round(time.time()-started,2)}s, returncode={proc.returncode}", flush=True)
    except subprocess.TimeoutExpired:
        print("[dashboard] TIMED OUT after 120s", flush=True)
        return jsonify({"error": "Run timed out after 120 seconds."}), 500
    except Exception as e:
        print(f"[dashboard] EXCEPTION launching subprocess: {e}", flush=True)
        return jsonify({"error": f"Failed to launch fault_injector.py: {e}"}), 500

    duration = round(time.time() - started, 2)

    with open(log_path) as f:
        full_log = f.read()

    if proc.returncode != 0 and not full_log.strip():
        print(f"[dashboard] Non-zero exit with no output.", flush=True)
        return jsonify({
            "error": f"fault_injector.py exited with error (code {proc.returncode}) and produced no output."
        }), 500

    results = []
    for ft in FAULT_TYPES:
        path = f"{output_base}_{ft}.json"
        if os.path.exists(path):
            try:
                with open(path) as f:
                    report = json.load(f)
                summary = report.get("summary", {})
                results.append({
                    "fault_type": ft,
                    "severity": summary.get("severity", "UNKNOWN"),
                    "reason": summary.get("reason", ""),
                })
            except Exception as e:
                results.append({"fault_type": ft, "severity": "ERROR", "reason": str(e)})
        else:
            results.append({"fault_type": ft, "severity": "ERROR", "reason": "No report file produced."})

    order = {"CRITICAL": 0, "HIGH": 1, "LOW": 2, "ERROR": 3, "UNKNOWN": 4}
    results.sort(key=lambda r: order.get(r["severity"], 9))

    run_record = {
        "id": run_id,
        "label": label,
        "target": target,
        "args": args,
        "function": function,
        "register": register,
        "duration": duration,
        "results": results,
        "raw_log": full_log[-4000:],  # keep it bounded
        "returncode": proc.returncode,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    HISTORY.insert(0, run_record)

    return jsonify(run_record)


if __name__ == "__main__":
    print("Dashboard running at: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
