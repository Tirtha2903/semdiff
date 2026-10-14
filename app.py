#!/usr/bin/env python3
"""
app.py — Local web dashboard for the Fault-Injection Cascade Analyzer,
with a Gemma-powered explanation and chat assistant for each run.
Uses Ollama (local, offline, no API credits) to run Gemma.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import requests
from flask import Flask, jsonify, render_template, request, send_from_directory

app = Flask(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 120  # generous — first token on CPU can be slow


def get_installed_model():
    """Detect available Gemma model from local Ollama instance, fallback to gemma4:latest."""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            names = [m.get("name") for m in r.json().get("models", [])]
            for n in names:
                if n.startswith("gemma4"):
                    return n
            for n in names:
                if "gemma" in n.lower():
                    return n
    except Exception:
        pass
    return "gemma4:latest"


OLLAMA_MODEL = get_installed_model()
FAULT_TYPES = ["bitflip", "register", "retaddr"]


def make_sample_run():
    """Returns a pre-recorded test run so the dashboard is immediately interactive."""
    return {
        "id": "sample-sleep",
        "label": "Demo: /bin/sleep (coreutils 9.4)",
        "target": "/bin/sleep",
        "args": "30",
        "function": "nanosleep",
        "register": "rax",
        "duration": 6.84,
        "results": [
            {
                "fault_type": "bitflip",
                "severity": "CRITICAL",
                "reason": "caused an immediate process crash (SIGSEGV)",
            },
            {
                "fault_type": "register",
                "severity": "HIGH",
                "reason": "process kept running and still crossed the write/send/open boundary afterward",
            },
            {
                "fault_type": "retaddr",
                "severity": "LOW",
                "reason": "no observable crash or boundary activity in the 2s window after injection",
            },
        ],
        "raw_log": (
            "[fault_injector] target: /bin/sleep 30\n"
            "[fault_injector] hooked nanosleep\n"
            "[fault-bitflip] injected bitflip into rax at offset 45\n"
            "[process] terminated with SIGSEGV (blast radius: CRITICAL)\n"
        ),
        "returncode": 0,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "chat_history": [],
        "explanation": (
            "During this fault test, flipping a bit inside nanosleep immediately caused a crash due to an invalid memory reference. "
            "Corrupting the register allowed execution to continue and leak across system call boundaries, creating a high security risk. "
            "Smashing the return address did not cause an observable cascade within the observation window."
        ),
        "fix_prediction": "",
    }


HISTORY = [make_sample_run()]  # in-memory run history, seeded with demo run


def explain_run_with_gemma(run_record):
    results_summary = "\n".join(
        f"- {r['fault_type']}: {r['severity']} ({r['reason']})"
        for r in run_record["results"]
    )
    prompt = f"""You are a security analyst explaining a fault-injection test to someone non-technical.

Target program: {run_record['target']}
Function tested: {run_record['function']}
Register corrupted: {run_record['register']}

Results:
{results_summary}

In 3-4 short, plain-English sentences, explain what happened and why it matters. No jargon, no bullet points, just flowing sentences."""

    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        return f"(Explanation unavailable — is Ollama running? {e})"


def predict_fix_with_gemma(run_record):
    results_summary = "\n".join(
        f"- {r['fault_type']}: {r['severity']} ({r['reason']})"
        for r in run_record["results"]
    )
    log_snippet = run_record.get("raw_log", "")[-1000:]
    prompt = f"""You are a Principal Systems Software Engineer and Compiler Security Expert.
An automated binary fault-injection test was executed on target binary: '{run_record['target']}'.

FAULT INJECTION TELEMETRY:
- Target Binary: {run_record['target']}
- Function / Hook: {run_record['function']}
- Target Register/Offset: {run_record['register']}
- Results:
{results_summary}

Log / Crash Snippet:
{log_snippet}

TASK:
Provide a rigorous diagnosis and remediation plan formatted strictly in Markdown with these 3 sections:

### 1. Root Cause Mechanism
Explain technically why corrupting {run_record['register']} or injecting this fault led to this cascade (e.g., register operand invalidation, ABI calling convention violation, stack frame smash, unhandled SIGSEGV/panic leaking into write/send syscalls).

### 2. Software Hardening & Defensive Code Fix
Show the exact defensive programming pattern in C/C++ (or Rust) to make this function resilient against this corruption (e.g., pointer validation, canary checks, double-computation sanity check, or bounding input before syscalls). Provide a concise code snippet before and after.

### 3. Compiler & System Level Mitigations
List 2-3 specific compiler flags or OS mitigations (e.g., `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fcf-protection`, Shadow Call Stack) that prevent or contain this fault.

Be direct, technical, and actionable."""

    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2
            }
        }, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        return f"### Remediation Prediction Unavailable\nCould not reach local Gemma model: {e}"


def chat_about_run(run_record, question, chat_history):
    results_summary = "\n".join(
        f"- {r['fault_type']}: {r['severity']} ({r['reason']})"
        for r in run_record["results"]
    )
    history_text = "\n".join(
        f"{'User' if m['role']=='user' else 'Assistant'}: {m['text']}"
        for m in chat_history[-6:]
    )
    prompt = f"""You are a security analyst assistant. A fault-injection test was run with these results:

Target: {run_record['target']}
Function: {run_record['function']}
Register: {run_record['register']}
Results:
{results_summary}

Conversation so far:
{history_text}

User: {question}

Answer in 2-3 plain sentences, based only on the data above."""

    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        return f"(Could not reach the local model: {e})"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/gemma-test")
def gemma_test():
    return render_template("gemma_test.html")


@app.route("/api/gemma-ping", methods=["POST"])
def api_gemma_ping():
    data = request.get_json(force=True)
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        prompt = "Say exactly: Gemma is alive and running on this machine."
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        answer = resp.json().get("response", "").strip()
        return jsonify({"ok": True, "model": OLLAMA_MODEL, "response": answer})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/history")
def api_history():
    return jsonify(HISTORY)


@app.route("/api/sample-run", methods=["POST"])
def api_sample_run():
    sample = make_sample_run()
    if not any(r["id"] == sample["id"] for r in HISTORY):
        HISTORY.insert(0, sample)
    return jsonify(sample)


@app.route("/semdiff")
@app.route("/app.html")
def semdiff_page():
    return send_from_directory(".", "app.html")



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
    temp_dir = tempfile.gettempdir()
    output_base = os.path.join(temp_dir, f"fault_report_{run_id}")
    log_path = os.path.join(temp_dir, f"fault_dashboard_log_{run_id}.txt")

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
        "raw_log": full_log[-4000:],
        "returncode": proc.returncode,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "chat_history": [],
    }

    print("[dashboard] Asking Gemma for an explanation (this can take a while on CPU)...", flush=True)
    run_record["explanation"] = explain_run_with_gemma(run_record)
    print("[dashboard] Explanation ready.", flush=True)

    HISTORY.insert(0, run_record)
    return jsonify(run_record)


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(force=True)
    run_id = data.get("run_id")
    question = data.get("question", "").strip()

    run_record = next((r for r in HISTORY if r["id"] == run_id), None)
    if not run_record:
        return jsonify({"error": "Run not found."}), 404
    if not question:
        return jsonify({"error": "Question is empty."}), 400

    run_record.setdefault("chat_history", [])
    run_record["chat_history"].append({"role": "user", "text": question})

    print(f"[dashboard] Chat question: {question!r} (waiting on Gemma...)", flush=True)
    answer = chat_about_run(run_record, question, run_record["chat_history"])
    print("[dashboard] Chat answer ready.", flush=True)

    run_record["chat_history"].append({"role": "assistant", "text": answer})

    return jsonify({"answer": answer})


@app.route("/api/predict_fix", methods=["POST"])
def api_predict_fix():
    data = request.get_json(force=True)
    run_id = data.get("run_id")
    run_record = next((r for r in HISTORY if r["id"] == run_id), None)
    if not run_record:
        return jsonify({"error": "Run not found."}), 404

    if "fix_prediction" not in run_record or not run_record["fix_prediction"]:
        print(f"[dashboard] Asking Gemma for fix prediction on run {run_id}...", flush=True)
        run_record["fix_prediction"] = predict_fix_with_gemma(run_record)
        print("[dashboard] Fix prediction ready.", flush=True)

    return jsonify({"fix_prediction": run_record["fix_prediction"]})


def warm_up_model():
    print("[dashboard] Warming up Gemma (first load can take a while on CPU)...", flush=True)
    try:
        requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": "Say OK.",
            "stream": False
        }, timeout=(3.0, 120))
        print("[dashboard] Gemma is warmed up and ready.", flush=True)
    except Exception as e:
        print(f"[dashboard] Warm-up failed (will retry on first real request): {e}", flush=True)


if __name__ == "__main__":
    print("Dashboard running at: http://127.0.0.1:5000")
    print("Gemma test page:      http://127.0.0.1:5000/gemma-test")
    print("Press Ctrl+C to stop.")
    threading.Thread(target=warm_up_model, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True, use_reloader=False)

