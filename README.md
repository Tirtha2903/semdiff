# SemDiff

Compare two builds of a program and see only what changed in **behavior**, not bytes.
The engine proves and locates changes. Gemma 4, running locally through Ollama, investigates and explains them fully.

## Quickstart: How to Run Step-by-Step

This repository includes two complementary systems:
1. **Fault-Injection Cascade Analyzer & Gemma Remediation Dashboard** (`app.py` on port 5000): Injects binary faults (bit-flips, register corruption, return address smashes) via Frida, tracks syscall blast radius, and uses Google Gemma to diagnose and predict code-level hardening patches.
2. **SemDiff Engine & C Compiler** (`server.py` on port 8000): Behavioral differential testing engine for C functions compiled with GCC across optimization levels.

---

### Linux (Ubuntu / Debian / Mint)

#### 1. System Prerequisites
```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip python3-venv curl
```

#### 2. Configure Yama Ptrace (Required for Frida)
Linux restricts process tracing by default. Enable non-child ptrace for Frida:
```bash
sudo sysctl kernel.yama.ptrace_scope=0
# To make permanent across reboots:
echo "kernel.yama.ptrace_scope = 0" | sudo tee -a /etc/sysctl.d/10-ptrace.conf
```

#### 3. Install & Start Ollama with Gemma
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull gemma3:4b       # For Fault-Injection Cascade Analyzer & Fix Predictor
ollama pull gemma4:e4b      # Optional: for SemDiff behavioral analyst
```

#### 4. Setup Python Environment
```bash
cd semdiff                  # or repository root
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 5. Launch
- **Fault-Injection Dashboard & Gemma Fix Predictor (Port 5000):**
  ```bash
  python3 app.py
  # Or run the included script: ./start_dashboard.sh
  ```
  Open **http://127.0.0.1:5000** in your browser.

- **SemDiff Behavioral Difference Engine (Port 8000):**
  ```bash
  python3 server.py 8000
  ```
  Open **http://localhost:8000** in your browser.

- **CLI Direct Fault Injection Sweep:**
  ```bash
  python3 fault_injector.py --target /bin/sleep --args 30 --function nanosleep --register rdi --fault-type all
  ```

---

### Windows

You can run SemDiff and the Cascade Analyzer on Windows using either **WSL (Recommended for 100% Linux binary compatibility)** or **Native Windows PowerShell**.

#### Option A: WSL (Windows Subsystem for Linux) — Recommended
Because Frida targets ELF binaries (`/bin/sleep`, `/bin/cat`, `/bin/gzip`) and POSIX syscalls (`write`, `send`, `open`, `openat`), WSL provides seamless 1:1 execution parity with Linux:

1. Open PowerShell and launch your WSL distribution:
   ```powershell
   wsl
   ```
2. Follow the Linux instructions above:
   ```bash
   sudo apt update && sudo apt install -y build-essential python3-venv python3-pip curl
   sudo sysctl kernel.yama.ptrace_scope=0
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ollama pull gemma3:4b
   python3 app.py
   ```
3. Open `http://localhost:5000` in any Windows browser (WSL auto-forwards ports to Windows).

---

#### Option B: Windows Native (PowerShell / Command Prompt)

#### 1. Prerequisites
- **Python 3.10+**: Download from [python.org](https://www.python.org/downloads/) (make sure to check **"Add python.exe to PATH"** during installation).
- **Ollama for Windows**: Download from [ollama.ai/download/windows](https://ollama.ai/download/windows) and install.
  In PowerShell, pull the Gemma model:
  ```powershell
  ollama pull gemma3:4b
  ```
- **GCC (Optional, for SemDiff C compilation)**:
  - Install MinGW-w64 via WinLibs or MSYS2:
    ```powershell
    winget install MSYS2.MSYS2
    ```
  - Ensure `gcc` is in your `PATH` (`gcc --version`).

#### 2. Setup Virtual Environment
In PowerShell:
```powershell
# Navigate to repository
cd "C:\path\to\semdiff"

# Create virtual environment
python -m venv venv

# If execution policy blocks scripts, allow for current session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate environment
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

#### 3. Run Applications
- **Fault-Injection Dashboard & Gemma Fix Predictor:**
  ```powershell
  python app.py
  ```
  Navigate to **http://127.0.0.1:5000** in your browser.
  *(Note: You can inspect custom compiled Windows `.exe` binaries or use WSL for testing Linux utilities).*

- **SemDiff Differential Engine:**
  ```powershell
  python server.py 8000
  ```
  Navigate to **http://localhost:8000** in your browser.

---

### Troubleshooting & Common Issues

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `Frida: Failed to attach / ptrace` | Linux Yama ptrace restriction | Run `sudo sysctl kernel.yama.ptrace_scope=0` |
| `Could not reach local Gemma model` | Ollama service not running | Start Ollama: run `ollama serve` or launch Ollama desktop app |
| `gcc: command not found` | Compiler missing | Linux: `sudo apt install build-essential`<br>Windows: install MinGW-w64 or run inside WSL |
| `Scripts disabled on this system` | PowerShell ExecutionPolicy | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |


## What it does
- **Compile and diff real C** with your own gcc at any -O level (Demo page).
- **Behavior matching:** runs every function on hundreds of edge-case and random inputs, records calls, memory writes and return values, and matches functions without using names.
- **Handles compiler noise:** register allocation, 32/64-bit code, flags, inlined helper functions, memcpy calls vs inline block copies.
- **Exploit finder:** finds the input where the old build does a risky copy and bisects the exact threshold the new build enforces.
- **Benchmark page:** 12 real functions, same-source builds at different -O levels plus injected bugs.
- **Gemma 4 analyst:** thinking mode, function calling (compare, run_function, find_exploit, get_assembly), vision for screenshots of assembly.
- **Guided story** and downloadable Markdown/JSON reports.

## Honest limits
Differential testing is strong evidence, not a formal proof. Overlapping memcpy (undefined behavior) and extreme loop bounds are marked inconclusive, never reported as changes. Unsupported instructions (SSE/AVX, floating point, indirect calls) make a function "Not analyzed" instead of guessed. x86-64 only; the compile flags disable vectorization.

## Files
engine.js (interpreter, matching, classification, exploit finder) / server.py (static server + gcc) / app.js, gemma.js, story.js, bench.js / index.html, app.html, bench.html

## Contribute (Hacktoberfest welcome)
Ideas: SSE/AVX and floating point, AArch64, ELF import via Ghidra P-code, Z3 proof mode, more benchmark functions, loops with symbolic bounds. MIT licensed.
