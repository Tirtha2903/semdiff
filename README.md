# SemDiff

Compare two builds of a program and see only what changed in **behavior**, not bytes.
The engine proves and locates changes. Gemma 4, running locally through Ollama, investigates and explains them.

## Run (Ubuntu)
    cd semdiff
    python3 server.py              # open http://localhost:8000
    ollama pull gemma4:e4b         # optional: enables the Gemma 4 analyst
Compiling real C needs gcc: `sudo apt install build-essential`.

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
