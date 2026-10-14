import subprocess
import sys
import time

cmd = [
    sys.executable, "fault_injector.py",
    "--target", "/bin/sleep",
    "--function", "nanosleep",
    "--register", "rdi",
    "--fault-type", "all",
    "--observe-seconds", "3",
    "--output", "/tmp/fault_report_isolated.json",
    "--args", "5",
]

print("Launching via subprocess.run (output to file, not pipes)...")
started = time.time()

with open("/tmp/subproc_stdout.log", "w") as out:
    proc = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT, timeout=60)

print(f"Done in {time.time()-started:.1f}s, code={proc.returncode}")
print("---OUTPUT (from log file)---")
with open("/tmp/subproc_stdout.log") as f:
    print(f.read())
