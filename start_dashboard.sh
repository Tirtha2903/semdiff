#!/bin/bash
cd ~/Downloads/semdiff
source venv/bin/activate
sudo sysctl kernel.yama.ptrace_scope=0
echo "Starting dashboard — wait for 'Gemma is warmed up and ready' before opening the browser..."
python3 app.py
