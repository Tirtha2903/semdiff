#!/usr/bin/env python3
"""
fault_injector.py — Binary-Level Fault-Injection Cascade Analyzer
Spawns a target binary under Frida's control, injects a controlled fault
(bitflip / register / retaddr), watches syscall boundaries, and reports
the blast radius of that one fault type.
"""

import argparse
import json
import sys
import time
import threading
from datetime import datetime

try:
    import frida
except ImportError:
    print("Frida is not installed. Run: pip install frida frida-tools")
    sys.exit(1)


AGENT_SRC = r"""
'use strict';

function safeSend(entry) {
    try {
        entry.ts = Date.now();
        send({ type: 'event', payload: entry });
    } catch (e) {}
}

function findExport(name) {
    try {
        if (Module.findGlobalExportByName) {
            const a = Module.findGlobalExportByName(name);
            if (a) return a;
        }
    } catch (e) {}
    try {
        return Module.findExportByName(null, name);
    } catch (e) {
        return null;
    }
}

function hookBoundary(name) {
    try {
        const addr = findExport(name);
        if (addr === null || addr === undefined) {
            safeSend({ kind: 'hook-missing', fn: name });
            return;
        }
        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    if (name === 'write' || name === 'send') {
                        const fd = args[0].toInt32();
                        const len = args[2] ? args[2].toInt32() : 0;
                        const n = Math.max(0, Math.min(len, 64));
                        let preview = '';
                        if (n > 0) {
                            try { preview = hexdump(args[1], { length: n, ansi: false }); }
                            catch (e) { preview = '<unreadable>'; }
                        }
                        safeSend({ kind: 'boundary-call', fn: name, fd, len, preview });
                    } else if (name === 'open' || name === 'openat') {
                        const pathPtr = (name === 'open') ? args[0] : args[1];
                        let path = '<unreadable>';
                        try { path = pathPtr.readCString(); } catch (e) {}
                        safeSend({ kind: 'boundary-call', fn: name, path });
                    }
                } catch (e) {
                    safeSend({ kind: 'boundary-call-error', fn: name, error: e.message });
                }
            }
        });
        safeSend({ kind: 'hook-installed', fn: name, addr: addr.toString() });
    } catch (e) {
        safeSend({ kind: 'hook-error', fn: name, error: e.message });
    }
}

function faultBitFlip(addrHex, regionSize) {
    try {
        const base = ptr(addrHex);
        const byteOffset = Math.floor(Math.random() * regionSize);
        const bitOffset = Math.floor(Math.random() * 8);
        const target = base.add(byteOffset);
        const before = target.readU8();
        const after = before ^ (1 << bitOffset);
        target.writeU8(after);
        safeSend({
            kind: 'fault-bitflip', address: target.toString(),
            byteOffset, bitOffset,
            before: '0x' + before.toString(16), after: '0x' + after.toString(16)
        });
    } catch (e) {
        safeSend({ kind: 'fault-bitflip-error', error: e.message });
    }
}

function faultRegister(fnAddrHex, regName, garbageHex) {
    try {
        const fnAddr = ptr(fnAddrHex);
        const garbage = ptr(garbageHex);
        const listener = Interceptor.attach(fnAddr, {
            onEnter(args) {
                try {
                    const ctx = this.context;
                    const before = ctx[regName];
                    if (before === undefined) {
                        safeSend({ kind: 'fault-register-error', error: 'unknown register ' + regName });
                    } else {
                        ctx[regName] = garbage;
                        safeSend({ kind: 'fault-register', fn: fnAddrHex, reg: regName,
                                   before: before.toString(), after: garbage.toString() });
                    }
                } catch (e) {
                    safeSend({ kind: 'fault-register-error', error: e.message });
                }
                listener.detach();
            }
        });
        safeSend({ kind: 'fault-register-armed', fn: fnAddrHex, reg: regName });
    } catch (e) {
        safeSend({ kind: 'fault-register-error', error: e.message });
    }
}

function faultReturnAddress(fnAddrHex, garbageHex) {
    try {
        const fnAddr = ptr(fnAddrHex);
        const garbage = ptr(garbageHex);
        const listener = Interceptor.attach(fnAddr, {
            onEnter(args) {
                try {
                    const ctx = this.context;
                    const sp = ctx.sp;
                    const main = Process.enumerateModules()[0];
                    const lo = main.base;
                    const hi = main.base.add(main.size);
                    let patched = false;
                    for (let i = 0; i < 12; i++) {
                        const slot = sp.add(i * Process.pointerSize);
                        let val;
                        try { val = slot.readPointer(); } catch (e) { continue; }
                        if (val.compare(lo) >= 0 && val.compare(hi) < 0) {
                            slot.writePointer(garbage);
                            safeSend({ kind: 'fault-retaddr', fn: fnAddrHex, slot: slot.toString(),
                                       before: val.toString(), after: garbage.toString() });
                            patched = true;
                            break;
                        }
                    }
                    if (!patched) {
                        safeSend({ kind: 'fault-retaddr-notfound', fn: fnAddrHex, sp: sp.toString() });
                    }
                } catch (e) {
                    safeSend({ kind: 'fault-retaddr-error', error: e.message });
                }
                listener.detach();
            }
        });
        safeSend({ kind: 'fault-retaddr-armed', fn: fnAddrHex });
    } catch (e) {
        safeSend({ kind: 'fault-retaddr-error', error: e.message });
    }
}

Process.setExceptionHandler(details => {
    safeSend({ kind: 'crash', type: details.type,
               address: details.address ? details.address.toString() : null });
    return false;
});

rpc.exports = {
    hookboundaries(names) {
        names.forEach(hookBoundary);
        return true;
    },
    findexport(name) {
        const a = findExport(name);
        return a ? a.toString() : null;
    },
    mainmodule() {
        const m = Process.enumerateModules()[0];
        return { base: m.base.toString(), size: m.size, name: m.name };
    },
    findwritable(size) {
        try {
            const ranges = Process.enumerateRanges('rw-');
            for (const r of ranges) {
                if (r.size >= size + 16) {
                    return r.base.add(8).toString();
                }
            }
            return null;
        } catch (e) {
            return null;
        }
    },
    dobitflip(addrHex, regionSize) {
        faultBitFlip(addrHex, regionSize);
        return true;
    },
    doregisterfault(fnAddrHex, regName, garbageHex) {
        faultRegister(fnAddrHex, regName, garbageHex);
        return true;
    },
    doretaddrfault(fnAddrHex, garbageHex) {
        faultReturnAddress(fnAddrHex, garbageHex);
        return true;
    }
};
"""


class DeadProcess(Exception):
    pass


class FaultInjector:
    def __init__(self, target_args, target_function, region_size, garbage_hex):
        self.target_args = target_args
        self.target_function = target_function
        self.region_size = region_size
        self.garbage_hex = garbage_hex
        self.events = []
        self.pid = None
        self.session = None
        self.script = None
        self.process_dead = False

    def _on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict) and payload.get('type') == 'event':
                ev = payload['payload']
                ev['_recv_t'] = time.time()
                self.events.append(ev)
                self._print_event(ev)
                if ev.get('kind') == 'crash':
                    self.process_dead = True
        elif message['type'] == 'error':
            print(f"[agent error] {message.get('stack', message)}")

    def _on_detached(self, reason, crash):
        self.process_dead = True
        print(f"[*] Target process detached (reason: {reason})")

    @staticmethod
    def _print_event(ev):
        kind = ev.get('kind', '?')
        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        if kind == 'crash':
            print(f"[{ts}] !!! CRASH  type={ev.get('type')} addr={ev.get('address')}")
        elif kind == 'boundary-call':
            extra = ev.get('path') or f"fd={ev.get('fd')} len={ev.get('len')}"
            print(f"[{ts}] boundary  {ev.get('fn')}({extra})")
        elif kind.startswith('fault-') and kind.endswith('-error'):
            print(f"[{ts}] FAULT FAILED  {kind}: {ev.get('error')}")
        elif kind.startswith('fault-'):
            print(f"[{ts}] fault     {kind}  {ev}")
        elif kind == 'hook-installed':
            print(f"[{ts}] hooked    {ev.get('fn')} @ {ev.get('addr')}")
        elif kind == 'hook-missing':
            print(f"[{ts}] (no export named {ev.get('fn')} found — skipped)")
        elif kind == 'hook-error':
            print(f"[{ts}] (hook error for {ev.get('fn')}: {ev.get('error')})")
        else:
            print(f"[{ts}] {kind}  {ev}")

    def _safe_call(self, fn, *fn_args, timeout=2.0):
        if self.process_dead:
            raise DeadProcess("process already marked dead")
        result = {}
        error = {}

        def worker():
            try:
                result['value'] = fn(*fn_args)
            except Exception as e:
                error['e'] = e

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            self.process_dead = True
            raise DeadProcess("RPC call timed out — process is gone")
        if 'e' in error:
            self.process_dead = True
            raise DeadProcess(str(error['e']))
        return result.get('value')

    def start(self):
        print(f"[*] Spawning: {' '.join(self.target_args)}")
        self.pid = frida.spawn(self.target_args)
        self.session = frida.attach(self.pid)
        self.session.on('detached', self._on_detached)
        self.script = self.session.create_script(AGENT_SRC)
        self.script.on('message', self._on_message)
        self.script.load()

        print("[*] Hooking boundary syscalls: write, send, open, openat")
        self._safe_call(self.script.exports_sync.hookboundaries,
                         ['write', 'send', 'open', 'openat'])

    def resume_now(self):
        print("[*] Resuming process")
        frida.resume(self.pid)
        time.sleep(0.3)

    def resolve_target_function(self):
        try:
            addr = self._safe_call(self.script.exports_sync.findexport, self.target_function)
        except DeadProcess:
            print("[!] Skipped: target process is no longer running.")
            return None
        if addr is None:
            print(f"[!] Could not find exported function '{self.target_function}'. "
                  f"Try --function with something the target actually calls "
                  f"(e.g. nanosleep, malloc, read, write).")
        else:
            print(f"[*] Target function '{self.target_function}' resolved to {addr}")
        return addr

    def run_bitflip(self):
        try:
            addr = self._safe_call(self.script.exports_sync.findwritable, self.region_size)
        except DeadProcess:
            print("[!] Skipped bit-flip: target process is no longer running.")
            return
        if addr is None:
            print("[!] Could not find a writable region to bit-flip.")
            return
        print(f"[*] Bit-flip target region: writable heap/data @ {addr} "
              f"(window of {self.region_size} bytes)")
        try:
            self._safe_call(self.script.exports_sync.dobitflip, addr, self.region_size)
        except DeadProcess:
            print("[!] Bit-flip did not complete: target process is no longer running.")

    def run_register_fault(self, fn_addr, reg='rax'):
        print(f"[*] Arming register corruption: {reg} -> {self.garbage_hex} "
              f"on next call to {self.target_function}")
        try:
            self._safe_call(self.script.exports_sync.doregisterfault,
                             fn_addr, reg, self.garbage_hex)
        except DeadProcess:
            print("[!] Skipped register fault: target process is no longer running.")

    def run_retaddr_fault(self, fn_addr):
        print(f"[*] Arming return-address corruption on next call to {self.target_function}")
        try:
            self._safe_call(self.script.exports_sync.doretaddrfault, fn_addr, self.garbage_hex)
        except DeadProcess:
            print("[!] Skipped return-address fault: target process is no longer running.")

    def wait_and_report(self, seconds, out_path, fault_type):
        print(f"[*] Observing for {seconds}s...")
        time.sleep(seconds)

        def _detach():
            try:
                self.session.detach()
            except Exception:
                pass

        t = threading.Thread(target=_detach, daemon=True)
        t.start()
        t.join(2.0)
        if t.is_alive():
            print("[*] (detach is taking too long on an already-dead process — skipping, no data lost)")

        report = self._build_blast_radius_report()
        print("\n" + "=" * 70)
        print(f"BLAST RADIUS RESULT — fault type: {fault_type}")
        print("=" * 70)
        if not report:
            print("  [LOW       ] no-effect-observed    -> fault ran but caused no observable crash "
                  "or boundary activity")
        for row in report:
            print(f"  [{row['severity']:<10}] {row['fault']:<20} -> {row['reason']}")
        print("=" * 70)

        result_summary = {
            'fault_type': fault_type,
            'severity': report[0]['severity'] if report else 'LOW',
            'reason': report[0]['reason'] if report else 'fault ran but caused no observable effect',
            'process_crashed': self.process_dead,
        }

        if out_path:
            with open(out_path, 'w') as f:
                json.dump({'events': self.events, 'ranking': report, 'summary': result_summary}, f, indent=2)
            print(f"[*] Full event log + result written to {out_path}")

        return result_summary

    def _build_blast_radius_report(self):
        fault_kinds = [e for e in self.events if e.get('kind', '').startswith('fault-')
                       and not e['kind'].endswith('-error') and not e['kind'].endswith('-armed')]
        report = []
        for fe in fault_kinds:
            window_start = fe['_recv_t']
            window_end = window_start + 2.0
            followups = [e for e in self.events
                         if window_start <= e['_recv_t'] <= window_end and e is not fe]
            crashed = any(e.get('kind') == 'crash' for e in followups) or self.process_dead
            leaked = any(e.get('kind') == 'boundary-call' for e in followups)
            if crashed:
                severity, reason = "CRITICAL", "caused an immediate process crash"
            elif leaked:
                severity, reason = "HIGH", "process kept running and still crossed the write/send/open boundary afterward"
            else:
                severity, reason = "LOW", "no observable crash or boundary activity in the 2s window after injection"
            report.append({'fault': fe['kind'], 'severity': severity, 'reason': reason})

        order = {'CRITICAL': 0, 'HIGH': 1, 'LOW': 2}
        report.sort(key=lambda r: order.get(r['severity'], 9))
        return report


def run_one(args, fault_type):
    target_args = [args.target] + args.args
    injector = FaultInjector(target_args, args.function, args.region_size, args.garbage)

    injector.start()

    if fault_type in ('register', 'retaddr'):
        fn_addr = injector.resolve_target_function()
        if fault_type == 'register' and fn_addr:
            injector.run_register_fault(fn_addr, reg=args.register)
        elif fault_type == 'retaddr' and fn_addr:
            injector.run_retaddr_fault(fn_addr)

    print(f"\n[*] --- Resuming process with '{fault_type}' fault armed ---\n")
    injector.resume_now()
    time.sleep(1.0)

    if fault_type == 'bitflip':
        injector.run_bitflip()
        time.sleep(1.5)

    out_file = args.output.replace('.json', f'_{fault_type}.json') if args.output else None
    return injector.wait_and_report(args.observe_seconds, out_file, fault_type)


def main():
    ap = argparse.ArgumentParser(description="Binary-Level Fault-Injection Cascade Analyzer")
    ap.add_argument('--target', required=True)
    ap.add_argument('--args', nargs='*', default=[])
    ap.add_argument('--function', default='nanosleep')
    ap.add_argument('--region-size', type=int, default=64)
    ap.add_argument('--garbage', default='0xDEADBEEF')
    ap.add_argument('--register', default='rax')
    ap.add_argument('--observe-seconds', type=float, default=4.0)
    ap.add_argument('--output', default='fault_report.json')
    ap.add_argument('--fault-type', choices=['bitflip', 'register', 'retaddr', 'all'],
                     default='all',
                     help="Which fault to inject. 'all' runs all three as separate "
                          "clean passes and prints a combined comparison table.")
    args = ap.parse_args()

    if args.fault_type != 'all':
        run_one(args, args.fault_type)
        return

    # Run all three fault types as separate clean passes, then compare.
    summaries = []
    for ft in ['bitflip', 'register', 'retaddr']:
        print("\n" + "#" * 70)
        print(f"#  PASS: {ft.upper()}")
        print("#" * 70)
        summary = run_one(args, ft)
        summaries.append(summary)
        time.sleep(1.0)  # brief pause between passes

    order = {'CRITICAL': 0, 'HIGH': 1, 'LOW': 2}
    summaries.sort(key=lambda s: order.get(s['severity'], 9))

    print("\n" + "=" * 70)
    print("FINAL COMPARATIVE BLAST RADIUS RANKING (most to least dangerous)")
    print("=" * 70)
    for s in summaries:
        print(f"  [{s['severity']:<10}] {s['fault_type']:<10} -> {s['reason']}")
    print("=" * 70)

    with open(args.output, 'w') as f:
        json.dump({'comparative_ranking': summaries}, f, indent=2)
    print(f"[*] Comparative ranking written to {args.output}")


if __name__ == '__main__':
    main()
