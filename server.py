#!/usr/bin/env python3
"""SemDiff local server: serves the web app and compiles C with your own gcc.
Run:  python3 server.py        then open http://localhost:8000
Binds to 127.0.0.1 only. Needs gcc (sudo apt install build-essential)."""
import http.server, json, os, re, shutil, subprocess, sys, tempfile

HDR = "#include <string.h>\n#include <stdlib.h>\n#include <stdio.h>\n#include <stdint.h>\n"
FLAGS = ["-S", "-masm=intel", "-fno-asynchronous-unwind-tables", "-fcf-protection=none", "-fno-pie",
         "-fno-stack-protector", "-fno-ident", "-fno-tree-vectorize", "-fno-tree-slp-vectorize", "-mno-sse", "-fno-builtin"]

def ret_bits(source):
    out = {}
    for m in re.finditer(r'^([A-Za-z_][^\n(){};=]*?)\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{', source, re.M):
        t, name = m.group(1), m.group(2)
        if re.fullmatch(r'\s*(static\s+|inline\s+)*void\s*', t): bits = 0
        elif '*' in t or re.search(r'\b(long|size_t|ssize_t|uintptr_t|intptr_t|int64_t|uint64_t|ptrdiff_t)\b', t): bits = 64
        elif re.search(r'\b(char|bool|_Bool|int8_t|uint8_t)\b', t): bits = 8
        elif re.search(r'\b(short|int16_t|uint16_t)\b', t): bits = 16
        else: bits = 32
        out[name] = bits
    return out

def clean(asm):
    out = []
    for line in asm.splitlines():
        s = line.split('#')[0].rstrip()
        if not s.strip() or re.match(r'^\s+\.', s) or re.match(r'^\.L(FB|FE|C)\d+:', s): continue
        if s.endswith(':') and s[0] not in ' \t': out.append(s); continue
        s = s.strip().replace('@PLT', '')
        parts = re.split(r'\s+', s, maxsplit=1)
        ops = parts[1] if len(parts) > 1 else ''
        ops = re.sub(r'(-?\d+)\[([^\]]+)\]', lambda m: '[%s%+d]' % (m.group(2), int(m.group(1))), ops)
        out.append('  ' + parts[0] + (' ' + ops if ops else ''))
    return '\n'.join(out)

def compile_c(source, opt):
    if not shutil.which('gcc'): raise RuntimeError('gcc not found. Install it with: sudo apt install build-essential')
    if str(opt) not in ('0', '1', '2', '3', 's'): raise RuntimeError('bad optimization level')
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'x.c')
        open(p, 'w').write(HDR + source)
        r = subprocess.run(['gcc', '-O' + str(opt)] + FLAGS + ['-o', '-', p], capture_output=True, text=True, timeout=20)
        if r.returncode: raise RuntimeError(r.stderr.replace(d + '/', '')[:1500])
        ver = subprocess.run(['gcc', '--version'], capture_output=True, text=True).stdout.splitlines()[0]
        return {'asm': clean(r.stdout), 'ret': ret_bits(source), 'gcc': ver + ' -O' + str(opt)}

class H(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        try:
            if self.path != '/api/compile': raise RuntimeError('unknown endpoint')
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            res, code = compile_c(body.get('source', ''), body.get('opt', '2')), 200
        except Exception as e:
            res, code = {'error': str(e)}, 400
        data = json.dumps(res).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def log_message(self, *a): pass

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print('SemDiff running at http://localhost:%d  (gcc: %s)' % (port, 'found' if shutil.which('gcc') else 'MISSING'))
    http.server.ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
