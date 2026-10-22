# php2shell: Dissecting PHP's Critical Session Upload Progress Vulnerabilities

*CVE-2026-109618 & CVE-2026-109619 — From source code audit to three independent RCE chains*

---

On October 20, 2026, PHP's security team announced an emergency release for two critical vulnerabilities rated CVSS v4.0 9.2, scheduled for October 21 at 14:00 UTC. Details leaked early, a proof-of-concept tool called "PHP2Shell" surfaced, and the security community scrambled to understand the impact.

I spent the past 24 hours building a lab, reading PHP source code line by line, and constructing working exploits from scratch. Here's what I found — including attack paths that weren't in any of the leaked POCs.

**TL;DR:** Three independent RCE chains, all exploiting PHP's `session.upload_progress` feature (enabled by default since PHP 5.4). One requires LFI, one requires unserialize, and the third — the one I discovered during this research — chains a session handler mismatch with `__destruct` execution on deserialization failure.

## The Attack Surface

PHP's `session.upload_progress` feature, introduced in PHP 5.4.0, tracks multipart file upload progress in session data. It processes multipart POST bodies **before application code runs** — in the SAPI layer's `php_session_rfc1867_callback`.

This means:
- No authentication required
- No application code involvement
- The handler creates session files with attacker-controllable data
- It runs on **any** PHP endpoint that accepts POST requests

## Bug 1: Session Fixation

The `MULTIPART_EVENT_FORMDATA` handler accepts session IDs from the POST body **without checking `session.use_only_cookies`**:

```c
// ext/session/session.c — MULTIPART_EVENT_FORMDATA
if (name_len == progress->sname_len && 
    memcmp(data->name, PS(session_name), name_len) == 0) {
    ZVAL_STRINGL(&progress->sid, (*data->value), value_len);
    // ← No use_only_cookies check!
}
```

An attacker sends `PHPSESSID=controlled_value` in the multipart body → controls the session file path.

**Fix:** [PR #22113](https://github.com/php/php-src/pull/22113) — adds `!PS(use_only_cookies) &&` guard.

## Bug 2: Unvalidated Filename Injection

The upload filename is stored **raw** in the session file:

```c
// ext/session/session.c — FILE_START handler
add_assoc_string_ex(&progress->current_file, "name", 
                    sizeof("name") - 1, *data->filename);
```

No sanitization. No encoding. A filename of `<?php system('id');?>` is stored as-is. Combined with session fixation (Bug 1) and any LFI vulnerability, this gives pre-auth RCE.

I verified this on PHP 8.2.34:

```
$ python3 exploit_session_inject.py --command 'id && uname -a'
[+] RCE CONFIRMED!
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 5b5e45fd8525 6.8.0-117-generic x86_64 GNU/Linux
```

## Bug 3: var_destroy `__destruct` Reentry UAF

This is the memory corruption bug. In `ext/standard/var_unserializer.re`, the `var_destroy` function:

1. **Phase 1** (line 245): Frees back-reference extension chunks via `efree_size()`
2. **Phase 2** (line 310): Calls `i_zval_ptr_dtor(zv)` — **without `BG(serialize_lock)`**

If `__destruct` fires during Phase 2 (which it does for objects moved to the dtor list via duplicate-key handling), and the destructor calls `unserialize()`, the inner parser **reuses the outer's var_hash** (because `BG(serialize_lock)==0` and `BG(unserialize).level>0`).

The inner `R:1500;` back-reference walks into the freed extension chunks from Phase 1 → **heap-use-after-free**.

ASAN confirmed on PHP 8.2.34:
```
ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 at 0xfffff0cb6900 thread T0
    #0 php_var_unserialize at var_unserializer.c:851
    #13 var_destroy at var_unserializer.c:310
freed at:
    #3 var_destroy at var_unserializer.c:245
```

I turned this into full RCE on x86-64 by:
1. Using the UAF read to discover `zif_system` via `executor_globals.function_table`
2. Overwriting `var_dump`'s handler pointer with `zif_system` via `/proc/self/mem`
3. Calling `var_dump('id > /tmp/proof')` → `system('id > /tmp/proof')` → RCE

## The Novel Finding: Handler Mismatch → `__destruct`

Here's where it gets interesting. During my analysis, I discovered a chain that doesn't require LFI or application-level `unserialize()`.

### The Setup

PHP's session data can be serialized with different handlers (`php`, `php_serialize`, `php_binary`). If two directories on the same server use different handlers via `.user.ini`, the session file format depends on which directory handles the request.

### The Key Insight: `__destruct` Fires on Decode Failure

When the `php` handler reads data written by `php_serialize`, the format mismatch causes a decode **FAILURE**. PHP's `session_start()` calls `php_session_cancel_decode()` to destroy the session.

But here's the critical finding: **`__destruct` fires BEFORE the session is destroyed.** The `PHP_VAR_UNSERIALIZE_DESTROY(var_hash)` cleanup runs on both success and failure paths, and object destructors fire during this cleanup.

```
garbage|O:4:"Evil":1:{s:3:"cmd";s:22:"id > /tmp/rce_proof";}TRAILING_JUNK
       ↑                                                     ↑
       php handler splits here                                trailing data → FAILURE
       O:4:"Evil" deserialized                                but __destruct ALREADY FIRED
```

### The Complete Chain

```
Request 1 → POST /app/ (php_serialize handler)
  Filename: x|O:4:"Evil":1:{s:3:"cmd";s:N:"COMMAND";}
  → Session file in php_serialize format, | preserved in filename string

Request 2 → POST /api/ (php handler, same session save_path)  
  → rfc1867 reads session with php handler → mismatch
  → Finds | → deserializes Evil object → decode FAILURE
  → __destruct("COMMAND") fires during var_hash cleanup → RCE!
```

This entire chain executes **inside the rfc1867 handler**, before any application code runs. The only requirements are:
1. Two directories with different `session.serialize_handler` (common in multi-app setups)
2. A class with exploitable `__destruct` loaded via `opcache.preload` (standard for Laravel/Symfony)

Verified on PHP 8.2.34 FPM:
```
DESTRUCT! cmd=id; uname -a; hostname
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 5b5e45fd8525 6.8.0-117-generic aarch64 GNU/Linux
```

## Impact

| Scenario | Attack Chain | Requirements |
|----------|-------------|-------------|
| App with LFI (WordPress plugins, etc.) | Session injection → include → RCE | Default PHP config |
| App with unserialize (Laravel, Magento) | var_destroy UAF → memory corruption → RCE | Default PHP config |
| Multi-dir setup with handler mismatch | Session mismatch → `__destruct` → RCE | Different `.user.ini` per directory |
| OPcache preload + handler mismatch | Pure rfc1867 `__destruct` → RCE | opcache.preload + handler mismatch |

**Affected:** PHP 5.4.0 through 8.5.11 (every version with `session.upload_progress`)  
**Fixed in:** 8.2.35, 8.3.36, 8.4.27, 8.5.12

## Mitigation

```ini
; Immediate (does NOT fix all chains)
session.upload_progress.enabled = Off
session.use_only_cookies = On

; Ensure consistent handler across all directories
session.serialize_handler = php_serialize
```

**The only complete fix is patching PHP.**

## POCs and Lab

Verification POCs (no weaponized exploits) are available at:
**[github.com/bahartanir/php2shell](https://github.com/bahartanir/php2shell)**

The repo includes a Docker lab setup and three verification scripts covering each attack chain.

---

*Full exploit code with the handler mismatch RCE chain and the var_destroy UAF → handler overwrite chain is available to paid subscribers below.*

---

## [Paid] Exploit: Handler Mismatch → `__destruct` RCE

*(This section is for paid subscribers)*

The complete exploit automates all three steps of Chain C...

## [Paid] Exploit: var_destroy UAF → Function Handler Overwrite

*(This section is for paid subscribers)*

The UAF exploit chains the var_destroy reentry bug with `/proc/self/mem` symbol discovery...

## [Paid] Exploit: Session Injection + LFI → One-Shot RCE

*(This section is for paid subscribers)*

The simplest chain — inject PHP code in the filename and include the session file...
