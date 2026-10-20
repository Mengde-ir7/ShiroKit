#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shiro 指纹识别。

除了检查响应头里的 rememberMe，还做了三件事：
    1. 同时看响应头、响应体，以及访问不存在路径时的行为；
    2. 主动发送一个**格式合法但密钥错误**的 rememberMe，确认服务端是否回写
       ``rememberMe=deleteMe`` —— 这决定后续能不能用 deleteMe 做判定；
    3. 尝试从错误页/异常栈里提取 Shiro 版本，便于直接映射 CVE。
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field

from .httpc import HttpClient, Response, join_url, normalize_base
from . import rememberme

_VERSION_PATTERNS = [
    re.compile(r"shiro[-_ ]?(?:core|web|spring|all)?[-_ ]?v?(\d+\.\d+\.\d+)", re.I),
    re.compile(r"org\.apache\.shiro[^\s]*?-(\d+\.\d+\.\d+)"),
    re.compile(r"Apache Shiro[^\d]{0,10}(\d+\.\d+\.\d+)", re.I),
]


@dataclass
class Fingerprint:
    url: str
    shiro: bool = False
    remember_me_seen: bool = False
    delete_me: bool = False
    oracle_ready: bool = False
    version: str | None = None
    evidence: list[str] = field(default_factory=list)
    responses: list[Response] = field(default_factory=list)

    def describe(self) -> str:
        lines = [f"目标: {self.url}"]
        lines.append(f"Shiro 指纹: {'是' if self.shiro else '否/不确定'}")
        lines.append(f"rememberMe Cookie: {'出现' if self.remember_me_seen else '未出现'}")
        lines.append(f"deleteMe 行为: {'有' if self.delete_me else '无'}")
        lines.append(f"版本线索: {self.version or '未识别'}")
        for ev in self.evidence:
            lines.append(f"  - {ev}")
        return "\n".join(lines)


def _scan_hints(text: str) -> tuple[bool, str | None]:
    lowered = text.lower()
    has = "rememberme" in lowered or "shiro" in lowered
    version = None
    for pattern in _VERSION_PATTERNS:
        m = pattern.search(text)
        if m:
            version = m.group(1)
            break
    return has, version


def fingerprint(client: HttpClient, url: str, verbose: bool = True) -> Fingerprint:
    base = normalize_base(url)
    fp = Fingerprint(url=base)

    root = client.get(base + "/")
    fp.responses.append(root)
    for name, value in root.cookie_pairs():
        if name.lower() == rememberme.COOKIE_NAME.lower():
            fp.remember_me_seen = True
            fp.evidence.append(f"根路径响应头出现 {name}={value[:16]}")
    body_hint, version = _scan_hints(root.text)
    if body_hint:
        fp.evidence.append("根路径响应体出现 rememberMe/shiro 字样")

    # 访问随机不存在路径：Shiro 的过滤器依旧会处理 rememberMe
    probe_path = "/" + "".join(random.choices(string.ascii_lowercase, k=10)) + ".txt"
    missing = client.get(join_url(base, probe_path))
    fp.responses.append(missing)
    for name, value in missing.cookie_pairs():
        if name.lower() == rememberme.COOKIE_NAME.lower():
            fp.remember_me_seen = True
            fp.evidence.append(f"不存在路径响应头出现 {name}={value[:16]}")
    body_hint2, version2 = _scan_hints(missing.text)
    if body_hint2:
        fp.evidence.append("不存在路径响应体出现 rememberMe/shiro 字样")
    fp.version = version or version2

    # 主动探测：格式合法但密钥错误的 Cookie
    baseline = rememberme.baseline_probe(client, base + "/")
    fp.responses.append(baseline.resp)
    fp.delete_me = baseline.delete_me
    if baseline.delete_me:
        fp.delete_me = True
        fp.oracle_ready = True
        fp.evidence.append("发送无效 rememberMe 后回写 rememberMe=deleteMe")
    elif fp.remember_me_seen:
        fp.evidence.append("能看到 rememberMe Cookie，但无效 Cookie 未触发 deleteMe")

    if "org.apache.shiro" in missing.text.lower() or "org.apache.shiro" in root.text.lower():
        fp.evidence.append("响应中出现 org.apache.shiro 异常栈")
    if "unavailablesecuritymanagerexception" in (root.text + missing.text).lower():
        fp.evidence.append("UnavailableSecurityManagerException（Shiro 已加载但未初始化）")

    fp.shiro = bool(fp.remember_me_seen or fp.delete_me or
                    any("shiro" in e.lower() for e in fp.evidence))
    if verbose:
        print(fp.describe())
    return fp
