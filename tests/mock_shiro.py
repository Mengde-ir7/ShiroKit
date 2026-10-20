#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地靶场：尽量按 Shiro / Spring 的真实行为模拟，用于自测工具。

MockShiro:
    * Cookie 格式 ``base64(IV + AES-CBC(...))``，用真实 AES 解密（与目标一致）；
    * 解密失败 / 反序列化失败 → ``rememberMe=deleteMe``（真实 Shiro 行为）；
    * ``leaky=True`` 时模拟“可区分 padding”的异常处理：padding 错返回 500，
      解密成功但反序列化失败返回 200 —— 这是 Shiro-721 能成立的前提；
    * 反序列化成功且是 URLDNS payload → 真的向回调监听器发一个 DNS 查询，
      用来验证工具的密钥爆破/回调匹配逻辑。

MockSpring:
    * 模拟 Shiro 过滤器 + Spring 路由的解析差异，仅用于验证绕过扫描器的判定逻辑。
"""

from __future__ import annotations

import base64
import random
import re
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from shirokit import aes


def dns_query(name: str, server: str = "127.0.0.1", port: int = 53,
              timeout: float = 1.0) -> None:
    """发一个 A 查询（不等响应），模拟目标端的 DNS 解析行为。"""
    qname = b"".join(bytes([len(label)]) + label.encode("ascii")
                     for label in name.split(".") if label) + b"\x00"
    packet = struct.pack(">HHHHHH", random.randrange(0, 65535), 0x0100, 1, 0, 0, 0)
    packet += qname + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockShiro/1.0"

    def _send(self, status: int, body: bytes, extra_headers: list[tuple[str, str]] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):  # noqa: C901
        owner: "MockShiro" = self.server.owner  # type: ignore[attr-defined]
        owner.requests += 1
        raw_cookie = self.headers.get("Cookie") or ""
        remember = None
        for part in raw_cookie.split(";"):
            if "=" in part:
                name, value = part.split("=", 1)
                if name.strip().lower() == "rememberme":
                    remember = value.strip()
                    break

        owner.log.append({"path": self.path, "remember": bool(remember)})

        if remember is None:
            self._send(200, b"<html><body>mock shiro home</body></html>")
            return

        record = {"path": self.path, "cookie_len": len(remember)}
        owner.payloads.append(record)

        try:
            raw = base64.b64decode(remember, validate=False)
        except Exception:  # noqa: BLE001
            self._fail(owner, record, "base64 解码失败")
            return

        if len(raw) <= 16 or (len(raw) - 16) % 16:
            self._fail(owner, record, "Cookie 长度非法")
            return

        iv, ciphertext = raw[:16], raw[16:]
        try:
            plaintext = aes.pkcs7_unpad(aes.cbc_decrypt(owner.key, ciphertext, iv))
        except Exception:  # noqa: BLE001
            record["padding_ok"] = False
            if owner.leaky:
                owner.padding_errors += 1
                self._send(500, b"<html><body>padding error</body></html>")
            else:
                self._fail(owner, record, "解密失败")
            return

        record["padding_ok"] = True
        record["plaintext_prefix"] = plaintext[:8].hex()
        if not plaintext.startswith(b"\xac\xed\x00\x05"):
            record["serialized"] = False
            if owner.leaky:
                owner.deserialize_errors += 1
                self._send(200, b"<html><body>deserialize error</body></html>")
            else:
                self._fail(owner, record, "反序列化失败")
            return

        record["serialized"] = True
        host = owner._extract_callback_host(plaintext)
        if host:
            record["dns_host"] = host
            dns_query(host, owner.dns_target[0], owner.dns_target[1])
            owner.remembered_payloads.append({"host": host, "plaintext": plaintext})
            self._send(200, b"<html><body>mock shiro home (logged in)</body></html>")
            return

        owner.executed.append(plaintext)
        self._send(200, b"<html><body>mock shiro home (logged in)</body></html>")

    def _fail(self, owner: "MockShiro", record: dict, why: str):
        record["error"] = why
        owner.failures += 1
        self._send(200, b"<html><body>mock shiro home</body></html>",
                   [("Set-Cookie", "rememberMe=deleteMe; Path=/; HttpOnly")])

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        return


class MockShiro:
    def __init__(self, key_b64: str, leaky: bool = False,
                 dns_target: tuple[str, int] = ("127.0.0.1", 5353),
                 callback_domain: str = "cb.test"):
        self.key = aes.b64decode_key(key_b64)
        self.key_b64 = key_b64
        self.leaky = leaky
        self.dns_target = dns_target
        self.callback_pattern = re.compile(
            r"([a-z0-9][a-z0-9\-\.]*\." + re.escape(callback_domain) + r")", re.I)
        self.requests = 0
        self.failures = 0
        self.padding_errors = 0
        self.deserialize_errors = 0
        self.log: list[dict] = []
        self.payloads: list[dict] = []
        self.remembered_payloads: list[dict] = []
        self.executed: list[bytes] = []
        self._server: ThreadingHTTPServer | None = None
        self.port = 0

    # -- 生命周期 ---------------------------------------------------------- #
    def start(self) -> "MockShiro":
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.owner = self  # type: ignore[attr-defined]
        self._server = server
        self.port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # -- 辅助 -------------------------------------------------------------- #
    def _extract_callback_host(self, plaintext: bytes) -> str | None:
        try:
            text = plaintext.decode("latin-1")
        except Exception:  # noqa: BLE001
            return None
        m = self.callback_pattern.search(text)
        return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# Spring + Shiro 权限绕过靶场
# --------------------------------------------------------------------------- #

_BYPASS_PATHS = {
    "/admin/..;/",
    "/admin/..;/admin/",
    "/;/admin/",
    "/admin/;",
    "/admin/;/",
    "/admin/%3b",
    "/admin/%3bxxx",
    "/admin/%3b/",
    "/admin/%2e",
    "/admin/%2e/",
    "/%2e/admin/",
    "/admin/%2e%2e/",
    "/admin/..;/..;/",
    "/admin/%2e%2e;/",
    "/admin/..%3b/",
    "//admin/",
    "//admin//",
    "/admin/./",
    "/admin/../admin/",
    "/admin/%20",
    "/admin/%09",
    "/admin/%0a",
    "/admin/%0d%0a",
    "/admin",
    "/admin.",
    "/admin;",
    "/admin.json",
    "/admin/index",
}


class _SpringHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, headers: list[tuple[str, str]] | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers or []:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        owner: "MockSpring" = self.server.owner  # type: ignore[attr-defined]
        owner.paths.append(self.path)
        if self.path in ("/login", "/login/"):
            self._send(200, b"<html><body><h1>Login</h1><form>username password</form>"
                            b"<p>" + b"login page " * 40 + b"</p></body></html>")
            return
        if self.path == "/admin/" or self.path.startswith("/admin/?") or \
                (self.path.startswith("/admin/") and ".." not in self.path and
                 ";" not in self.path and "%" not in self.path):
            self._send(302, b"", [("Location", "/login")])
            return
        if self.path in _BYPASS_PATHS:
            body = (b"<html><body><h1>Admin Dashboard</h1>"
                    b"<table><tr><td>user list</td></tr></table>"
                    b"<p>" + b"admin panel content " * 60 + b"</p></body></html>")
            self._send(200, body)
            return
        body = b"<html><body>not found</body></html>"
        self._send(404, body)

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        return


class MockSpring:
    def __init__(self):
        self.paths: list[str] = []
        self._server: ThreadingHTTPServer | None = None
        self.port = 0

    def start(self) -> "MockSpring":
        server = ThreadingHTTPServer(("127.0.0.1", 0), _SpringHandler)
        server.daemon_threads = True
        server.owner = self  # type: ignore[attr-defined]
        self._server = server
        self.port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

