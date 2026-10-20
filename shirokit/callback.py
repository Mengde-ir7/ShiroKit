#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内置回调服务器：DNS（UDP/53）+ HTTP。

为什么需要它：
    URLDNS 是唯一不依赖第三方 gadget 的探测链，它只能产生一次 DNS 解析。
    不少公开脚本把这件事交给外部 dnslog 平台，并靠响应猜测判定。本模块让工具
    自己收 DNS 查询，从而可以精确判断“这个随机子域名被解析了”等价于
    “这个密钥解密成功了”。

使用前提（很重要）：
    目标必须能把这个域名解析到本机，例如：
      * 把 ``cb.你的域名`` 的 A 记录 / NS 记录指向攻击机公网 IP；
      * 内网环境直接改目标 DNS 或 hosts，把 ``cb.lab`` 指到本机；
      * 使用你自己搭建的权威 DNS，把 zone 委派给本监听器。
    纯内网 IP（如 10.0.0.5）不能作为 URLDNS 的 host —— java.net.URL 对
    字面 IP 不会做 DNS 查询，这是 URLDNS 的固有局限。
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class DnsHit:
    qname: str
    source: str
    qtype: int
    time: float


@dataclass
class HttpHit:
    method: str
    path: str
    source: str
    headers: dict[str, str] = field(default_factory=dict)
    time: float = 0.0


def _parse_dns_query(data: bytes) -> tuple[str, int] | tuple[None, None]:
    if len(data) < 12:
        return None, None
    qdcount = struct.unpack(">H", data[4:6])[0]
    if qdcount < 1:
        return None, None
    pos = 12
    labels: list[str] = []
    while pos < len(data):
        length = data[pos]
        pos += 1
        if length == 0:
            break
        if length & 0xC0:          # 查询报文里不应出现压缩指针
            break
        labels.append(data[pos:pos + length].decode("ascii", "replace"))
        pos += length
    if pos + 4 > len(data):
        return None, None
    qtype = struct.unpack(">H", data[pos:pos + 2])[0]
    return ".".join(labels), qtype


class _DnsUdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):  # noqa: C901
        data, sock = self.request
        qname, qtype = _parse_dns_query(data)
        if not qname:
            return
        owner: "CallbackServer" = self.server.owner  # type: ignore[attr-defined]
        owner._record_dns(qname, self.client_address[0], qtype)
        answer = self._build_response(data, qname, qtype)
        if answer:
            try:
                sock.sendto(answer, self.client_address)
            except OSError:
                pass

    @staticmethod
    def _build_response(data: bytes, qname: str, qtype: int) -> bytes | None:
        # 仅对 A 记录返回 127.0.0.1，避免目标端解析超时导致二次发包
        if qtype != 1:
            header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
            # 保留原问题段
            try:
                end = data.index(b"\x00", 12) + 1 + 4
            except ValueError:
                return None
            return data[:2] + header[2:6] + header[6:] + data[12:end]
        try:
            end = data.index(b"\x00", 12) + 1 + 4
        except ValueError:
            return None
        question = data[12:end]
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4)
                  + socket.inet_aton("127.0.0.1"))
        header = struct.pack(">HHHHHH", struct.unpack(">H", data[0:2])[0],
                             0x8180, 1, 1, 0, 0)
        return header + question + answer


class _HttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):  # noqa: C901
        owner: "CallbackServer" = self.server.owner  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        owner._record_http(self.command, self.path, self.client_address[0],
                           {k: v for k, v in self.headers.items()}, body)
        payload = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except OSError:
            pass

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle

    def log_message(self, fmt, *args):  # 静默
        return


class CallbackServer:
    """DNS + HTTP 回调监听器（可只开其中一个）。"""

    def __init__(self, dns_port: int = 53, http_port: int = 8000,
                 bind: str = "0.0.0.0", enable_dns: bool = True,
                 enable_http: bool = True, verbose: bool = True):
        self.bind = bind
        self.dns_port = dns_port
        self.http_port = http_port
        self.enable_dns = enable_dns
        self.enable_http = enable_http
        self.verbose = verbose
        self.dns_hits: list[DnsHit] = []
        self.http_hits: list[HttpHit] = []
        self._cond = threading.Condition()
        self._dns_server: _DnsUdpServer | None = None
        self._http_server: ThreadingHTTPServer | None = None
        self._threads: list[threading.Thread] = []
        self.dns_ready = False
        self.http_ready = False
        self.errors: list[str] = []

    # -- 生命周期 ---------------------------------------------------------- #
    def start(self) -> "CallbackServer":
        if self.enable_dns:
            try:
                self._dns_server = _DnsUdpServer((self.bind, self.dns_port), _DnsHandler)
                self._dns_server.owner = self  # type: ignore[attr-defined]
                self.dns_ready = True
                t = threading.Thread(target=self._dns_server.serve_forever,
                                     name="shirokit-dns", daemon=True)
                t.start()
                self._threads.append(t)
            except OSError as exc:
                self.errors.append(f"DNS {self.bind}:{self.dns_port} 绑定失败: {exc}")
        if self.enable_http:
            try:
                self._http_server = ThreadingHTTPServer((self.bind, self.http_port),
                                                        _HttpHandler)
                self._http_server.daemon_threads = True
                self._http_server.owner = self  # type: ignore[attr-defined]
                self.http_ready = True
                t = threading.Thread(target=self._http_server.serve_forever,
                                     name="shirokit-http", daemon=True)
                t.start()
                self._threads.append(t)
            except OSError as exc:
                self.errors.append(f"HTTP {self.bind}:{self.http_port} 绑定失败: {exc}")
        if self.verbose:
            if self.dns_ready:
                print(f"[*] DNS 监听已启动  udp://{self.bind}:{self.dns_port}")
            if self.http_ready:
                print(f"[*] HTTP 监听已启动 http://{self.bind}:{self.http_port}/")
            for err in self.errors:
                print(f"[!] {err}")
        return self

    @property
    def dns_address(self) -> tuple[str, int]:
        """实际绑定地址（支持 port=0 由系统分配；0.0.0.0 归一化为 127.0.0.1）。"""
        if self._dns_server is not None:
            host, port = self._dns_server.server_address[:2]
            return ("127.0.0.1" if host in ("0.0.0.0", "") else host, port)
        return (self.bind, self.dns_port)

    @property
    def http_address(self) -> tuple[str, int]:
        if self._http_server is not None:
            host, port = self._http_server.server_address[:2]
            return ("127.0.0.1" if host in ("0.0.0.0", "") else host, port)
        return (self.bind, self.http_port)

    def stop(self) -> None:
        if self._dns_server:
            self._dns_server.shutdown()
            self._dns_server.server_close()
            self._dns_server = None
        if self._http_server:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None
        self.dns_ready = self.http_ready = False

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    # -- 记录与等待 -------------------------------------------------------- #
    def _record_dns(self, qname: str, source: str, qtype: int) -> None:
        hit = DnsHit(qname=qname.lower().rstrip("."), source=source, qtype=qtype,
                     time=time.time())
        with self._cond:
            self.dns_hits.append(hit)
            self._cond.notify_all()
        if self.verbose:
            print(f"[+] DNS 回调: {hit.qname}  (来自 {source})")

    def _record_http(self, method: str, path: str, source: str,
                     headers: dict[str, str], body: bytes) -> None:
        hit = HttpHit(method=method, path=path, source=source, headers=headers,
                      time=time.time())
        with self._cond:
            self.http_hits.append(hit)
            self._cond.notify_all()
        if self.verbose:
            print(f"[+] HTTP 回调: {method} {path}  (来自 {source})")
            if body:
                snippet = body[:200].decode("utf-8", "replace").strip()
                if snippet:
                    print(f"    body: {snippet}")

    def wait_for_dns(self, needle: str, timeout: float = 8.0) -> DnsHit | None:
        """等待包含 ``needle`` 的 DNS 查询（子串、大小写不敏感）。"""
        needle = needle.lower()
        deadline = time.time() + timeout
        with self._cond:
            while True:
                for hit in self.dns_hits:
                    if needle in hit.qname:
                        return hit
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def wait_for_http(self, needle: str, timeout: float = 8.0) -> HttpHit | None:
        needle = needle.lower()
        deadline = time.time() + timeout
        with self._cond:
            while True:
                for hit in self.http_hits:
                    if needle in hit.path.lower():
                        return hit
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def reset(self) -> None:
        with self._cond:
            self.dns_hits.clear()
            self.http_hits.clear()
