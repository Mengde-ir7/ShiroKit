#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""零依赖 HTTP 客户端（标准库 urllib），专为“打得出去、收得回来”的探测场景设计。

特性：
    * 不自动跟随跳转（判断权限绕过时 302 本身就是证据）；
    * 可关闭 TLS 校验（目标多为自签证书）；
    * 支持代理（Burp/Clash 等）；
    * 返回结构化的状态码 / 原始响应头 / 耗时，方便多个字段做 diff；
    * 线程安全：每次请求独立连接，可放心放进线程池。
"""

from __future__ import annotations

import gzip
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field


@dataclass
class Response:
    url: str
    status: int = 0
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    error: str | None = None

    # -- 便捷访问 ---------------------------------------------------------- #
    def header(self, name: str) -> str | None:
        name_l = name.lower()
        for k, v in self.headers:
            if k.lower() == name_l:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        name_l = name.lower()
        return [v for k, v in self.headers if k.lower() == name_l]

    def set_cookies(self) -> list[str]:
        """返回所有 Set-Cookie 的原文（含属性）。"""
        return self.header_all("set-cookie")

    def cookie_pairs(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for raw in self.set_cookies():
            first = raw.split(";", 1)[0]
            if "=" in first:
                k, v = first.split("=", 1)
                pairs.append((k.strip(), v.strip()))
        return pairs

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.header("content-type") or ""
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")

    def looks_like_error(self) -> bool:
        return self.error is not None or self.status >= 500

    def summary(self) -> str:
        if self.error:
            return f"ERR {self.error}"
        return f"{self.status} {len(self.body)}B {self.elapsed * 1000:.0f}ms"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class HttpClient:
    """极简 HTTP 客户端。"""

    def __init__(self, timeout: float = 10.0, proxy: str | None = None,
                 insecure: bool = True, headers: dict[str, str] | None = None,
                 follow_redirects: bool = False, retries: int = 1):
        self.timeout = timeout
        self.retries = max(0, retries)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if headers:
            self.headers.update(headers)

        handlers: list[urllib.request.BaseHandler] = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))   # 忽略系统代理
        if not follow_redirects:
            handlers.append(_NoRedirect())
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    # -- 核心请求 ---------------------------------------------------------- #
    def request(self, method: str, url: str, headers: dict[str, str] | None = None,
                body: bytes | None = None) -> Response:
        all_headers = dict(self.headers)
        if headers:
            all_headers.update(headers)
        last = Response(url=url)
        for attempt in range(self.retries + 1):
            started = time.time()
            req = urllib.request.Request(url, data=body, method=method,
                                         headers=all_headers)
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    last = Response(
                        url=resp.geturl(),
                        status=getattr(resp, "status", 0) or resp.code,
                        reason=getattr(resp, "reason", "") or "",
                        headers=list(resp.headers.items()),
                        body=self._decode(raw, resp.headers),
                        elapsed=time.time() - started,
                    )
                return last
            except urllib.error.HTTPError as exc:
                raw = exc.read() if hasattr(exc, "read") else b""
                last = Response(
                    url=url, status=exc.code, reason=str(exc.reason or ""),
                    headers=list((exc.headers or {}).items()),
                    body=self._decode(raw, exc.headers),
                    elapsed=time.time() - started,
                )
                return last
            except urllib.error.URLError as exc:
                last = Response(url=url, elapsed=time.time() - started,
                                error=f"{exc.reason}")
            except Exception as exc:  # noqa: BLE001
                last = Response(url=url, elapsed=time.time() - started,
                                error=f"{type(exc).__name__}: {exc}")
            if attempt < self.retries:
                time.sleep(0.2 * (attempt + 1))
        return last

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, headers=headers)

    def post(self, url: str, body: bytes = b"",
             headers: dict[str, str] | None = None) -> Response:
        return self.request("POST", url, headers=headers, body=body)

    # -- 辅助 -------------------------------------------------------------- #
    @staticmethod
    def _decode(raw: bytes, headers) -> bytes:
        enc = ""
        try:
            enc = (headers.get("Content-Encoding") or "").lower()
        except AttributeError:
            enc = ""
        try:
            if enc == "gzip":
                return gzip.decompress(raw)
            if enc == "deflate":
                return zlib.decompress(raw, -zlib.MAX_WBITS)
        except Exception:  # noqa: BLE001
            return raw
        return raw


def join_url(base: str, path: str) -> str:
    """把路径原样拼到 base 后面（绝不规范化），权限绕过测试必须保留原始形式。"""
    if path.startswith(("http://", "https://")):
        return path
    return base.rstrip("/") + (path if path.startswith("/") else "/" + path)


def normalize_base(url: str) -> str:
    """只去掉末尾斜杠与空白，不做路径规范化。"""
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")
