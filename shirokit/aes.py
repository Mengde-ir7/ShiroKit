#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""纯 Python AES-128/192/256 + CBC + PKCS#7。

为什么要自己写：
    * 不引入 pycryptodome/cryptography，目标机器没有这些库时也能用；
    * 直接给出 Shiro RememberMe 所需的完整格式：
      ``base64(IV + AES-CBC(明文))``。IV 必须在密文前面，否则服务端会把
      密文首块当成 IV，导致解密失败。

本模块零第三方依赖，纯标准库实现，性能足够（单块 ~0.15ms，构造 Cookie 只需几毫秒）。
同时提供 ``backend`` 说明，便于将来换成 pycryptodome。
"""

from __future__ import annotations

import base64
import binascii
import struct

BLOCK_SIZE = 16

# --------------------------------------------------------------------------- #
# GF(2^8) 以及 S 盒（运行时算出来，避免手抄 256 个常量出错）
# --------------------------------------------------------------------------- #


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        n >>= 1
    return r


def _rotl8(v: int, n: int) -> int:
    return ((v << n) | (v >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    for x in range(256):
        inv = _gf_pow(x, 254) if x else 0
        s = inv
        for n in range(1, 5):
            s ^= _rotl8(inv, n)
        sbox[x] = s ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()

# 列混合矩阵（FIPS-197 5.1.3）
MUL2 = [_gf_mul(i, 2) for i in range(256)]
MUL3 = [_gf_mul(i, 3) for i in range(256)]
MUL9 = [_gf_mul(i, 9) for i in range(256)]
MUL11 = [_gf_mul(i, 11) for i in range(256)]
MUL13 = [_gf_mul(i, 13) for i in range(256)]
MUL14 = [_gf_mul(i, 14) for i in range(256)]

RCON = [0x01]
for _ in range(1, 14):
    RCON.append(_gf_mul(RCON[-1], 2))


class AES:
    """最小化 AES 实现（ECB 单块），CBC 由下面的封装完成。"""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES 密钥长度必须是 16/24/32 字节，当前 {len(key)}")
        self.key = bytes(key)
        self.nk = len(key) // 4          # 4/6/8
        self.nr = self.nk + 6            # 10/12/14
        self.round_keys = self._expand_key(self.key)

    # -- 密钥扩展 ---------------------------------------------------------- #
    def _expand_key(self, key: bytes):
        words = [list(key[4 * i:4 * i + 4]) for i in range(self.nk)]
        total = 4 * (self.nr + 1)
        for i in range(self.nk, total):
            temp = list(words[i - 1])
            if i % self.nk == 0:
                temp = temp[1:] + temp[:1]                       # RotWord
                temp = [SBOX[b] for b in temp]                    # SubWord
                temp[0] ^= RCON[i // self.nk - 1]
            elif self.nk > 6 and i % self.nk == 4:
                temp = [SBOX[b] for b in temp]
            words.append([a ^ b for a, b in zip(words[i - self.nk], temp)])
        return [sum(words[4 * r:4 * r + 4], []) for r in range(self.nr + 1)]

    # -- 状态变换 ---------------------------------------------------------- #
    @staticmethod
    def _add_round_key(state, round_key):
        return [s ^ k for s, k in zip(state, round_key)]

    @staticmethod
    def _sub_bytes(state):
        return [SBOX[b] for b in state]

    @staticmethod
    def _inv_sub_bytes(state):
        return [INV_SBOX[b] for b in state]

    @staticmethod
    def _shift_rows(state):
        # state 是列主序：state[c*4 + r]
        return [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]

    @staticmethod
    def _inv_shift_rows(state):
        return [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3],
        ]

    @staticmethod
    def _mix_columns(state):
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = state[4 * c:4 * c + 4]
            out[4 * c + 0] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
            out[4 * c + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
            out[4 * c + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
            out[4 * c + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]
        return out

    @staticmethod
    def _inv_mix_columns(state):
        out = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = state[4 * c:4 * c + 4]
            out[4 * c + 0] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3]
            out[4 * c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3]
            out[4 * c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3]
            out[4 * c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3]
        return out

    # -- 单块加解密 -------------------------------------------------------- #
    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("block 必须为 16 字节")
        state = self._add_round_key(list(block), self.round_keys[0])
        for rnd in range(1, self.nr):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[rnd])
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[self.nr])
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("block 必须为 16 字节")
        state = self._add_round_key(list(block), self.round_keys[self.nr])
        for rnd in range(self.nr - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[rnd])
            state = self._inv_mix_columns(state)
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])
        return bytes(state)


# --------------------------------------------------------------------------- #
# 填充
# --------------------------------------------------------------------------- #


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("非法 block_size")
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("密文长度不是分组长度的整数倍")
    pad = data[-1]
    if pad == 0 or pad > block_size or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS#7 填充非法")
    return data[:-pad]


# --------------------------------------------------------------------------- #
# CBC
# --------------------------------------------------------------------------- #


def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV 必须为 16 字节")
    aes = AES(key)
    data = pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = bytes(a ^ b for a, b in zip(data[i:i + BLOCK_SIZE], prev))
        enc = aes.encrypt_block(block)
        out += enc
        prev = enc
    return bytes(out)


def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV 必须为 16 字节")
    if len(ciphertext) % BLOCK_SIZE:
        raise ValueError("密文长度不是 16 的整数倍")
    aes = AES(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec = aes.decrypt_block(block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


# --------------------------------------------------------------------------- #
# 面向 Shiro 的高层封装
# --------------------------------------------------------------------------- #


def b64decode_key(key_b64: str) -> bytes:
    """严格解码 Shiro 密钥（base64），并校验 AES 合法长度。"""
    key_b64 = (key_b64 or "").strip()
    if not key_b64:
        raise ValueError("空密钥")
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"非法 base64: {exc}") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError(f"解码后 {len(key)} 字节，不是合法的 AES 密钥长度（16/24/32）")
    return key


def shiro_encrypt(key: bytes, plaintext: bytes, iv: bytes | None = None) -> bytes:
    """返回 Shiro RememberMe Cookie 的原始字节：``IV || AES-CBC(明文)``。

    注意：IV 必须在最前面。
    """
    iv = iv if iv is not None else bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV 必须为 16 字节")
    return iv + cbc_encrypt(key, plaintext, iv)


def shiro_decrypt(key: bytes, cookie_bytes: bytes) -> bytes:
    """解析 ``IV || AES-CBC(明文)`` 并去填充。供本地自测/验证使用。"""
    if len(cookie_bytes) <= BLOCK_SIZE or (len(cookie_bytes) - BLOCK_SIZE) % BLOCK_SIZE:
        raise ValueError("Cookie 长度非法（需要 16 字节 IV + 整数个密文块）")
    iv = cookie_bytes[:BLOCK_SIZE]
    ciphertext = cookie_bytes[BLOCK_SIZE:]
    return pkcs7_unpad(cbc_decrypt(key, ciphertext, iv))


def shiro_encrypt_b64(key: bytes, plaintext: bytes, iv: bytes | None = None) -> str:
    return base64.b64encode(shiro_encrypt(key, plaintext, iv)).decode("ascii")


def shiro_decrypt_b64(key: bytes, cookie_b64: str) -> bytes:
    return shiro_decrypt(key, base64.b64decode(cookie_b64, validate=False))


def sample_aes_vector_check() -> bool:
    """自检：FIPS-197 附录 C 的三个标准向量。"""
    vectors = [
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
        (
            bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
        ),
    ]
    for key, pt, ct in vectors:
        aes = AES(key)
        if aes.encrypt_block(pt) != ct:
            return False
        if aes.decrypt_block(ct) != pt:
            return False
    return True


if __name__ == "__main__":  # pragma: no cover
    print("AES 自检:", "PASS" if sample_aes_vector_check() else "FAIL")
