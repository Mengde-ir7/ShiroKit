#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shiro RememberMe AES 密钥库 + 校验。

常见公开密钥字典里常出现 3 类问题，本模块逐一过滤：
    1. 部分字符串不是合法 base64（例如 ``FlGAdIUNQADZXcKeQGEX``）；
    2. 部分是合法 base64，但解码后不是 16/24/32 字节，AES 根本用不了；
    3. 存在重复项，爆破时重复发包，白白增加特征。

用法::

    from shirokit.keys import load_keys, audit
    keys = load_keys()                 # 只返回真实可用的密钥
    for item in audit()[:10]: ...
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# 密钥库：(密钥, 来源/备注)
# --------------------------------------------------------------------------- #

_BUILTIN: list[tuple[str, str]] = [
    # Shiro 官方默认密钥（1.2.4 及更早，命中率最高）
    ("kPH+bIxk5D2deZiIxcaaaA==", "Shiro 官方默认密钥"),
    # 公开泄露/常见弱密钥（大量历史项目直接照抄示例配置）
    ("4AvVhmFLUs0KTA3Kprsdag==", "常见公开密钥"),
    ("3AvVhmFLUs0KTA3Kprsdag==", "常见公开密钥（变体）"),
    ("2AvVhdsgUs0FSA3SDFAdag==", "常见公开密钥（变体）"),
    ("1AvVhdsgUs0FSA3SDFAdag==", "常见公开密钥（变体）"),
    ("6AvVhmFLUs0KTA3Kprsdag==", "常见公开密钥（变体）"),
    ("5AvVhmFLUs0KTA3Kprsdag==", "常见公开密钥（变体）"),
    ("7AvVhmFLUs0KTA3Kprsdag==", "常见公开密钥（变体）"),
    ("6ZmI6I2j5Y+R5aSn5ZOlAA==", "公开样本中出现（中文项目）"),
    ("5aaC5qKm5oqA5pyvAAAAAA==", "公开样本中出现（中文项目）"),
    ("Z3VucwAAAAAAAAAAAAAAAA==", "公开样本：guns 脚手架默认值"),
    ("U3ByaW5nQmxhZGUAAAAAAA==", "公开样本：SpringBlade 默认值"),
    ("wGiHplamyXlVB11UXWol8g==", "公开样本"),
    ("1QWLxg+NYmxraMoxAXu/Iw==", "公开样本"),
    ("a2VlcE9uR29pbmdBbmRGaQ==", "公开样本：keepOnGoingAndFi"),
    ("cmVtZW1iZXJNZQAAAAAAAA==", "公开样本：rememberMe"),
    ("bWluZS1hc3NldC1rZXk6QQ==", "公开样本：mine-asset-key"),
    ("fCq+/sbmFZX1NnE3T9FQ0g==", "公开样本"),
    ("WCFIPQ0qK5r3f5IKwB+Mrw==", "公开样本（PoC 仓库）"),
    ("5J7cGSEj1zL6Y9E3j9V3Yw==", "公开样本（PoC 仓库）"),
    ("3X8kL9m2N7p5J1q6W4rT0z==", "公开样本（PoC 仓库）"),
    # 常见的“把默认密钥改一两个字符”的弱变体（真实目标上偶有命中）
    ("0AvVhmFLUs0KTA3Kprsdag==", "默认密钥字符变体"),
    ("4AvVhmFLUs0KTA3KprsdaA==", "默认密钥字符变体"),
]

# 历史/公开字典里流传的密钥，单独保留用于审计，
# 其中非法项会在 audit() 中明确标记原因。
_LEGACY_DICT: list[str] = [
    "kPH+bIxk5D2deZiIxcaaaA==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "2AvVhmFLUs0KTA3SDFAdag==",
    "1AvVhmFLUs0KTA3SDFAdag==",
    "1AvvhdgsUs0KTA3Kprsdag==",
    "1AvVhdgsUs0KTA3Kprsdag==",
    "6AvVhmFLUs0KTA3Kprsdag==",
    "5AvVhmFLUs0KTA3Kprsdag==",
    "wGiHp1+qX1cdUjv1+u9j1Q==",
    "wCFIPQ0qK5r3f5IKwB+Mrw==",
    "5J7cGSEj1zL6Y9E3j9V3Yw==",
    "4r0J8E213D9x7Q2v6Z5sA==",
    "3X8kL9m2N7p5J1q6W4rT0z==",
    "Z3JvbnRvbG9v3N1c2FtZQ==",
    "cm9vdG9v3N1c2FtZQ==",
    "k3GfGEqU4L8q7N2p9Xv1Zs==",
    "FZX2qKpR5J8h3L9m0Q6Yw==",
    "1Q8z6v5L9f3H7w2K4r1T0x==",
    "W5pD5H8mK2qL7r3P9x1J0z==",
    "M3w4r7T9k2H5J8pL1V6N3q==",
    "U8y5B3f7L1qR9k4W2M6T0x==",
    "FlGAdIUNQADZXcKeQGEX",
]


@dataclass(frozen=True)
class KeyEntry:
    key: str
    source: str

    @property
    def raw(self) -> bytes:
        return base64.b64decode(self.key)


def check_key(key: str) -> tuple[bool, str]:
    """校验单个密钥字符串；返回 (是否可用, 原因)。"""
    if not key or not key.strip():
        return False, "空字符串"
    key = key.strip()
    if len(key) % 4:
        return False, "base64 长度不是 4 的倍数（缺少 padding）"
    try:
        raw = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        return False, "不是合法 base64"
    if len(raw) not in (16, 24, 32):
        return False, f"解码后 {len(raw)} 字节，不是 16/24/32 字节"
    return True, f"{len(raw) * 8} 位 AES 密钥"


def audit() -> list[dict]:
    """审计内置密钥库 + 历史字典，返回逐条结果。"""
    rows: list[dict] = []
    builtin_keys = {k for k, _ in _BUILTIN}
    for key, source in _BUILTIN:
        ok, why = check_key(key)
        rows.append({"key": key, "source": source, "ok": ok, "reason": why,
                     "in_legacy": key in _LEGACY_DICT,
                     "duplicate": sum(1 for k, _ in _BUILTIN if k == key) > 1})
    for key in _LEGACY_DICT:
        if key in builtin_keys:
            continue
        ok, why = check_key(key)
        rows.append({"key": key, "source": "历史字典", "ok": ok, "reason": why,
                     "in_legacy": True, "duplicate": False})
    return rows


def load_keys(extra: list[str] | None = None) -> list[KeyEntry]:
    """返回去重、且通过校验的密钥列表。"""
    seen: set[str] = set()
    result: list[KeyEntry] = []
    for key, source in _BUILTIN:
        ok, _ = check_key(key)
        if ok and key not in seen:
            seen.add(key)
            result.append(KeyEntry(key, source))
    for key in extra or []:
        ok, _ = check_key(key)
        if ok and key not in seen:
            seen.add(key)
            result.append(KeyEntry(key, "自定义字典"))
    return result


def load_keys_file(path: str) -> list[str]:
    keys: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 允许 "key  # 注释" 形式
            keys.append(line.split("#", 1)[0].strip())
    return keys


def default_keys_for_bruteforce() -> list[str]:
    return [e.key for e in load_keys()]


if __name__ == "__main__":  # pragma: no cover
    rows = audit()
    bad = [r for r in rows if not r["ok"]]
    print(f"内置可用密钥: {sum(1 for r in rows if r['ok'])}")
    print(f"无效条目: {len(bad)}")
    for r in bad:
        print(f"  [-] {r['key']:<28} {r['reason']}  ({r['source']})")
