#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shiro 漏洞利用工具包（shirokit）。

模块划分::

    aes        纯 Python AES/CBC/PKCS7（零第三方依赖）
    jserial    Java 序列化字节流写入器
    gadgets    URLDNS payload + ysoserial 桥接
    keys       校验过的 Shiro 密钥库
    httpc      零依赖 HTTP 客户端
    detect     Shiro 指纹识别
    rememberme RememberMe Cookie 构造/解析/判定
    brute      密钥爆破（DNS 回调 + deleteMe 自检）
    bypass     Spring+Shiro 权限绕过字典与扫描
    padding    Shiro-721 Padding Oracle 引擎
    callback   内置 DNS/HTTP 回调监听
    cli        命令行
"""

__version__ = "1.1.0"
__author__ = "M3ngde"

__all__ = [
    "aes", "jserial", "gadgets", "keys", "httpc", "detect",
    "rememberme", "brute", "bypass", "padding", "callback", "cli",
]
