# -*- coding: utf-8 -*-
"""
EVE 启动器更新加速器

三件事：
  1. 换节点：多路 DNS（DoH + UDP + 系统解析）加 Cloudflare 任播段就近扫描收集候选 IPv4。
     每个候选都要连得上 443，TLS 校验证书主机名，再下载官方索引里的真实更新文件，
     和多数节点交叉比对内容，最后按两段式测速排名（前 3 MB / 2 秒算起步不计入）。
     写进 hosts 后还要落地复检，没过的域名单独摘掉，全部失败才回滚。
  2. 掉速诊断：单连接速度曲线，新连接对比，4 条并发对比，
     用来区分按连接限速、线路整体拥堵和启动器自身问题。
  3. 并发预下载：多线程把缺的资源文件下进 EVE 共享缓存，逐个校验 md5，
     先写临时文件再原子改名。启动器发现本地已有就跳过。

全程仅使用 IPv4。支持 Windows / macOS / Linux。
"""

import argparse
import ctypes
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

APP_NAME = "EVE 启动器更新加速器"
APP_VER = "2.2.0"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 EVELauncher/2")

# --------------------------------------------------------------------------
# 只允许 IPv4：把整个进程的名字解析钉死在 AF_INET
# --------------------------------------------------------------------------
_ORIG_GETADDRINFO = socket.getaddrinfo


def _ipv4_only_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return _ORIG_GETADDRINFO(host, port, socket.AF_INET, type, proto, flags)


socket.getaddrinfo = _ipv4_only_getaddrinfo

# --------------------------------------------------------------------------
# 默认配置
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "_version": APP_VER,
    "_说明": "domains 可自行增删。probes 是验证节点是否真能下东西的探测路径；"
             "discover 为 binaries/resources 的域名会自动从 EVE 官方索引里取真实更新文件来验证和测速。"
             "optional 的域名找不到可验证路径时只会跳过，不算失败。",
    "domains": [
        {"host": "binaries.eveonline.com",
         "note": "客户端/启动器二进制 + 更新索引",
         "discover": "binaries",
         "probes": ["/eveclient_TQ.json", "/"]},
        {"host": "resources.eveonline.com",
         "note": "客户端资源文件 resfile（更新流量最大）",
         "discover": "resources",
         "probes": ["/"]},
        {"host": "launcher.eveonline.com",
         "note": "启动器配置/自更新",
         "probes": ["/", "/favicon.ico"]},
        {"host": "web.ccpgamescdn.com",
         "note": "CCP 网站/启动器 CDN",
         "optional": True,
         "probes": ["/launcher/win32/evelauncher.txt", "/"]},
        {"host": "login.eveonline.com",
         "note": "登录/SSO（默认不加速，需要时把 enabled 改成 true）",
         "enabled": False,
         "probes": ["/robots.txt", "/"]}
    ],
    "settings": {
        "connect_timeout": 6.0,
        "verify_timeout": 10.0,
        "quick_seconds": 3.0,        # 第一轮粗测：淘汰下不动的节点
        "quick_bytes": 3145728,
        "speed_seconds": 7.0,        # 第二轮持续测速：专看前几 MB 之后还剩多少
        "speed_bytes": 12582912,
        "warmup_bytes": 3145728,     # 起步段：下满 3 MB
        "warmup_seconds": 2.0,       # 或者跑够 2 秒，先到者为准（慢节点也能测出持续速度）
        "sustain_top_n": 4,
        "threads": 24,
        "latency_samples": 3,
        "speed_top_n": 5,
        "discover_cache_hours": 72,
        "cf_scan": True,
        "cf_scan_count": 320,
        "cf_keep": 12,
        "predownload_threads": 8,    # 并发预下载的连接数（按连接限速时，这个才是关键）
        "predownload_timeout": 12.0,  # 单个文件的超时，卡住的连接会被及时换掉
        "predownload_recycle": 64,   # 每条连接下多少个文件就重建，防止被中间设备静默掐死
        "shared_cache": "",          # EVE 共享缓存目录，留空 = 自动探测
        "res_index": "auto"          # auto = 按平台挑索引；full = 跨平台全量索引
    }
}

# 常见 DNS 污染 / 黑洞地址，直接丢弃（后面的验证也会拦，这里只是省时间）
BOGUS_IPS = {
    "0.0.0.0", "1.1.1.1", "8.7.198.45", "37.61.54.158", "46.82.174.68",
    "59.24.3.173", "78.16.49.15", "93.46.8.89", "128.121.126.139",
    "159.106.121.75", "169.132.13.103", "192.67.198.6", "202.106.1.2",
    "203.98.7.65", "203.161.230.171", "207.12.88.98", "208.56.31.43",
    "209.36.73.33", "209.145.54.50", "209.220.30.174", "211.94.66.147",
    "213.169.251.35", "216.221.188.182", "216.234.179.13", "243.185.187.39",
    "243.185.187.30", "249.129.46.48", "253.157.14.165", "4.36.66.178",
    "255.255.255.255", "127.0.0.1"
}

# DoH（走 IP 直连 + SNI，避免解析器自身被解析问题影响）
DOH_SERVERS = [
    ("223.5.5.5", "dns.alidns.com", "/resolve", True),
    ("223.6.6.6", "dns.alidns.com", "/resolve", True),
    ("120.53.53.53", "doh.pub", "/dns-query", True),
    ("1.12.12.12", "doh.pub", "/dns-query", True),
    ("1.1.1.1", "cloudflare-dns.com", "/dns-query", True),
    ("1.0.0.1", "cloudflare-dns.com", "/dns-query", True),
    ("8.8.8.8", "dns.google", "/resolve", True),
    ("8.8.4.4", "dns.google", "/resolve", True),
    ("9.9.9.9", "dns.quad9.net", "/dns-query", False),
    ("208.67.222.222", "doh.opendns.com", "/dns-query", False),
]

# 传统 UDP DNS：国内的能给出离你最近的 CDN 节点，国外的能绕开部分错误解析
UDP_DNS_SERVERS = [
    "223.5.5.5", "223.6.6.6",          # 阿里
    "119.29.29.29", "182.254.116.116",  # DNSPod
    "180.76.76.76",                    # 百度
    "114.114.114.114", "114.114.115.115",  # 114
    "117.50.11.11", "52.80.66.66",     # OneDNS
    "101.226.4.6", "218.30.118.6",     # DNS 派
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
]

IS_WIN = (os.name == "nt")
IS_MAC = (sys.platform == "darwin")

if IS_WIN:
    HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                              "System32", "drivers", "etc", "hosts")
else:
    HOSTS_PATH = "/etc/hosts"
MARK_BEGIN = "# ==== EVE-ACCEL BEGIN ====  (EVE加速器自动生成，勿手动编辑本段)"
MARK_END = "# ==== EVE-ACCEL END ===="

if IS_WIN:
    APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "EVEAccel")
elif IS_MAC:
    APP_DIR = os.path.expanduser("~/Library/Application Support/EVEAccel")
else:
    APP_DIR = os.path.expanduser("~/.local/share/eve-accel")
BACKUP_FILE = os.path.join(APP_DIR, "hosts_backup.txt")   # 只留这一份
LEGACY_BACKUP_DIR = os.path.join(APP_DIR, "backups")      # 1.0 版按时间戳堆备份的老目录


# --------------------------------------------------------------------------
# 控制台
# --------------------------------------------------------------------------
def setup_console():
    if os.name == "nt":
        try:
            k = ctypes.windll.kernel32
            k.SetConsoleOutputCP(65001)
            k.SetConsoleCP(65001)
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k.GetConsoleMode(h, ctypes.byref(mode)):
                k.SetConsoleMode(h, mode.value | 0x0004)  # VT 序列
            ctypes.windll.kernel32.SetConsoleTitleW(u"%s v%s" % (APP_NAME, APP_VER))
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


C_RESET = "\033[0m"
C_DIM = "\033[90m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[96m"
C_BOLD = "\033[1m"


def info(msg=""):
    print(msg, flush=True)


def ok(msg):
    print("%s[  OK  ]%s %s" % (C_GREEN, C_RESET, msg), flush=True)


def warn(msg):
    print("%s[ 注意 ]%s %s" % (C_YELLOW, C_RESET, msg), flush=True)


def err(msg):
    print("%s[ 失败 ]%s %s" % (C_RED, C_RESET, msg), flush=True)


def step(msg):
    print("%s[ 步骤 ]%s %s" % (C_BLUE, C_RESET, msg), flush=True)


def dim(msg):
    print("%s%s%s" % (C_DIM, msg, C_RESET), flush=True)


# --------------------------------------------------------------------------
# 管理员权限
# --------------------------------------------------------------------------
def is_admin():
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def admin_word():
    return "管理员" if IS_WIN else "root"


def relaunch_as_admin(extra_args=None):
    args = list(sys.argv[1:]) if extra_args is None else list(extra_args)
    if not IS_WIN:
        # macOS / Linux 上不做自动提权，避免莫名其妙地弹密码框
        cmd = sys.executable if getattr(sys, "frozen", False) else \
            "%s %s" % (os.path.basename(sys.executable), os.path.abspath(sys.argv[0]))
        err("需要 root 权限才能改 /etc/hosts，请这样运行：")
        info("    sudo %s %s" % (cmd, " ".join(args)))
        return False
    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = subprocess.list2cmdline(args)
    else:
        exe = sys.executable
        params = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + args)
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, u"runas", exe, params, os.getcwd(), 1)
        return int(rc) > 32
    except Exception:
        return False


# --------------------------------------------------------------------------
# 极简 HTTPS 客户端：连接指定 IP，但按域名做 SNI 与证书校验
# --------------------------------------------------------------------------
class Resp(object):
    __slots__ = ("ok", "status", "reason", "headers", "body", "err",
                 "t_conn", "t_tls", "t_ttfb", "t_total", "nbytes", "ip",
                 "t_warm", "n_warm")

    def __init__(self):
        self.ok = False
        self.status = 0
        self.reason = ""
        self.headers = {}
        self.body = b""
        self.err = ""
        self.t_conn = 0.0
        self.t_tls = 0.0
        self.t_ttfb = 0.0
        self.t_total = 0.0
        self.nbytes = 0
        self.ip = ""
        self.t_warm = 0.0     # 下满 warmup_bytes 的时刻
        self.n_warm = 0       # 那一刻已下的字节数

    @property
    def latency(self):
        return self.t_ttfb

    @property
    def speed_bps(self):
        """整段平均速度（含起步爆发）。"""
        dt = self.t_total - self.t_ttfb
        if self.nbytes >= 65536 and dt > 0.03:
            return self.nbytes / dt
        return 0.0

    @property
    def sustained_bps(self):
        """跑完起步段之后的速度。很多节点前几 MB 很猛，之后掉到几十 KB，
        这个值才是真正决定更新要下多久的东西。"""
        if self.n_warm and self.t_warm:
            dt = self.t_total - self.t_warm
            nb = self.nbytes - self.n_warm
            if dt >= 0.8 and nb >= 32768:
                return nb / dt
        return 0.0


_SSL_CTX = None


def ssl_ctx():
    """默认上下文：强制校验证书链 + 主机名。证书校验本身就是最硬的防劫持手段。"""
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        try:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
        except Exception:
            pass
        _SSL_CTX = ctx
    return _SSL_CTX


def https_request(ip, host, path, method="GET", extra_headers=None, timeout=8.0,
                  read_max=262144, keep_max=131072, body_seconds=None, port=443,
                  warmup_bytes=0, warmup_seconds=0.0, progress_cb=None):
    """向 ip:port 发起请求，Host / SNI / 证书校验全部按 host 走。返回 Resp。"""
    r = Resp()
    r.ip = ip
    s = ss = fp = None
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.connect((ip, port))
        t1 = time.perf_counter()
        r.t_conn = t1 - t0

        ss = ssl_ctx().wrap_socket(s, server_hostname=host)
        t2 = time.perf_counter()
        r.t_tls = t2 - t1

        lines = ["%s %s HTTP/1.1" % (method, path),
                 "Host: %s" % host,
                 "User-Agent: %s" % UA,
                 "Accept: */*",
                 "Accept-Encoding: identity",
                 "Cache-Control: no-cache",
                 "Connection: close"]
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append("%s: %s" % (k, v))
        ss.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii", "ignore"))

        fp = ss.makefile("rb")
        first = fp.readline(8192)
        r.t_ttfb = time.perf_counter() - t0
        if not first:
            r.err = "无响应数据"
            return r
        parts = first.decode("iso-8859-1").strip().split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            r.err = "响应不是 HTTP"
            return r
        r.status = int(parts[1])
        r.reason = parts[2] if len(parts) > 2 else ""

        while True:
            hl = fp.readline(16384)
            if not hl or hl in (b"\r\n", b"\n"):
                break
            if b":" in hl:
                k, v = hl.decode("iso-8859-1").split(":", 1)
                r.headers[k.strip().lower()] = v.strip()

        deadline = time.perf_counter() + (body_seconds if body_seconds else timeout)
        buf = bytearray()
        total = 0
        last_cb = time.perf_counter()
        if method != "HEAD" and r.status not in (204, 304):
            te = r.headers.get("transfer-encoding", "").lower()
            if "chunked" in te:
                while True:
                    ln = fp.readline(128)
                    if not ln:
                        break
                    try:
                        size = int(ln.strip().split(b";")[0], 16)
                    except Exception:
                        break
                    if size == 0:
                        break
                    got = 0
                    while got < size:
                        chunk = fp.read(min(65536, size - got))
                        if not chunk:
                            break
                        got += len(chunk)
                        total += len(chunk)
                        if not r.n_warm and total > 0:
                            el = time.perf_counter() - t0
                            if ((warmup_bytes and total >= warmup_bytes)
                                    or (warmup_seconds and el >= warmup_seconds)):
                                r.n_warm, r.t_warm = total, el
                        if progress_cb is not None:
                            now = time.perf_counter()
                            if now - last_cb >= 0.25:
                                last_cb = now
                                progress_cb(total, now - t0)
                        if len(buf) < keep_max:
                            buf += chunk[:keep_max - len(buf)]
                    fp.read(2)
                    if total >= read_max or time.perf_counter() > deadline:
                        break
            else:
                cl = r.headers.get("content-length", "")
                remaining = int(cl) if cl.isdigit() else None
                while True:
                    if remaining is not None and total >= remaining:
                        break
                    want = 65536
                    if remaining is not None:
                        want = min(want, remaining - total)
                    chunk = fp.read(want)
                    if not chunk:
                        break
                    total += len(chunk)
                    if not r.n_warm and total > 0:
                        el = time.perf_counter() - t0
                        if ((warmup_bytes and total >= warmup_bytes)
                                or (warmup_seconds and el >= warmup_seconds)):
                            r.n_warm, r.t_warm = total, el
                    if progress_cb is not None:
                        now = time.perf_counter()
                        if now - last_cb >= 0.25:
                            last_cb = now
                            progress_cb(total, now - t0)
                    if len(buf) < keep_max:
                        buf += chunk[:keep_max - len(buf)]
                    if total >= read_max or time.perf_counter() > deadline:
                        break
        r.body = bytes(buf)
        r.nbytes = total
        r.t_total = time.perf_counter() - t0
        r.ok = True
        return r
    except ssl.SSLCertVerificationError as e:
        r.err = "证书校验不通过(非本站节点/被劫持): %s" % (getattr(e, "verify_message", None) or e)
    except ssl.SSLError as e:
        r.err = "TLS 握手失败: %s" % e
    except socket.timeout:
        r.err = "超时"
    except OSError as e:
        r.err = "连接失败: %s" % (getattr(e, "strerror", None) or e)
    except Exception as e:
        r.err = "%s: %s" % (type(e).__name__, e)
    finally:
        for c in (fp, ss, s):
            try:
                if c is not None:
                    c.close()
            except Exception:
                pass
    r.t_total = time.perf_counter() - t0
    return r


# --------------------------------------------------------------------------
# DNS：DoH(JSON) + 原生 UDP + 系统解析，只取 A 记录（IPv4）
# --------------------------------------------------------------------------
def usable_ipv4(ip):
    try:
        a = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    if (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved
            or a.is_link_local or a.is_unspecified):
        return False
    return ip not in BOGUS_IPS


def doh_query(server_ip, server_host, path, domain, ecs=None, timeout=5.0):
    q = "%s?name=%s&type=A&cd=false" % (path, domain)
    if ecs:
        q += "&edns_client_subnet=%s" % ecs
    r = https_request(server_ip, server_host, q,
                      extra_headers={"accept": "application/dns-json"},
                      timeout=timeout, read_max=65536, keep_max=65536)
    if not r.ok or r.status != 200:
        return []
    try:
        data = json.loads(r.body.decode("utf-8", "replace"))
    except Exception:
        return []
    out = []
    for ans in (data.get("Answer") or []):
        if ans.get("type") == 1:
            ip = str(ans.get("data", "")).strip()
            if usable_ipv4(ip):
                out.append(ip)
    return out


def _skip_dns_name(data, off):
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length
    return off


def dns_udp_query(server, domain, timeout=3.0):
    out = []
    s = None
    try:
        tid = random.randint(0, 0xFFFF)
        pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        for label in domain.rstrip(".").split("."):
            b = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
            pkt += bytes([len(b)]) + b
        pkt += b"\x00" + struct.pack(">HH", 1, 1)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            data, _addr = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                break
            data = b""
        if not data:
            return out
        qd = struct.unpack(">H", data[4:6])[0]
        an = struct.unpack(">H", data[6:8])[0]
        off = 12
        for _ in range(qd):
            off = _skip_dns_name(data, off) + 4
        for _ in range(an):
            off = _skip_dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype, rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rclass == 1 and rdlen == 4 and off + 4 <= len(data):
                ip = socket.inet_ntoa(data[off:off + 4])
                if usable_ipv4(ip):
                    out.append(ip)
            off += rdlen
    except Exception:
        pass
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass
    return out


def system_resolve(domain):
    out = []
    try:
        for item in _ORIG_GETADDRINFO(domain, 443, socket.AF_INET, socket.SOCK_STREAM):
            ip = item[4][0]
            if usable_ipv4(ip):
                out.append(ip)
    except Exception:
        pass
    return out


def get_public_ipv4(timeout=3.0):
    """拿到出口 IP 只是为了给 DoH 带 ECS，让解析器返回离你最近的节点；失败也不影响。"""
    import urllib.request
    urls = ["https://www.taobao.com/help/getip.php",
            "http://ip-api.com/line/?fields=query",
            "https://api.ipify.org",
            "https://myip.ipip.net"]
    pat = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                txt = resp.read(2048).decode("utf-8", "replace")
            m = pat.search(txt)
            if m and usable_ipv4(m.group(1)):
                return m.group(1)
        except Exception:
            continue
    return None


def gather_candidates(domain, ecs=None, threads=24):
    """多路解析并聚合候选 IPv4，返回 {ip: {来源,...}}。"""
    found = {}

    def add(ips, src):
        for ip in ips:
            found.setdefault(ip, set()).add(src)

    jobs = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for (sip, shost, spath, allow_ecs) in DOH_SERVERS:
            use_ecs = ecs if (allow_ecs and ecs) else None
            jobs.append((ex.submit(doh_query, sip, shost, spath, domain, use_ecs),
                         "doh:%s" % shost))
            if use_ecs:
                jobs.append((ex.submit(doh_query, sip, shost, spath, domain, None),
                             "doh:%s" % shost))
        for srv in UDP_DNS_SERVERS:
            jobs.append((ex.submit(dns_udp_query, srv, domain), "udp:%s" % srv))
        jobs.append((ex.submit(system_resolve, domain), "system"))
        for fut, src in jobs:
            try:
                add(fut.result() or [], src)
            except Exception:
                pass
    return found


# --------------------------------------------------------------------------
# Cloudflare 边缘节点就近扫描
# binaries / resources 都挂在 Cloudflare 上，而 DNS 只会给你两三个 IP。
# Cloudflare 是任播：它任何一个边缘 IP 都能凭 SNI 提供同一个站点，
# 所以随机采样 + 测延迟，能挑出离你最近的那个（再经过后面的真实下载验证）。
# --------------------------------------------------------------------------
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_EDGE_CACHE = None
_FAST_CF_NODES = []   # 在某个 Cloudflare 域名上真跑出好速度的节点，留给后面的域名复用


def tcp_latency(ip, port=443, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.connect((ip, port))
        return time.perf_counter() - t0
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def sample_cf_ips(count):
    nets = []
    for c in CF_RANGES:
        try:
            nets.append(ipaddress.IPv4Network(c))
        except Exception:
            pass
    if not nets:
        return []
    weights = [n.num_addresses for n in nets]
    total = float(sum(weights))
    out = set()
    guard = 0
    while len(out) < count and guard < count * 12:
        guard += 1
        pick = random.random() * total
        acc = 0.0
        chosen = nets[-1]
        for n, w in zip(nets, weights):
            acc += w
            if pick <= acc:
                chosen = n
                break
        # 跳过网络号/广播号
        if chosen.num_addresses <= 4:
            continue
        ip = str(chosen.network_address + random.randint(1, chosen.num_addresses - 2))
        if usable_ipv4(ip):
            out.add(ip)
    return list(out)


def scan_cloudflare_edges(count, keep, threads=64):
    """随机采样 Cloudflare 任播段并测 TCP 延迟，返回最快的 keep 个 IP。"""
    global _CF_EDGE_CACHE
    if _CF_EDGE_CACHE is not None:
        return _CF_EDGE_CACHE
    ips = sample_cf_ips(count)
    scored = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(tcp_latency, ip): ip for ip in ips}
        for f, ip in futs.items():
            try:
                d = f.result()
            except Exception:
                d = None
            if d is not None:
                scored.append((d, ip))
    scored.sort()
    _CF_EDGE_CACHE = [ip for _d, ip in scored[:keep]]
    return _CF_EDGE_CACHE


# --------------------------------------------------------------------------
# 动态发现：从 EVE 官方更新索引里取【真实更新文件】作为验证与测速目标
#   binaries.eveonline.com/eveclient_TQ.json        -> 当前 build
#   binaries.eveonline.com/eveonline_<build>.txt    -> 客户端文件索引
#   索引里的 resfileindex_Windows.txt               -> 资源文件索引(res:)
# 这样"验证通过"的含义就是：这个节点确实能把 EVE 的更新文件原样发给你。
# --------------------------------------------------------------------------
BIN_HOST = "binaries.eveonline.com"
RES_HOST = "resources.eveonline.com"


def probe_cache_file():
    return os.path.join(APP_DIR, "probes.json")


PROBE_CACHE_VER = 3


def load_probe_cache(max_age_hours):
    try:
        with open(probe_cache_file(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if (int(data.get("v", 0)) == PROBE_CACHE_VER
                and time.time() - float(data.get("ts", 0)) <= max_age_hours * 3600
                and data.get("probes")):
            return data["probes"], data.get("build", "?")
    except Exception:
        pass
    return None, None


def cache_still_valid(probes, st):
    """EVE 发新版后旧文件可能被 CDN 清掉，用一次轻量请求确认缓存路径还在。"""
    for host, d in probes.items():
        path = d.get("probe")
        if not path:
            continue
        ips = system_resolve(host)
        if not ips:
            return False
        good = False
        for ip in ips[:2]:
            for _ in range(2):          # 网络抖一下不算缓存失效，否则白白重下几百 KB 索引
                r = https_request(ip, host, path, "GET", None, 10.0, 4096, 0)
                if r.ok and r.status == 200:
                    good = True
                    break
            if good:
                break
        if not good:
            return False
    return True


def save_probe_cache(probes, build):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(probe_cache_file(), "w", encoding="utf-8") as f:
            json.dump({"v": PROBE_CACHE_VER, "ts": time.time(), "build": build,
                       "probes": probes}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _fetch_from_any(host, path, ips, read_max, timeout=25.0, body_seconds=20.0):
    for ip in ips[:6]:
        r = https_request(ip, host, path, "GET", None, timeout, read_max, read_max, body_seconds)
        if r.ok and r.status == 200 and r.nbytes > 0:
            return r
    return None


def _parse_index(text, small_range, big_range, prefix):
    """索引行格式: <prefix>:/文件名,CDN路径,md5,CDN上实际大小,压缩前后大小[,mode]"""
    small = big = None
    for ln in text.splitlines():
        if not ln.startswith(prefix):
            continue
        f = ln.split(",")
        if len(f) < 4 or "/" not in f[1]:
            continue
        cdn = f[1].strip()
        try:
            size = int(f[3])
        except ValueError:
            continue
        if small is None and small_range[0] <= size <= small_range[1]:
            small = (cdn, size)
        if big_range[0] <= size <= big_range[1] and (big is None or size > big[1]):
            big = (cdn, size)
    return small, big


def _pick_big_files(text, prefix, lo, hi, count):
    """按体积从大到小挑 count 个文件（CDN 上的真实更新文件），用作测速目标。"""
    rows = []
    for ln in text.splitlines():
        if not ln.startswith(prefix):
            continue
        f = ln.split(",")
        if len(f) < 4 or "/" not in f[1]:
            continue
        try:
            size = int(f[3])
        except ValueError:
            continue
        if lo <= size <= hi:
            rows.append((size, f[1].strip()))
    rows.sort(reverse=True)
    return rows[:count]


def discover_probes(st, force=False):
    """返回 {域名: {"probe": 小文件路径, "speed": 大文件路径, "size": 字节}}，失败返回 {}。"""
    hours = float(st.get("discover_cache_hours", 72))
    if not force:
        cached, build = load_probe_cache(hours)
        if cached:
            if cache_still_valid(cached, st):
                dim("  复用已缓存的 EVE 更新索引（build %s）" % build)
                return cached
            dim("  缓存的更新索引已失效（EVE 可能更新了版本），重新获取…")

    # 系统解析优先（可能是上一轮写进 hosts 的节点），但同时准备好备用节点：
    # 万一那个旧节点已经失效，这里也能自愈，不至于连索引都拿不到。
    ips = system_resolve(BIN_HOST)
    for ip in gather_candidates(BIN_HOST, None, int(st["threads"])):
        if ip not in ips:
            ips.append(ip)
    if not ips:
        warn("  解析不到 %s，改用内置探测路径" % BIN_HOST)
        return {}

    r = _fetch_from_any(BIN_HOST, "/eveclient_TQ.json", ips, 16384, 12.0, 8.0)
    if not r:
        warn("  读不到 EVE 版本信息，改用内置探测路径")
        return {}
    try:
        build = str(json.loads(r.body.decode("utf-8", "replace"))["build"])
    except Exception:
        warn("  版本信息格式异常，改用内置探测路径")
        return {}

    r2 = _fetch_from_any(BIN_HOST, "/eveonline_%s.txt" % build, ips, 4000000, 25.0, 20.0)
    if not r2:
        warn("  读不到客户端索引，改用内置探测路径")
        return {}
    app_txt = r2.body.decode("utf-8", "replace")

    probes = {}
    big_app = _pick_big_files(app_txt, "app:", 6000000, 300000000, 2)
    probes[BIN_HOST] = {"probe": "/eveclient_TQ.json",   # 启动器每次必取，边缘一定是热的
                        "speed": ("/" + big_app[0][1]) if big_app else None,
                        "speed_list": ["/" + c for _sz, c in big_app],
                        "size": big_app[0][0] if big_app else 0}

    res_index = None
    for ln in app_txt.splitlines():
        if ln.startswith("app:/resfileindex"):
            f = ln.split(",")
            if len(f) >= 4:
                try:
                    cand = (f[1].strip(), int(f[3]))
                except ValueError:
                    continue
                if res_index is None or cand[1] < res_index[1]:
                    res_index = cand
    if res_index:
        r3 = _fetch_from_any(BIN_HOST, "/" + res_index[0], ips, 3000000, 30.0, 25.0)
        if r3:
            res_txt = r3.body.decode("utf-8", "replace")
            s2, _b2 = _parse_index(res_txt, (1000, 100000), (700000, 8000000), "res:")
            big_res = _pick_big_files(res_txt, "res:", 400000, 100000000, 10)
            if s2:
                probes[RES_HOST] = {"probe": "/" + s2[0],
                                    "speed": ("/" + big_res[0][1]) if big_res else None,
                                    "speed_list": ["/" + c for _sz, c in big_res],
                                    "size": sum(sz for sz, _c in big_res)}

    info("  已锁定 EVE build %s 的真实更新文件作为验证目标" % build)
    save_probe_cache(probes, build)
    return probes


# --------------------------------------------------------------------------
# 节点验证：探测路径 -> 指纹交叉比对 -> 延迟/速度
# --------------------------------------------------------------------------
def _sig_content(r):
    return (r.status, r.headers.get("etag", ""), r.headers.get("content-length", ""),
            hashlib.sha1(r.body).hexdigest())


def _sig_meta(r):
    return (r.status, r.headers.get("etag", ""), r.headers.get("content-length", ""))


def _sig_status(r):
    return (r.status,)


SIG_LEVELS = [("内容哈希一致", _sig_content), ("ETag/长度一致", _sig_meta), ("状态码一致", _sig_status)]


def choose_probe(host, probes, ips, st):
    """从候选节点里试出一个真正能拿到文件的探测路径，作为后续验证基准。"""
    sample = list(ips)
    random.shuffle(sample)
    sample = sample[:5]
    fallback = None
    for path in probes:
        results = []
        if not sample:
            break
        with ThreadPoolExecutor(max_workers=len(sample)) as ex:
            futs = [ex.submit(https_request, ip, host, path, "GET", None,
                              st["verify_timeout"], 262144, 131072) for ip in sample]
            for f in futs:
                try:
                    results.append(f.result())
                except Exception:
                    pass
        good = [r for r in results if r.ok and r.status == 200 and r.nbytes > 0]
        if good:
            return path, 200, good[0].headers.get("server", "")
        if fallback is None:
            alt = [r for r in results if r.ok and 200 <= r.status < 400]
            if alt:
                fallback = (path, alt[0].status, alt[0].headers.get("server", ""))
    return fallback if fallback else (None, 0, "")


def measure_latency(ip, host, path, st, samples=3):
    vals = []
    for _ in range(samples):
        r = https_request(ip, host, path, "GET", None, st["verify_timeout"], 4096, 0)
        if r.ok and r.status < 500:
            vals.append(r.t_ttfb)
    if not vals:
        return None
    vals.sort()
    return vals[len(vals) // 2]


def measure_speed(ip, host, paths, st, seconds=None, want=None, warmup=0,
                  warmup_secs=0.0):
    """用真实更新文件测速，可以连续下多个文件——资源域名上单个文件最大才 4MB，
    而启动器本来就是一个接一个地下几千个资源文件，连着下更贴近真实情况。
    返回 (整段平均速度, 持续速度, 实下字节数, 是否真的下到了东西)。
    持续速度 = 跑完 warmup 字节之后那一段的速度，用来识别"起步猛、几 MB 后掉到几十 KB"。"""
    if isinstance(paths, str):
        paths = [paths]
    paths = [x for x in paths if x]
    if not paths:
        return 0.0, 0.0, 0, False
    want = int(want or st["speed_bytes"])
    secs = float(seconds or st["speed_seconds"])
    warmup = int(warmup)
    warmup_secs = float(warmup_secs)

    t0 = time.perf_counter()
    deadline = t0 + secs
    total = 0
    warm_n = 0
    warm_t = 0.0
    got_any = False
    for path in paths:
        left_time = deadline - time.perf_counter()
        if left_time <= 0.3 or total >= want:
            break
        left_bytes = want - total
        r = https_request(ip, host, path, "GET",
                          {"Range": "bytes=0-%d" % (left_bytes - 1)},
                          timeout=st["verify_timeout"], read_max=left_bytes, keep_max=0,
                          body_seconds=left_time, port=443,
                          warmup_bytes=(max(0, warmup - total) if (warmup and not warm_n) else 0),
                          warmup_seconds=(max(0.05, warmup_secs - (time.perf_counter() - t0))
                                          if (warmup_secs and not warm_n) else 0.0))
        if not (r.ok and r.status in (200, 206) and r.nbytes > 0):
            if got_any:
                break
            return 0.0, 0.0, 0, False
        got_any = True
        if (warmup or warmup_secs) and not warm_n and r.n_warm:
            # 换算成"从测速开始"的相对时刻
            req_start = (time.perf_counter() - t0) - r.t_total
            warm_n = total + r.n_warm
            warm_t = req_start + r.t_warm
        total += r.nbytes

    elapsed = time.perf_counter() - t0
    if not got_any or elapsed <= 0.05:
        return 0.0, 0.0, 0, False
    # 样本太小时不报速度（比如探测路径只是个几百字节的页面）
    overall = (total / elapsed) if total >= 65536 else 0.0
    sustained = 0.0
    if warm_n:
        dt, nb = elapsed - warm_t, total - warm_n
        if dt >= 0.8 and nb >= 32768:
            sustained = nb / dt
    return overall, sustained, total, True


def eff_speed(m):
    """给节点排名用的速度：有持续速度就用持续速度，否则退回整段平均。"""
    return m.get("sustained") or m.get("speed") or 0.0


def evaluate_domain(dcfg, ecs, st, dyn=None):
    host = dcfg["host"]
    probes = list(dcfg.get("probes") or ["/"])
    dyn = dyn or {}
    if dyn.get("probe"):
        probes.insert(0, dyn["probe"])
    if "/" not in probes:
        probes.append("/")
    out = {"host": host, "note": dcfg.get("note", ""), "ok": False, "reason": "",
           "total": 0, "alive": 0, "valid": 0, "best": None, "probe": "", "level": "",
           "expect": 0, "sig": None, "baseline": None, "valid_list": [],
           "optional": bool(dcfg.get("optional")), "speed_path": "", "real_file": False}

    step("[%s] %s" % (host, dcfg.get("note", "")))
    found = gather_candidates(host, ecs, st["threads"])
    ips = list(found.keys())
    out["total"] = len(ips)
    if not ips:
        out["reason"] = "所有 DNS 都没解析出可用的 IPv4（域名可能已废弃或被完全阻断）"
        err("  %s" % out["reason"])
        return out
    info("  多路 DNS 共得到 %d 个候选 IPv4" % len(ips))

    probe_path, expect, server = choose_probe(host, probes, ips, st)
    if not probe_path:
        out["reason"] = "没有任何候选节点能通过 TLS+HTTP 验证（该域名当前直连也可能是坏的）"
        err("  %s" % out["reason"])
        return out
    out["probe"], out["expect"] = probe_path, expect
    info("  验证基准：GET %s  期望状态 %d" % (probe_path[:52], expect))

    if st.get("cf_scan", True) and "cloudflare" in (server or "").lower():
        info("  该域名由 Cloudflare 任播承载，正在就近扫描边缘节点…")
        extra = scan_cloudflare_edges(int(st.get("cf_scan_count", 320)),
                                      int(st.get("cf_keep", 12)))
        added = 0
        for ip in extra:
            if ip not in found:
                added += 1
            found.setdefault(ip, set()).add("cf-scan")
        for ip in _FAST_CF_NODES:
            if ip not in found:
                added += 1
            found.setdefault(ip, set()).add("前一个域名的优胜节点")
        ips = list(found.keys())
        out["total"] = len(ips)
        info("  新增 %d 个延迟最低的 Cloudflare 边缘节点，候选共 %d 个" % (added, len(ips)))

    results = []
    with ThreadPoolExecutor(max_workers=st["threads"]) as ex:
        futs = {ex.submit(https_request, ip, host, probe_path, "GET", None,
                          st["verify_timeout"], 262144, 131072): ip for ip in ips}
        for f in futs:
            try:
                results.append(f.result())
            except Exception:
                pass
    alive = [r for r in results if r.ok]
    out["alive"] = len(alive)

    hit = [r for r in alive if r.status == expect]
    if not hit:
        codes = Counter(r.status for r in alive)
        out["reason"] = "节点都连得上但没有一个返回期望内容（状态分布 %s）" % dict(codes)
        err("  %s" % out["reason"])
        return out

    valid, level = hit, "无法交叉验证(仅1个可用节点)"
    if len(hit) >= 2:
        for name, fn in SIG_LEVELS:
            c = Counter(fn(r) for r in hit)
            top, n = c.most_common(1)[0]
            if n >= 2 and n >= len(hit) * 0.34:
                valid = [r for r in hit if fn(r) == top]
                level = name
                out["sig"] = (name, top)
                break
    out["level"] = level
    out["valid"] = len(valid)
    info("  证书+内容验证通过 %d/%d 个（判定依据：%s）" % (len(valid), len(ips), level))

    sys_ips = system_resolve(host)
    base_ip = sys_ips[0] if sys_ips else None

    top_n = sorted(valid, key=lambda r: r.t_ttfb)[:int(st["speed_top_n"])]
    test_ips = [r.ip for r in top_n]
    # 前一个同 CDN 域名跑出好速度的节点必须进决赛圈，
    # 否则光按 TTFB 排名会把"延迟一般但吞吐很高"的节点挤掉。
    _valid_ips = set(r.ip for r in valid)
    for ip in _FAST_CF_NODES:
        if ip in _valid_ips and ip not in test_ips:
            test_ips.append(ip)
    if base_ip and base_ip not in test_ips:
        test_ips.append(base_ip)

    speed_path = dyn.get("speed") or probe_path
    speed_list = list(dyn.get("speed_list") or ([speed_path] if speed_path else []))
    real_file = bool(dyn.get("speed"))
    out["speed_path"], out["real_file"] = speed_path, real_file
    if real_file:
        info("  测速目标：%d 个真实更新文件，共 %.1f MB"
             % (len(speed_list), dyn.get("size", 0) / 1048576.0))

    measured = {}
    with ThreadPoolExecutor(max_workers=min(len(test_ips), 8) or 1) as ex:
        lat_f = {ip: ex.submit(measure_latency, ip, host, probe_path, st,
                               int(st["latency_samples"])) for ip in test_ips}
        lat = {ip: (f.result() if f else None) for ip, f in lat_f.items()}
    # 测速串行进行，避免几个节点互相抢带宽把结果测低。
    # 第一轮：短时间粗测，先把根本下不动的淘汰掉。
    for ip in test_ips:
        sp, _sus, nb, dl_ok = measure_speed(
            ip, host, speed_list[:1], st,
            seconds=float(st.get("quick_seconds", 3.0)),
            want=int(st.get("quick_bytes", 3145728)))
        measured[ip] = {"ip": ip, "latency": lat.get(ip), "speed": sp, "sustained": 0.0,
                        "bytes": nb, "dl_ok": dl_ok, "src": sorted(found.get(ip, []))[:3]}

    # 第二轮：只对领先的几个做长测，专门量"前几 MB 之后还剩多少"。
    # 很多节点起步很猛、几 MB 之后掉到几十 KB，只测前几秒会正好挑中这种。
    warmup = int(st.get("warmup_bytes", 2621440))
    if real_file:
        pool = [m for m in measured.values() if m["dl_ok"]]
        pool.sort(key=lambda m: -m["speed"])
        finals = [m["ip"] for m in pool[:int(st.get("sustain_top_n", 3))]]
        if base_ip and base_ip in measured and base_ip not in finals:
            finals.append(base_ip)
        if finals:
            info("  复测持续速度：每个节点最多下 %.0f MB，前 %.0f MB 或前 %.0f 秒算起步不计入…"
                 % (int(st["speed_bytes"]) / 1048576.0, warmup / 1048576.0,
                    float(st.get("warmup_seconds", 2.0))))
            for ip in finals:
                sp, sus, nb, dl_ok = measure_speed(
                    ip, host, speed_list, st, warmup=warmup,
                    warmup_secs=float(st.get("warmup_seconds", 2.0)))
                if not dl_ok:
                    measured[ip]["dl_ok"] = False
                    dim("    %-15s 长测失败，淘汰" % ip)
                    continue
                m = measured[ip]
                m["speed"], m["sustained"], m["bytes"], m["dl_ok"] = sp, sus, nb, True
                dim("    %-15s 起步 %-11s 持续 %s"
                    % (ip, human_speed(sp), human_speed(sus) if sus > 0 else "样本不足(用起步值)"))

    valid_ips = set(r.ip for r in valid)
    ranked = [measured[ip] for ip in test_ips
              if ip in valid_ips and measured.get(ip)
              and measured[ip]["latency"] is not None]
    if real_file:
        usable = [m for m in ranked if m["dl_ok"]]
        if usable:
            ranked = usable
        else:
            out["reason"] = "节点都握手正常，但没有一个能下载真实更新文件，已放弃该域名"
            err("  %s" % out["reason"])
            return out
    if not ranked:
        out["reason"] = "复测阶段全部超时，节点不稳定，放弃该域名"
        err("  %s" % out["reason"])
        return out

    if any(eff_speed(m) > 0 for m in ranked):
        ranked.sort(key=lambda m: (-eff_speed(m), m["latency"]))
    else:
        ranked.sort(key=lambda m: m["latency"])

    out["best"] = ranked[0]
    out["valid_list"] = ranked
    if base_ip and measured.get(base_ip) and measured[base_ip]["latency"] is not None:
        out["baseline"] = measured[base_ip]
    out["ok"] = True

    b = out["best"]
    if "cloudflare" in (server or "").lower() and b["speed"] > 1048576:
        if b["ip"] in _FAST_CF_NODES:
            _FAST_CF_NODES.remove(b["ip"])
        _FAST_CF_NODES.insert(0, b["ip"])
        del _FAST_CF_NODES[6:]
    msg = "  最优节点 %s  延迟 %.0f ms" % (b["ip"], b["latency"] * 1000)
    if b.get("sustained"):
        msg += "  持续 %s（起步 %s）" % (human_speed(b["sustained"]), human_speed(b["speed"]))
    elif b["speed"] > 0:
        msg += "  速度 %s" % human_speed(b["speed"])
    ok(msg)
    tested = [m for m in ranked if m.get("sustained")]
    if tested and all(m["sustained"] < m["speed"] * 0.25 for m in tested):
        warn("  所有节点都是起步猛、几 MB 之后掉速——这是线路/运营商在限速，")
        warn("  换 hosts 只能挑掉速后相对最快的那个，治不了根。可试试错峰或代理。")
    if out["baseline"] and out["baseline"]["ip"] != b["ip"]:
        bl = out["baseline"]
        cmp_txt = "  当前直连 %s 延迟 %.0f ms" % (bl["ip"], bl["latency"] * 1000)
        if eff_speed(bl) > 0:
            cmp_txt += "  速度 %s" % human_speed(eff_speed(bl))
        dim(cmp_txt)
    return out


def human_size(n):
    if n >= 1073741824:
        return "%.2f GB" % (n / 1073741824.0)
    if n >= 1048576:
        return "%.1f MB" % (n / 1048576.0)
    return "%.0f KB" % (n / 1024.0)


def human_speed(bps):
    if bps <= 0:
        return "-"
    if bps >= 1024 * 1024:
        return "%.2f MB/s" % (bps / 1024.0 / 1024.0)
    return "%.0f KB/s" % (bps / 1024.0)


# --------------------------------------------------------------------------
# hosts 读写
# --------------------------------------------------------------------------
def read_hosts_text():
    try:
        with open(HOSTS_PATH, "rb") as f:
            return f.read().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        return ""


def write_hosts_text(text):
    raw = text.encode("utf-8", "surrogateescape")
    if IS_WIN:
        try:
            ctypes.windll.kernel32.SetFileAttributesW(HOSTS_PATH, 0x80)  # 去掉只读
        except Exception:
            pass
    last = None
    for _ in range(3):
        try:
            with open(HOSTS_PATH, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            return True, ""
        except Exception as e:
            last = e
            time.sleep(0.4)
    return False, str(last)


def strip_block(text):
    out, skipping, removed = [], False, False
    for ln in text.splitlines(True):
        s = ln.strip()
        if s.startswith("# ==== EVE-ACCEL BEGIN"):
            skipping, removed = True, True
            continue
        if s.startswith("# ==== EVE-ACCEL END"):
            skipping = False
            continue
        if not skipping:
            out.append(ln)
    res = "".join(out)
    if removed:
        # 顺手清掉我们自己加的空行，避免反复启用/还原后文件尾部堆一堆空行
        trimmed = res.rstrip("\r\n")
        res = (trimmed + "\r\n") if trimmed else ""
    return res


def has_block(text):
    return "# ==== EVE-ACCEL BEGIN" in text


def cleanup_legacy_backups():
    """清掉 1.0 版按时间戳堆下来的一堆历史备份。"""
    if not os.path.isdir(LEGACY_BACKUP_DIR):
        return 0
    n = 0
    try:
        for f in os.listdir(LEGACY_BACKUP_DIR):
            if f.startswith("hosts_") and f.endswith(".bak"):
                try:
                    os.remove(os.path.join(LEGACY_BACKUP_DIR, f))
                    n += 1
                except Exception:
                    pass
        if not os.listdir(LEGACY_BACKUP_DIR):
            os.rmdir(LEGACY_BACKUP_DIR)
    except Exception:
        pass
    return n


def backup_hosts(text):
    """只保留一份备份：内容永远是"去掉加速段之后"的用户原始 hosts，覆盖写入，不堆文件。"""
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(BACKUP_FILE, "wb") as f:
            f.write(strip_block(text).encode("utf-8", "surrogateescape"))
        cleanup_legacy_backups()
        return BACKUP_FILE
    except Exception as e:
        warn("备份失败：%s" % e)
        return None


def migrate_backups():
    """老版本升上来时：先确保有那份唯一备份，再把历史备份清掉。"""
    if not os.path.isdir(LEGACY_BACKUP_DIR):
        return
    if not os.path.exists(BACKUP_FILE):
        backup_hosts(read_hosts_text())
    n = cleanup_legacy_backups()
    if n:
        dim("已清理旧版留下的 %d 份历史备份，现在只保留一份：%s" % (n, BACKUP_FILE))


def build_block(entries):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = [MARK_BEGIN,
             "# 生成时间 %s  by %s v%s" % (ts, APP_NAME, APP_VER),
             "# 全部节点均已通过 证书校验 + 真实下载内容比对，仅 IPv4",
             "# 还原：重新运行本程序选 [3]，或手工删除 BEGIN~END 之间所有行"]
    for e in entries:
        tail = "%.0fms" % (e["latency"] * 1000)
        if e["speed"] > 0:
            tail += " / " + human_speed(e["speed"])
        lines.append("%-16s %-38s # %s %s" % (e["ip"], e["host"], tail, e.get("note", "")))
    lines.append(MARK_END)
    return "\r\n".join(lines) + "\r\n"


def _run_quiet(cmd, timeout=20):
    kw = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "timeout": timeout}
    if IS_WIN:
        kw["creationflags"] = 0x08000000
    try:
        subprocess.run(cmd, **kw)
        return True
    except Exception:
        return False


def flush_dns():
    if IS_WIN:
        cmds = [["ipconfig", "/flushdns"]]
    elif IS_MAC:
        cmds = [["dscacheutil", "-flushcache"],
                ["killall", "-HUP", "mDNSResponder"]]
    else:
        cmds = [["resolvectl", "flush-caches"],
                ["systemd-resolve", "--flush-caches"]]
    for c in cmds:
        _run_quiet(c)


def apply_entries(entries, do_backup=True):
    """写 hosts，返回 (成功?, 旧文本, 备份路径)"""
    old = read_hosts_text()
    bak = backup_hosts(old) if do_backup else None
    base = strip_block(old)
    if base and not base.endswith("\n"):
        base += "\r\n"
    new = base + "\r\n" + build_block(entries)
    okw, msg = write_hosts_text(new)
    if not okw:
        return False, old, bak, msg
    return True, old, bak, ""


# --------------------------------------------------------------------------
# 落地复检 + 回滚
# --------------------------------------------------------------------------
def verify_entry(e, st, ip=None, attempts=2):
    """直连某个 IP，确认它现在确实能给出正确内容、并且能下真实更新文件。
    返回 (是否可用, 说明)。会重试，避免一次网络抖动就把好节点判死。"""
    ip = ip or e["ip"]
    why = "未知"
    for i in range(attempts):
        r = https_request(ip, e["host"], e["probe"], "GET", None,
                          st["verify_timeout"], 262144, 131072)
        good = r.ok and r.status == e["expect"]
        why = r.err or ("HTTP %s" % r.status)
        if good and e.get("sig"):
            name, top = e["sig"]
            fn = dict(SIG_LEVELS)[name]
            if fn(r) != top:
                good, why = False, "返回内容与官方不一致"
        # 最关键的一步：真的去拉一段更新文件下来
        if good and e.get("real_file") and e.get("speed_path"):
            d = https_request(ip, e["host"], e["speed_path"], "GET",
                              {"Range": "bytes=0-262143"}, st["verify_timeout"],
                              262144, 0, 12.0)
            if not (d.ok and d.status in (200, 206) and d.nbytes >= 65536):
                good = False
                why = d.err or ("下载真实更新文件失败 HTTP %s，只拿到 %d 字节"
                                % (d.status, d.nbytes))
        if good:
            return True, "%.0f ms" % (r.t_ttfb * 1000)
        if i + 1 < attempts:
            time.sleep(0.6)
    return False, why


def post_check(entries, st):
    """hosts 生效后再验一遍：系统解析是否指向我们的 IP，且这个 IP 现在真的能下东西。"""
    bad = []
    for e in entries:
        host, ip = e["host"], e["ip"]
        sys_ips = system_resolve(host)
        pinned = ip in sys_ips
        target = sys_ips[0] if sys_ips else ip
        good, why = verify_entry(e, st, ip=target, attempts=2)
        if good:
            ok("  %-32s -> %-15s 复检通过 (%s)%s"
               % (host, ip, why, "" if pinned else "  [注意: 系统解析未指向该 IP]"))
        else:
            bad.append((host, ip, why))
            err("  %-32s -> %-15s 复检失败: %s" % (host, ip, why))
    return bad


def rollback(old_text):
    okw, msg = write_hosts_text(old_text)
    flush_dns()
    return okw, msg


# --------------------------------------------------------------------------
# EVE 共享缓存（SharedCache）位置探测
#   启动器把资源文件按 CDN 路径存在 <SharedCache>/ResFiles/<2位>/<名字>，
#   所以只要文件在那儿，启动器就不会再去下载它。预下载功能靠的就是这个。
# --------------------------------------------------------------------------
def _cache_candidates():
    out = []
    if IS_WIN:
        try:
            import winreg
            for hive, path, name in (
                    (winreg.HKEY_CURRENT_USER, r"Software\CCP\EVEONLINE", "CACHEFOLDER"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\CCP\EVEONLINE", "CACHEFOLDER")):
                try:
                    with winreg.OpenKey(hive, path) as k:
                        v, _t = winreg.QueryValueEx(k, name)
                        if v:
                            out.append(os.path.normpath(str(v)))
                except OSError:
                    pass
        except Exception:
            pass
        # 启动器日志里也会写出实际路径
        try:
            import glob as _glob
            logs = sorted(_glob.glob(os.path.join(
                os.environ.get("LOCALAPPDATA", ""), "CCP", "EVE", "Launcher",
                "launcherlog-*.txt")))
            pat = re.compile(r"([A-Za-z]:[\\/][^\"'<>|\r\n]*?SharedCache)", re.I)
            for f in logs[-3:]:
                try:
                    with io.open(f, encoding="utf-8", errors="replace") as fh:
                        txt = fh.read()
                except Exception:
                    continue
                for m in pat.finditer(txt):
                    out.append(os.path.normpath(m.group(1)))
        except Exception:
            pass
        for base in ("C:\\ProgramData\\CCP\\EVE\\SharedCache",
                     os.path.join(os.environ.get("LOCALAPPDATA", ""), "CCP", "EVE", "SharedCache")):
            out.append(base)
        for drive in "CDEFGH":
            for sub in ("EVE", "Games\\EVE", "Program Files\\EVE",
                        "Program Files (x86)\\EVE"):
                out.append("%s:\\%s\\SharedCache" % (drive, sub))
    elif IS_MAC:
        out += [os.path.expanduser("~/Library/Application Support/EVE Online/SharedCache"),
                os.path.expanduser("~/Library/Application Support/CCP/EVE/SharedCache")]
    else:
        out += [os.path.expanduser("~/.eve/SharedCache"),
                os.path.expanduser("~/EVE/SharedCache")]
        # Linux 下多半跑在 Wine/Proton 里
        for wp in ("~/.wine/drive_c/EVE/SharedCache",
                   "~/.steam/steam/steamapps/compatdata"):
            out.append(os.path.expanduser(wp))
    return out


_CACHE_PATH = None


def find_shared_cache(configured=None, force=False):
    """返回 SharedCache 目录（其下必须有 ResFiles），找不到返回 None。"""
    global _CACHE_PATH
    if _CACHE_PATH and not force:
        return _CACHE_PATH
    cands = []
    if configured:
        cands.append(os.path.expanduser(str(configured)))
    cands += _cache_candidates()
    seen = set()
    for c in cands:
        if not c:
            continue
        c = os.path.normpath(c.rstrip("/\\"))
        key = c.lower()
        if key in seen:
            continue
        seen.add(key)
        if os.path.isdir(os.path.join(c, "ResFiles")):
            _CACHE_PATH = c
            return c
    return None


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def config_path():
    return os.path.join(base_dir(), "eve_accel.json")


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    p = config_path()
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                user = json.load(f)
            if str(user.get("_version", "")) != APP_VER:
                old = p + ".old"
                try:
                    os.replace(p, old)
                except Exception:
                    pass
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                warn("配置文件是旧版本，已重置为 v%s 的默认域名列表（旧文件留在 %s）"
                     % (APP_VER, os.path.basename(old)))
                return cfg
            if isinstance(user.get("domains"), list) and user["domains"]:
                cfg["domains"] = [d for d in user["domains"] if d.get("host")]
            if isinstance(user.get("settings"), dict):
                cfg["settings"].update(user["settings"])
            dim("已加载配置 %s" % p)
        except Exception as e:
            warn("配置文件解析失败，改用内置默认：%s" % e)
    else:
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            dim("已生成默认配置 %s（可自行增删域名）" % p)
        except Exception:
            pass
    return cfg


EVE_PROC_NAMES = ("evelauncher.exe", "eve.exe", "exefile.exe", "eveonline.exe",
                  "eveclient.exe", "evelauncher", "eve online")


def eve_processes_running():
    """启动器/客户端要是正在后台下载，会把所有节点的测速一起拉低，测出来的排名没有意义。"""
    try:
        if IS_WIN:
            cmd = ["tasklist", "/FO", "CSV", "/NH"]
            kw = {"creationflags": 0x08000000}
        else:
            cmd = ["ps", "-axco", "command"] if IS_MAC else ["ps", "-eo", "comm"]
            kw = {}
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=20, **kw)
        txt = (out.stdout or b"").decode("utf-8", "replace").lower()
    except Exception:
        return []
    found = []
    for name in EVE_PROC_NAMES:
        if name in txt and name not in found:
            found.append(name)
    return found


def has_global_ipv6():
    s = None
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("2400:3200::1", 53))
        addr = s.getsockname()[0]
        return not (addr.startswith("fe80") or addr in ("::", "::1"))
    except Exception:
        return False
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# 动作
# --------------------------------------------------------------------------
def banner():
    info("")
    info("%s============================================================%s" % (C_BLUE, C_RESET))
    info("%s  %s  v%s%s" % (C_BOLD, APP_NAME, APP_VER, C_RESET))
    info("  多路DNS找节点 → 证书+真实内容验证 → 测速 → 写hosts → 落地复检")
    info("  仅 IPv4 · 任何一步验不过就不写 · 复检不过自动回滚")
    info("%s============================================================%s" % (C_BLUE, C_RESET))
    info("")


def scan(cfg):
    st = cfg["settings"]
    procs = eve_processes_running()
    if procs:
        warn("检测到 EVE 相关进程正在运行：%s" % "、".join(procs))
        warn("如果启动器正在下载，它会和测速抢同一条带宽，所有节点都会被一起拉低，")
        warn("测出来的排名不作数。建议先完全退出启动器和客户端再测。")
    if has_global_ipv6():
        warn("检测到本机有可用 IPv6：hosts 只能改 IPv4，若启动器走 AAAA 记录加速会失效。")
        warn("如果加速后仍然慢，可在“网络适配器属性”里临时取消勾选 IPv6 再试。")
    step("获取出口 IP（用于让 DNS 返回离你最近的节点）…")
    pub = get_public_ipv4()
    ecs = None
    if pub:
        ecs = ".".join(pub.split(".")[:3]) + ".0/24"
        info("  出口 IP %s，ECS 使用 %s" % (pub, ecs))
    else:
        warn("  拿不到出口 IP，跳过 ECS（不影响验证，只是候选节点会少一些）")
    info("")
    step("获取 EVE 官方更新索引（拿真实更新文件当验证/测速目标）…")
    try:
        dyn_all = discover_probes(st)
    except Exception as e:
        warn("  索引获取失败：%s，改用内置探测路径" % e)
        dyn_all = {}
    info("")

    results = []
    for d in cfg["domains"]:
        if d.get("enabled") is False:
            dim("[跳过] %s（配置里 enabled=false）" % d.get("host"))
            continue
        try:
            results.append(evaluate_domain(d, ecs, st, dyn_all.get(d.get("host"))))
        except Exception as e:
            err("[%s] 检测异常：%s" % (d.get("host"), e))
            results.append({"host": d.get("host"), "ok": False, "reason": str(e),
                            "note": d.get("note", ""), "best": None,
                            "optional": bool(d.get("optional"))})
        info("")
    return results


def print_summary(results):
    info("%s---------------------------- 检测结果 ----------------------------%s"
         % (C_BOLD, C_RESET))
    info("%-32s %-16s %-9s %-11s %s" % ("域名", "最优节点", "延迟", "速度", "验证"))
    for r in results:
        if r.get("ok") and r.get("best"):
            b = r["best"]
            mark = "真实文件" if r.get("real_file") else "内容比对"
            info("%-32s %-16s %-9s %-11s %d/%d 通过 (%s)"
                 % (r["host"], b["ip"], "%.0f ms" % (b["latency"] * 1000),
                    human_speed(eff_speed(b)), r["valid"], r["total"], mark))
            if b.get("sustained") and b["speed"] > b["sustained"] * 1.3:
                dim("%-32s %-16s 起步 %s，掉速后 %s（表里按掉速后算）"
                    % ("", "", human_speed(b["speed"]), human_speed(b["sustained"])))
            bl = r.get("baseline")
            if bl and bl["ip"] != b["ip"]:
                gain = ""
                if eff_speed(bl) > 0 and eff_speed(b) > 0:
                    gain = "，速度 %+.0f%%" % ((eff_speed(b) / eff_speed(bl) - 1) * 100)
                elif bl["latency"] and b["latency"]:
                    gain = "，延迟 %+.0f%%" % ((b["latency"] / bl["latency"] - 1) * 100)
                dim("%-32s %-16s 直连 %-13s %s%s"
                    % ("", bl["ip"], human_speed(bl["speed"]) if bl["speed"] > 0
                       else "%.0f ms" % (bl["latency"] * 1000), "对比", gain))
        else:
            color = C_DIM if r.get("optional") else C_YELLOW
            reason = r.get("reason", "无可用节点")
            if r.get("optional"):
                reason = "可选域名，没有可验证的下载路径，跳过"
            info("%s%-32s %-16s %s%s" % (color, r["host"], "-", reason, C_RESET))
    info("%s------------------------------------------------------------------%s"
         % (C_BOLD, C_RESET))
    real = [r for r in results if r.get("ok") and r.get("real_file") and r.get("best")]
    if real:
        best = max(eff_speed(r["best"]) for r in real)
        if 0 < best < 400 * 1024:
            warn("所有节点最快也只有 %s——这不是选哪个节点的问题，" % human_speed(best))
            warn("是你这条线到 Cloudflare 整体就这么快。可以试：")
            warn("  ① 确认 EVE 启动器/客户端没在后台下载（它会和测速抢带宽）；")
            warn("  ② 换个时间段再测（跨境线路晚高峰很容易这样）；")
            warn("  ③ 走代理或加速器绕开这段拥堵。")
    info("")


def need_admin_or_relaunch(flag):
    if is_admin():
        return True
    warn("修改 hosts 需要%s权限，正在请求提权…" % admin_word())
    if relaunch_as_admin([flag]):
        info("已在新的管理员窗口继续，本窗口可以关闭。")
        return False
    if IS_WIN:
        err("提权被拒绝。请右键本程序 →“以管理员身份运行”。")
    return False


def do_apply(cfg, results):
    st = cfg["settings"]
    entries = []
    for r in results:
        if r.get("ok") and r.get("best"):
            b = r["best"]
            entries.append({"host": r["host"], "ip": b["ip"], "latency": b["latency"],
                            "speed": eff_speed(b), "note": r.get("note", ""),
                            "probe": r["probe"], "expect": r["expect"], "sig": r.get("sig"),
                            "speed_path": r.get("speed_path") or r["probe"],
                            "real_file": bool(r.get("real_file")),
                            "alternates": list((r.get("valid_list") or [])[1:6])})
    if not entries:
        err("没有任何域名找到通过验证的节点，hosts 保持原样未做修改。")
        return False

    # ---- 写入前最后确认：测速到写入之间可能过了一分钟，节点状态会变 ----
    step("写入前最终确认（不合格就地换备选节点）…")
    final = []
    for e in entries:
        good, why = verify_entry(e, st)
        if good:
            ok("  %-32s %-15s 可用 (%s)" % (e["host"], e["ip"], why))
            final.append(e)
            continue
        warn("  %-32s %-15s 不可用：%s，改试备选节点" % (e["host"], e["ip"], why))
        picked = None
        for alt in e["alternates"]:
            cand = dict(e)
            cand["ip"] = alt["ip"]
            cand["latency"] = alt.get("latency") or e["latency"]
            cand["speed"] = eff_speed(alt)
            g2, w2 = verify_entry(cand, st)
            if g2:
                ok("  %-32s 改用备选 %-15s (%s)" % ("", cand["ip"], w2))
                picked = cand
                break
        if picked:
            final.append(picked)
        else:
            err("  %-32s 首选和备选都不可用，本次不加速这个域名" % e["host"])
    if not final:
        err("所有域名的节点在写入前都失效了，hosts 保持原样未做修改。")
        return False

    step("写入 hosts（%d 条）…" % len(final))
    okw, old_text, bak, msg = apply_entries(final)
    if not okw:
        err("写入失败：%s" % msg)
        err("请确认以管理员身份运行，且杀毒软件没有锁定 hosts 文件。")
        return False
    if bak:
        info("  原 hosts 已备份到 %s" % bak)
    ok("hosts 写入完成")

    step("刷新 DNS 缓存…")
    flush_dns()
    time.sleep(0.8)

    step("落地复检 —— 防止改完反而下不动的最后一道闸…")
    bad = post_check(final, st)
    if bad:
        bad_hosts = set(h for h, _ip, _w in bad)
        survivors = [e for e in final if e["host"] not in bad_hosts]
        if not survivors:
            err("所有域名都没通过复检，正在完全回滚…")
            rok, rmsg = rollback(old_text)
            if rok:
                ok("已回滚到修改前的 hosts，你的下载不会受影响。")
            else:
                err("回滚失败：%s！请手动用备份 %s 覆盖 %s" % (rmsg, bak, HOSTS_PATH))
            return False
        # 只把没过的域名摘掉，通过的继续保留——它们本来就是实测更快的
        warn("有 %d 个域名复检不通过，只把它们从 hosts 里摘掉，其余 %d 个保留。"
             % (len(bad), len(survivors)))
        for h, ip, w in bad:
            dim("    摘掉 %s (%s)：%s" % (h, ip, w))
        okw2, _old2, _bak2, msg2 = apply_entries(survivors, do_backup=False)
        if not okw2:
            err("重写 hosts 失败：%s，执行完全回滚。" % msg2)
            rollback(old_text)
            return False
        flush_dns()
        time.sleep(0.6)
        step("剔除后再复检一次…")
        if post_check(survivors, st):
            err("剔除后仍有域名不通过，执行完全回滚。")
            rollback(old_text)
            ok("已回滚到修改前的 hosts。")
            return False
        final = survivors

    info("")
    ok("加速已生效，当前 hosts 中的 %d 条：" % len(final))
    for e in final:
        extra = ("  %s" % human_speed(e["speed"])) if e["speed"] > 0 else ""
        info("    %-16s %-32s %.0f ms%s" % (e["ip"], e["host"], e["latency"] * 1000, extra))
    info("")
    warn("请完全退出 EVE 启动器（含托盘图标）后重新打开，让它重新解析域名。")
    return True


def _seconds_curve(samples, span):
    """把 (时刻, 累计字节) 采样点换算成每秒速度。"""
    out = []
    prev_t, prev_n = 0.0, 0
    for sec in range(1, int(span) + 1):
        cur = None
        for t, n in samples:
            if t <= sec:
                cur = (t, n)
            else:
                break
        if cur is None or cur[0] <= prev_t:
            continue
        out.append((sec, (cur[1] - prev_n) / (cur[0] - prev_t)))
        prev_t, prev_n = cur
    return out


def do_diagnose(cfg):
    """回答一个问题：掉速到底是这个节点/线路整体就这么慢，还是按连接限速？
    两者的应对完全不同，所以值得单独测一次。"""
    st = cfg["settings"]
    info("")
    step("掉速诊断（会实际下载数据，慢线路上大约几 MB）")
    dyn = discover_probes(st)
    d = dyn.get(BIN_HOST) or {}
    paths = list(d.get("speed_list") or [])
    if not paths:
        err("拿不到官方测速文件，没法诊断。")
        return
    ips = system_resolve(BIN_HOST)
    if not ips:
        err("解析不到 %s。" % BIN_HOST)
        return
    ip = ips[0]
    info("  测试节点 %s（当前 hosts / DNS 实际会用的那个）" % ip)

    # 1) 单连接长曲线
    span = 20.0
    samples = []
    r = https_request(ip, BIN_HOST, paths[0], "GET",
                      {"Range": "bytes=0-%d" % (40 * 1024 * 1024 - 1)},
                      timeout=st["verify_timeout"], read_max=40 * 1024 * 1024,
                      keep_max=0, body_seconds=span, port=443,
                      progress_cb=lambda n, el: samples.append((el, n)))
    if not (r.ok and r.nbytes > 0):
        err("  连下载都没建立起来：%s" % (r.err or r.status))
        return
    curve = _seconds_curve(samples, span)
    info("")
    info("  单连接每秒速度：")
    peak = max([sp for _s, sp in curve] or [1])
    for sec, sp in curve:
        bar = "#" * max(1, int(round(sp / peak * 32)))
        info("    第 %2d 秒  %-11s %s" % (sec, human_speed(sp), bar))
    head = [sp for sec, sp in curve if sec <= 3]
    tail = [sp for sec, sp in curve if sec >= max(4, len(curve) - 4)]
    head_avg = sum(head) / len(head) if head else 0.0
    tail_avg = sum(tail) / len(tail) if tail else 0.0
    info("  起步 3 秒平均 %s，最后几秒平均 %s"
         % (human_speed(head_avg), human_speed(tail_avg)))

    # 2) 立刻新开一条连接，看是不是又"满血"了
    info("")
    step("换一条全新连接再下 4 秒…")
    fresh, _sus, fnb, fok = measure_speed(ip, BIN_HOST, paths[:1], st,
                                          seconds=4.0, want=12 * 1024 * 1024)
    info("  新连接速度 %s" % (human_speed(fresh) if fok else "失败"))

    # 3) 4 条并发
    info("")
    step("4 条连接同时下 8 秒，看总吞吐能不能叠上去…")
    par = paths * 4
    results = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(measure_speed, ip, BIN_HOST, [par[i]], st, 8.0,
                          12 * 1024 * 1024) for i in range(4)]
        for f in futs:
            try:
                results.append(f.result())
            except Exception:
                pass
    total_par = sum(x[0] for x in results if x[3])
    info("  4 条并发合计 %s（单条约 %s）"
         % (human_speed(total_par), human_speed(total_par / 4.0 if total_par else 0)))

    # ---- 结论 ----
    info("")
    info("%s---------------------------- 诊断结论 ----------------------------%s"
         % (C_BOLD, C_RESET))
    collapsed = head_avg > 0 and tail_avg < head_avg * 0.4
    fresh_recovers = fresh > 0 and head_avg > 0 and fresh > head_avg * 0.6
    par_helps = total_par > 0 and tail_avg > 0 and total_par > tail_avg * 2.0

    if collapsed and fresh_recovers:
        warn("典型的【按连接限速】：一条连接下几 MB 之后被压下去，新开连接又满血。")
        info("  这种情况换 hosts 节点收益有限，真正有用的是并发下载：")
        info("  · EVE 启动器设置里如果有并发/同时下载数量的选项，调到最大；")
        info("  · 或者用支持多线程的代理/加速器。")
    elif collapsed and not fresh_recovers:
        warn("下载会掉速，而且新连接也起不来——更像是这条跨境线路整体拥堵。")
        info("  换节点能挑出相对最快的一个，但治不了根。建议错峰，或走代理。")
    elif not collapsed and tail_avg > 0:
        ok("单连接速度全程稳定在 %s 左右，没有掉速现象。" % human_speed(tail_avg))
        info("  如果启动器那边仍然慢，多半是它自己的问题（并发数、磁盘、杀毒实时扫描）。")
    else:
        warn("样本不足以下结论，建议在网络空闲时再跑一次。")

    if par_helps:
        info("")
        ok("并发有明显收益：4 条合计 %s，是单条掉速后 %s 的 %.1f 倍。"
           % (human_speed(total_par), human_speed(tail_avg), total_par / tail_avg))
        info("  说明瓶颈在【单连接】而不是总带宽——优先把启动器的并发下载数调大。")
    info("%s------------------------------------------------------------------%s"
         % (C_BOLD, C_RESET))


# --------------------------------------------------------------------------
# 并发预下载
#   线路按连接限速时，单条连接下几 MB 就会被压到几十 KB，而官方启动器是单线程下载，
#   换哪个节点都救不了。但 EVE 的资源文件是内容寻址的：
#       <SharedCache>/ResFiles/<2位>/<hash>_<md5>
#   文件名里就带着 md5。我们自己开多条连接把缺的文件下好放进去，
#   启动器再去更新时发现本地已有，直接跳过。
#   每个文件都校验 md5，先写临时文件再原子改名，绝不动已有文件。
# --------------------------------------------------------------------------
class PinnedSession(object):
    """连到指定 IP 的长连接（keep-alive），SNI 和证书校验都按域名走。
    几千个小文件复用一条连接，省掉每次握手。"""

    def __init__(self, ip, host, timeout=20.0, recycle=64):
        self.ip, self.host, self.timeout = ip, host, timeout
        self.recycle = max(1, int(recycle))
        self.served = 0
        self.sock = None
        self.fp = None

    def _connect(self):
        self.close()
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        raw.connect((self.ip, 443))
        self.sock = ssl_ctx().wrap_socket(raw, server_hostname=self.host)
        self.fp = self.sock.makefile("rb")

    def close(self):
        for c in (self.fp, self.sock):
            try:
                if c is not None:
                    c.close()
            except Exception:
                pass
        self.sock = self.fp = None

    def _read_head(self):
        line = self.fp.readline(8192)
        if not line:
            raise IOError("连接已关闭")
        parts = line.decode("iso-8859-1").strip().split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise IOError("响应不是 HTTP")
        status = int(parts[1])
        headers = {}
        while True:
            hl = self.fp.readline(16384)
            if not hl or hl in (b"\r\n", b"\n"):
                break
            if b":" in hl:
                k, v = hl.decode("iso-8859-1").split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers

    def _read_body(self, headers):
        te = headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            out = bytearray()
            while True:
                ln = self.fp.readline(128)
                if not ln:
                    break
                try:
                    size = int(ln.strip().split(b";")[0], 16)
                except Exception:
                    break
                if size == 0:
                    self.fp.readline(8)
                    break
                got = 0
                while got < size:
                    chunk = self.fp.read(min(65536, size - got))
                    if not chunk:
                        raise IOError("提前断开")
                    got += len(chunk)
                    out += chunk
                self.fp.read(2)
            return bytes(out)
        cl = headers.get("content-length", "")
        if cl.isdigit():
            need = int(cl)
            out = bytearray()
            while len(out) < need:
                chunk = self.fp.read(min(65536, need - len(out)))
                if not chunk:
                    raise IOError("提前断开")
                out += chunk
            return bytes(out)
        # 没有长度信息只能读到底，读完这条连接就废了
        data = self.fp.read()
        self.close()
        return data

    def get(self, path, retries=2):
        for attempt in range(retries + 1):
            try:
                if self.sock is None or self.served >= self.recycle:
                    self._connect()
                    self.served = 0
                req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                       "Accept: */*\r\nAccept-Encoding: identity\r\n"
                       "Connection: keep-alive\r\n\r\n" % (path, self.host, UA))
                self.sock.sendall(req.encode("ascii", "ignore"))
                status, headers = self._read_head()
                body = self._read_body(headers)
                self.served += 1
                if "close" in headers.get("connection", "").lower():
                    self.close()
                return status, body
            except Exception:
                self.close()
                if attempt >= retries:
                    return 0, b""
                time.sleep(0.3 + 0.3 * attempt)
        return 0, b""


def _pick_res_index(app_txt, st):
    """挑一份和当前平台匹配的资源索引，返回 (文件名, CDN路径, 大小, md5)。

    全量索引是跨平台的，里面有 Windows 客户端根本不会下载的文件。照着它比对，
    会让人白下几百 MB 用不到的东西。"""
    found = {}
    for ln in app_txt.splitlines():
        if not ln.startswith("app:/resfileindex"):
            continue
        f = ln.split(",")
        if len(f) < 5 or "/" not in f[1]:
            continue
        try:
            found[f[0].split("/")[-1]] = (f[1].strip(), int(f[3]), f[2].strip())
        except ValueError:
            continue
    if str(st.get("res_index", "auto")).lower() == "full":
        order = ["resfileindex.txt"]
    elif IS_WIN:
        order = ["resfileindex_Windows.txt", "resfileindex.txt"]
    else:
        order = ["resfileindex.txt"]
    for name in order:
        if name in found:
            cdn, size, md5 = found[name]
            return name, cdn, size, md5
    return None, None, 0, ""


def fetch_res_index(st, build, ips):
    """取资源索引，按 build 和索引名缓存到本地。"""
    app = _fetch_from_any(BIN_HOST, "/eveonline_%s.txt" % build, ips, 4000000, 25.0, 20.0)
    if not app:
        return None
    name, cdn, size, md5 = _pick_res_index(app.body.decode("utf-8", "replace"), st)
    if not cdn:
        return None

    cached = os.path.join(APP_DIR, "resindex_%s_%s" % (build, name))
    if os.path.exists(cached) and os.path.getsize(cached) >= size * 0.9:
        try:
            with io.open(cached, encoding="utf-8", errors="replace") as f:
                txt = f.read()
            dim("  复用已缓存的 %s" % name)
            return txt
        except Exception:
            pass

    info("  下载 %s（%s）…" % (name, human_size(size)))
    last = [0.0]

    def prog(n, el):
        if el - last[0] >= 1.0:
            last[0] = el
            sys.stdout.write("\r    %s / %s" % (human_size(n), human_size(size)))
            sys.stdout.flush()

    order = list(ips)
    if size > 2 * 1024 * 1024:          # 索引够大才值得先花时间挑节点
        fast = pick_download_nodes(BIN_HOST, "/" + cdn, st, want=2)
        order = fast + [x for x in ips if x not in fast]
    for ip in order[:4]:
        r = https_request(ip, BIN_HOST, "/" + cdn, "GET", None, 30.0,
                          size + 65536, size + 65536, 900.0, 443, 0, 0.0, prog)
        sys.stdout.write("\r" + " " * 44 + "\r")
        sys.stdout.flush()
        if r.ok and r.status == 200 and r.nbytes == size:
            if md5 and hashlib.md5(r.body).hexdigest() != md5:
                warn("    索引校验不通过，换个节点重试")
                continue
            txt = r.body.decode("utf-8", "replace")
            try:
                os.makedirs(APP_DIR, exist_ok=True)
                with io.open(cached, "w", encoding="utf-8", newline="") as f:
                    f.write(txt)
            except Exception as e:
                warn("    索引缓存没写成功，下次还得重下：%s" % e)
            return txt
    return None


def _bar_progress(prefix="    "):
    """下载进度回调：终端里原地刷新，重定向到文件时每 5 秒打一行。"""
    state = {"t": 0.0}
    try:
        tty = bool(sys.stdout.isatty())
    except Exception:
        tty = False
    start = time.perf_counter()

    def cb(done, total):
        now = time.perf_counter()
        if now - state["t"] < (0.5 if tty else 5.0):
            return
        state["t"] = now
        el = max(0.001, now - start)
        line = "%s%s / %s  %s" % (prefix, human_size(done), human_size(total),
                                  human_speed(done / el))
        if tty:
            sys.stdout.write("\r" + line + "    ")
            sys.stdout.flush()
        else:
            print(line, flush=True)
    return cb


def pick_download_nodes(host, sample_path, st, want=4):
    """拿一个真实文件当样本，实测候选节点的速度后排序。

    同一时刻不同边缘节点能差十倍以上，节点挑得对不对比开几条连接更能决定快慢。
    分两轮：先短测淘汰明显不行的，再对领先的几个测持续速度——有节点粗测 1.33 MB/s，
    复测时直接垮掉，只看头几秒会挑错人。"""
    cands = list(system_resolve(host))
    if st.get("cf_scan", True):
        try:
            for ip in scan_cloudflare_edges(int(st.get("cf_scan_count", 320)),
                                            int(st.get("cf_keep", 12))):
                if ip not in cands:
                    cands.append(ip)
        except Exception:
            pass
    seen, uniq = set(), []
    for ip in cands:
        if ip not in seen:
            seen.add(ip)
            uniq.append(ip)
    uniq = uniq[:8]
    if not uniq:
        return []

    info("  粗测 %d 个候选节点…" % len(uniq))
    rough = []
    for ip in uniq:
        # 串行测，免得互相抢带宽
        sp, _sus, _nb, okd = measure_speed(ip, host, [sample_path], st,
                                           seconds=3.0, want=3 * 1024 * 1024)
        if okd and sp > 0:
            rough.append((sp, ip))
        dim("    %-16s %s" % (ip, human_speed(sp) if sp else "不可用"))
    rough.sort(reverse=True)
    if len(rough) < 2:
        return [ip for _s, ip in rough[:want]]

    finals = rough[:3]
    info("  复测前 %d 名的持续速度…" % len(finals))
    rescored = []
    for _sp, ip in finals:
        sp, sus, _nb, okd = measure_speed(
            ip, host, [sample_path], st,
            seconds=float(st.get("speed_seconds", 7.0)),
            want=int(st.get("speed_bytes", 12582912)),
            warmup=int(st.get("warmup_bytes", 3145728)),
            warmup_secs=float(st.get("warmup_seconds", 2.0)))
        eff = sus or sp
        if okd and eff > 0:
            rescored.append((eff, ip))
        dim("    %-16s 起步 %-11s 持续 %s"
            % (ip, human_speed(sp), human_speed(sus) if sus else "样本不足"))
    if not rescored:
        return [ip for _s, ip in rough[:want]]
    rescored.sort(reverse=True)
    picked = [ip for _e, ip in rescored]
    return (picked + [ip for _s, ip in rough if ip not in picked])[:want]


def single_download(host, ip, path, size, expect_md5, dest, st, on_progress=None):
    """单连接下载一个文件，校验 md5 后原子落盘。

    EVE 的 CDN 不支持 Range（响应 chunked、无 content-length、带 Range 也返回 200），
    所以一个文件没法切给多条连接，只能挑一个快节点老实下。"""
    tmp = dest + ".eveaccel.part"
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
    except Exception as e:
        warn("  建目录失败：%s" % e)
        return False

    def prog(n, _el):
        if on_progress:
            on_progress(n, size)

    r = https_request(ip, host, path, "GET", None, float(st["verify_timeout"]),
                      size + 65536, size + 65536, 7200.0, 443, 0, 0.0, prog)
    if not (r.ok and r.status == 200 and r.nbytes == size):
        return False
    if expect_md5 and hashlib.md5(r.body).hexdigest() != expect_md5:
        warn("  校验不通过，已丢弃")
        return False
    try:
        with open(tmp, "wb") as fh:
            fh.write(r.body)
        os.replace(tmp, dest)
    except Exception as e:
        warn("  落盘失败：%s" % e)
        return False
    return True


def scan_local_resfiles(resroot):
    """把本地已有的资源文件名读成 {两位目录: 文件名集合}，比逐个 stat 快得多。"""
    have = {}
    try:
        for d in os.scandir(resroot):
            if not d.is_dir():
                continue
            names = set()
            try:
                for e in os.scandir(d.path):
                    if e.is_file():
                        names.add(e.name)
            except Exception:
                pass
            have[d.name.lower()] = names
    except Exception:
        pass
    return have


def do_predownload(cfg, assume_yes=False):
    st = cfg["settings"]
    info("")
    step("并发预下载：把缺的资源文件多线程下进 EVE 共享缓存")

    cache = find_shared_cache(st.get("shared_cache"))
    if not cache:
        err("找不到 EVE 共享缓存目录（SharedCache）。")
        info("  请在配置文件 eve_accel.json 里把 settings.shared_cache 填成你的 SharedCache 路径，")
        info("  例如 \"D:/EVE/SharedCache\"（那个目录下面应该有 ResFiles 文件夹）。")
        return False
    resroot = os.path.join(cache, "ResFiles")
    info("  共享缓存：%s" % cache)

    procs = eve_processes_running()
    if procs:
        warn("检测到 EVE 正在运行：%s" % "、".join(procs))
        warn("请先完全退出启动器和客户端，否则会和它抢带宽、也可能互相写同一批文件。")
        if not assume_yes:
            try:
                if input("仍然继续？[y/N] ").strip().lower() not in ("y", "yes"):
                    return False
            except (EOFError, KeyboardInterrupt):
                return False

    ips = system_resolve(BIN_HOST)
    for ip in gather_candidates(BIN_HOST, None, int(st["threads"])):
        if ip not in ips:
            ips.append(ip)
    if not ips:
        err("解析不到 %s。" % BIN_HOST)
        return False
    r = _fetch_from_any(BIN_HOST, "/eveclient_TQ.json", ips, 16384, 12.0, 8.0)
    if not r:
        err("读不到 EVE 版本信息。")
        return False
    try:
        build = str(json.loads(r.body.decode("utf-8", "replace"))["build"])
    except Exception:
        err("版本信息格式异常。")
        return False
    info("  当前 build %s" % build)

    text = fetch_res_index(st, build, ips)
    if not text:
        err("取不到资源索引。")
        return False

    step("对比本地缓存…")
    have = scan_local_resfiles(resroot)
    total_local = sum(len(v) for v in have.values())
    missing = []
    total_entries = 0
    for ln in text.splitlines():
        if not ln.startswith("res:"):
            continue
        f = ln.split(",")
        if len(f) < 4 or "/" not in f[1]:
            continue
        cdn = f[1].strip()
        sub, _sep, name = cdn.partition("/")
        total_entries += 1
        if name in have.get(sub.lower(), ()):
            continue
        try:
            size = int(f[3])
        except ValueError:
            continue
        missing.append((cdn, f[2].strip(), size))
    need_bytes = sum(m[2] for m in missing)
    info("  索引里 %d 个资源文件，本地已有 %d 个文件" % (total_entries, total_local))
    if not missing:
        ok("本地缓存已经是齐的，没有需要预下载的文件。")
        return True
    info("  缺少 %d 个，合计 %s" % (len(missing), human_size(need_bytes)))

    threads = max(1, min(32, int(st.get("predownload_threads", 8))))
    nodes = pick_download_nodes(RES_HOST, "/" + missing[0][0], st, want=4)
    if not nodes:
        nodes = system_resolve(RES_HOST)
    if not nodes:
        err("解析不到 %s。" % RES_HOST)
        return False
    info("  用这几个节点：%s" % "、".join(nodes))
    info("  %d 条并发连接分散到 %d 个节点（顺便绕开单 IP 限速）" % (threads, len(nodes)))
    if not assume_yes:
        try:
            if input("开始下载？[y/N] ").strip().lower() not in ("y", "yes"):
                info("已取消，什么都没做。")
                return False
        except (EOFError, KeyboardInterrupt):
            return False

    # 大文件单独走：一个线程负责一个文件的并发，碰上"只缺一个大文件"就退化成单连接。
    # 而这个 CDN 不支持 Range，一个文件切不开，所以大文件只能挑最快的节点老实下。
    big_min = int(st.get("range_min_size", 4194304))
    big = [m for m in missing if m[2] >= big_min]
    small = [m for m in missing if m[2] < big_min]
    if big:
        info("")
        step("先下 %d 个大文件（单个文件切不开，用最快的节点）…" % len(big))
        big_ok = 0
        for cdn, md5, size in big:
            sub, _s, name = cdn.partition("/")
            info("  %s  %s" % (cdn[:44], human_size(size)))
            t0 = time.perf_counter()
            got = single_download(RES_HOST, nodes[0], "/" + cdn, size, md5,
                                  os.path.join(resroot, sub, name), st,
                                  on_progress=_bar_progress("    "))
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()
            if got:
                big_ok += 1
                ok("    完成，%s" % human_speed(size / max(0.001, time.perf_counter() - t0)))
            else:
                err("    没下成功，重跑会自动补")
        info("  大文件完成 %d/%d" % (big_ok, len(big)))
        if not small:
            info("")
            info("现在打开 EVE 启动器，它会发现这些文件已经在本地，直接跳过下载。")
            return big_ok == len(big)
        info("")
        step("剩下 %d 个小文件用 %d 条连接并发下…" % (len(small), threads))

    missing = small
    need_bytes = sum(m[2] for m in missing)
    lock = threading.Lock()
    state = {"done": 0, "bytes": 0, "failed": 0, "stop": False}
    queue = list(missing)
    queue.reverse()

    def worker(widx=0):
        sess = PinnedSession(nodes[widx % len(nodes)], RES_HOST,
                             timeout=float(st.get("predownload_timeout", 12.0)),
                             recycle=int(st.get("predownload_recycle", 64)))
        try:
            while True:
                with lock:
                    if state["stop"] or not queue:
                        return
                    cdn, md5, size = queue.pop()
                status, data = sess.get("/" + cdn)
                good = (status == 200 and len(data) == size
                        and hashlib.md5(data).hexdigest() == md5)
                if good:
                    sub, _s, name = cdn.partition("/")
                    dst_dir = os.path.join(resroot, sub)
                    dst = os.path.join(dst_dir, name)
                    try:
                        os.makedirs(dst_dir, exist_ok=True)
                        tmp = dst + ".eveaccel.tmp"
                        with open(tmp, "wb") as fh:
                            fh.write(data)
                        os.replace(tmp, dst)      # 原子落盘，绝不会写出半个文件
                    except Exception:
                        good = False
                with lock:
                    if good:
                        state["done"] += 1
                        state["bytes"] += size
                    else:
                        state["failed"] += 1
        finally:
            sess.close()

    workers = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(threads)]
    t0 = time.perf_counter()
    for w in workers:
        w.start()
    info("")
    try:
        tty = False
        try:
            tty = bool(sys.stdout.isatty())
        except Exception:
            pass
        last_line = 0.0
        while any(w.is_alive() for w in workers):
            time.sleep(0.5)
            with lock:
                done, nbytes, failed = state["done"], state["bytes"], state["failed"]
            el = time.perf_counter() - t0
            spd = nbytes / el if el > 0.5 else 0
            eta = ((need_bytes - nbytes) / spd) if spd > 1000 else 0
            line = ("  %d/%d 个  %s/%s  %s  剩余约 %s  失败 %d"
                    % (done, len(missing), human_size(nbytes), human_size(need_bytes),
                       human_speed(spd), _fmt_eta(eta), failed))
            if tty:
                sys.stdout.write("\r" + line + "    ")
                sys.stdout.flush()
            elif el - last_line >= 5.0:
                last_line = el
                print(line, flush=True)
    except KeyboardInterrupt:
        with lock:
            state["stop"] = True
        info("")
        warn("正在停止（已下好的文件都留着，下次接着下）…")
        for w in workers:
            w.join(timeout=10)
    for w in workers:
        w.join(timeout=15)
    info("")

    el = max(0.001, time.perf_counter() - t0)
    ok("预下载结束：成功 %d 个 / %s，平均 %s，用时 %s"
       % (state["done"], human_size(state["bytes"]),
          human_speed(state["bytes"] / el), _fmt_eta(el)))
    if state["failed"]:
        warn("有 %d 个文件没下成功（校验不过或连接失败），再跑一次会自动补。" % state["failed"])
    info("")
    info("现在打开 EVE 启动器，它会发现这些文件已经在本地，直接跳过下载。")
    return True


def _fmt_eta(sec):
    sec = int(max(0, sec))
    if sec >= 3600:
        return "%d 小时 %d 分" % (sec // 3600, (sec % 3600) // 60)
    if sec >= 60:
        return "%d 分 %d 秒" % (sec // 60, sec % 60)
    return "%d 秒" % sec


def do_restore():
    text = read_hosts_text()
    if not has_block(text):
        info("hosts 中没有加速段，无需还原。")
        return True
    backup_hosts(text)
    okw, msg = write_hosts_text(strip_block(text))
    if not okw:
        err("还原失败：%s" % msg)
        return False
    flush_dns()
    ok("已移除加速段并刷新 DNS 缓存，hosts 回到修改前状态。")
    return True


def do_status():
    text = read_hosts_text()
    info("")
    info("hosts 路径：%s" % HOSTS_PATH)
    info("%s权限：%s" % (admin_word(), "是" if is_admin() else "否"))
    cache = find_shared_cache()
    info("EVE 共享缓存：%s" % (cache if cache else "未找到（预下载功能需要它）"))
    if has_block(text):
        ok("当前已启用加速，条目如下：")
        show = False
        for ln in text.splitlines():
            s = ln.strip()
            if s.startswith("# ==== EVE-ACCEL BEGIN"):
                show = True
                continue
            if s.startswith("# ==== EVE-ACCEL END"):
                show = False
                continue
            if show and s and not s.startswith("#"):
                info("    " + s)
    else:
        info("当前未启用加速（hosts 中没有本程序的段落）。")
    if os.path.exists(BACKUP_FILE):
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(BACKUP_FILE)))
        info("hosts 备份（只留一份，每次修改前覆盖）：%s  更新于 %s" % (BACKUP_FILE, ts))
    info("")


def menu(cfg):
    while True:
        info("")
        info("%s请选择操作：%s" % (C_BOLD, C_RESET))
        info("  [1] 一键加速     检测 → 验证 → 测速 → 写 hosts → 复检（推荐）")
        info("  [2] 只检测       只看哪个节点最快，不动 hosts")
        info("  [3] 还原 hosts   删除本程序写入的加速段")
        info("  [4] 查看状态     当前 hosts 里的加速条目 / 备份")
        info("  [5] 打开配置     编辑要加速的域名列表")
        info("  [6] 掉速诊断     下载会掉速时用：判断是按连接限速还是线路拥堵")
        info("  [7] 并发预下载   多线程把缺的资源文件下进 EVE 缓存，启动器直接跳过")
        info("  [0] 退出")
        try:
            choice = input("\n输入序号后回车 > ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "1":
            if not is_admin():
                if not need_admin_or_relaunch("--apply"):
                    return
            results = scan(cfg)
            print_summary(results)
            do_apply(cfg, results)
        elif choice == "2":
            results = scan(cfg)
            print_summary(results)
        elif choice == "3":
            if not is_admin():
                if not need_admin_or_relaunch("--restore"):
                    return
            do_restore()
        elif choice == "4":
            do_status()
        elif choice == "5":
            p = config_path()
            if not os.path.exists(p):
                load_config()
            try:
                if IS_WIN:
                    os.startfile(p)
                elif IS_MAC:
                    subprocess.run(["open", p], timeout=15)
                else:
                    subprocess.run(["xdg-open", p], timeout=15)
            except Exception as e:
                err("打开失败：%s（路径 %s）" % (e, p))
        elif choice == "6":
            do_diagnose(cfg)
        elif choice == "7":
            do_predownload(cfg)
        elif choice == "0":
            return
        else:
            warn("没有这个选项。")


def main():
    setup_console()
    ap = argparse.ArgumentParser(description=APP_NAME, add_help=True)
    ap.add_argument("--apply", action="store_true", help="直接执行一键加速并写入 hosts")
    ap.add_argument("--test", action="store_true", help="只检测，不修改 hosts")
    ap.add_argument("--restore", action="store_true", help="还原 hosts（移除加速段）")
    ap.add_argument("--status", action="store_true", help="查看当前状态")
    ap.add_argument("--diagnose", action="store_true", help="掉速诊断")
    ap.add_argument("--predownload", action="store_true", help="并发预下载资源文件")
    ap.add_argument("--yes", action="store_true", help="预下载时不再询问，直接开始")
    ap.add_argument("--no-pause", action="store_true", help="结束后不等待按键")
    args, _unknown = ap.parse_known_args()

    banner()
    migrate_backups()
    interactive = not (args.apply or args.test or args.restore or args.status
                       or args.diagnose or args.predownload)
    code = 0
    try:
        if args.status:
            do_status()
        elif args.diagnose:
            do_diagnose(load_config())
        elif args.predownload:
            code = 0 if do_predownload(load_config(), assume_yes=args.yes) else 1
        elif args.restore:
            if is_admin():
                code = 0 if do_restore() else 1
            else:
                need_admin_or_relaunch("--restore")
        elif args.test:
            cfg = load_config()
            print_summary(scan(cfg))
        elif args.apply:
            cfg = load_config()
            if is_admin():
                results = scan(cfg)
                print_summary(results)
                code = 0 if do_apply(cfg, results) else 1
            else:
                need_admin_or_relaunch("--apply")
        else:
            cfg = load_config()
            do_status()
            menu(cfg)
    except KeyboardInterrupt:
        info("")
        warn("已取消。")
        code = 130
    except Exception as e:
        err("发生未处理的异常：%s: %s" % (type(e).__name__, e))
        import traceback
        dim(traceback.format_exc())
        code = 1

    if not args.no_pause and (interactive or args.apply or args.restore):
        try:
            input("\n按回车键退出…")
        except Exception:
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())
