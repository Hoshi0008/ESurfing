#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esurfing.py —— 广东天翼校园网 (cdcportal / gd-portal) Linux/OpenWrt 认证客户端

纯 Python3 标准库实现，无需 libcurl / openssl（AES 在纯 Python 里完成）。

协议来自对官方客户端 D:\\Program Files (x86)\\Chinatelecom_GDPortal 的逆向：
  * 固定 HTTP 头：User-Agent / Algo-ID / Client-ID / CDC-SchoolId / CDC-Domain /
    CDC-Area / CDC-Checksum(md5 of body)
  * 报文 = XML，经算法加密后以大写 hex 作为 POST body
  * 算法来自服务端下发的 ZSM 模块（"001" + Pascal 字符串，其中一个是 Algo-ID UUID），
    客户端内置 Algo-ID -> key/iv 表；不支持的 Algo-ID 要丢弃并重新要一个
  * 流程：ticket(取 ZSM) -> ticket(取 <ticket>) -> auth(<keep-retry>) ->
          keep(<interval>) -> term

用法：
    sudo ./esurfing.py -u 账号 -p 密码 -i eno1
    sudo ./esurfing.py -u 账号 -p 密码 -i eno1 --test-ticket     # 只验证算法
    sudo ./esurfing.py -i eno1 --logout                          # 已登录时下线
"""
import argparse
import binascii
import hashlib
import http.client
import ipaddress
import os
import random
import re
import subprocess
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# 通道参数（官方客户端按渠道区分 UA / ostag；本脚本默认冒充 Windows）
# ---------------------------------------------------------------------------
CHANNELS = {
    "windows": ("CCTP/WinSVR5/1068", "Windows 11"),
    "linux": ("CCTP/Linux64/1003", "Linux"),
    "android": ("CCTP/android11_64/2104", "Android 14"),
    "macos": ("CCTP/macdy/5019", "macOS,14.4"),
    "ios": ("CCTP/iOSdy/4023", "iOS 17.0"),
}
ACCEPT = "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
# 校区相关的参数（认证服务器 / 端口 / 地址池 / 准入网）统一放 esurfing.conf，
# 仓库里那份是占位符；这些常量只是没有配置文件时的兜底。
DEFAULT_SERVERS = []
PORT = 7001
CAMPUS_NET = ""
EIA_NET = ""
EIA_PORTAL = ""
DETECT_URLS = ["http://connect.rom.miui.com/generate_204",
               "http://www.baidu.com/",
               "http://www.qq.com/"]

# ---------------------------------------------------------------------------
# double AES-128-CBC：两层 AES-128，IV 前缀 + 零填充，输出大写 hex
# （对应官方 PortalServer 里的 sub_1FA0 密钥扩展 / sub_27F0 分组加密 /
#   sub_3444 双层加密 / sub_34D8 双层解密）
# ---------------------------------------------------------------------------
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(x):
    return ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _key_expand(key):
    """官方实现：先转置 16 字节密钥，再 10 轮 S 盒/Rcon 混合，得到 176 字节轮密钥"""
    sk = [0] * 176
    sk[0], sk[1], sk[2], sk[3] = key[0], key[4], key[8], key[12]
    sk[4], sk[5], sk[6], sk[7] = key[1], key[5], key[9], key[13]
    sk[8], sk[9], sk[10], sk[11] = key[2], key[6], key[10], key[14]
    sk[12], sk[13], sk[14], sk[15] = key[3], key[7], key[11], key[15]
    for rnd in range(10):
        v = rnd * 16 + 15
        v4 = SBOX[sk[v - 8]] ^ RCON[rnd]
        v5 = SBOX[sk[v - 4]] ^ sk[v - 11]
        v6 = sk[v - 15]
        v7 = SBOX[sk[v - 12]] ^ sk[v - 3]
        v8 = sk[v - 10]
        v9 = SBOX[sk[v]]
        sk[v + 5] = v5
        v10 = sk[v - 7]
        v11 = v5 ^ v8
        v12 = sk[v - 2]
        v13 = v4 ^ v6
        v14 = sk[v - 6]
        sk[v + 13] = v7
        v15 = v7 ^ v12
        v16 = sk[v - 9]
        v17 = v9 ^ v10
        sk[v + 9] = v17
        v18 = v17 ^ v14
        v19 = sk[v - 14]
        sk[v + 6] = v11
        v20 = v11 ^ v16
        v21 = sk[v - 1]
        sk[v + 1] = v13
        v22 = v13 ^ v19
        v23 = sk[v - 5]
        sk[v + 14] = v15
        v24 = v15 ^ v21
        v25 = sk[v - 8]
        sk[v + 10] = v18
        v26 = v18 ^ v23
        v27 = sk[v - 13]
        sk[v + 7] = v20
        v28 = v20 ^ v25
        v29 = sk[v]
        sk[v + 2] = v22
        v30 = v22 ^ v27
        v31 = sk[v - 4]
        sk[v + 15] = v24
        v32 = v24 ^ v29
        v33 = sk[v - 12]
        sk[v + 11] = v26
        sk[v + 3] = v30
        sk[v + 8] = v28
        sk[v + 12] = v26 ^ v31
        sk[v + 4] = v30 ^ v33
        sk[v + 16] = v32
    return sk


def _block_encrypt(sk, block):
    s = [block[c * 4 + r] for r in range(4) for c in range(4)]
    for i in range(16):
        s[i] ^= sk[i]
    for rnd in range(1, 11):
        s = [SBOX[x] for x in s]
        s = [s[r * 4 + ((c + r) & 3)] for r in range(4) for c in range(4)]
        if rnd < 10:
            for c in range(4):
                a0, a1, a2, a3 = s[c], s[4 + c], s[8 + c], s[12 + c]
                s[c] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
                s[4 + c] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
                s[8 + c] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
                s[12 + c] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
        for i in range(16):
            s[i] ^= sk[16 * rnd + i]
    return bytes(s[r * 4 + c] for c in range(4) for r in range(4))


def _block_decrypt(sk, block):
    s = [block[c * 4 + r] for r in range(4) for c in range(4)]
    for i in range(16):
        s[i] ^= sk[160 + i]
    for rnd in range(9, 0, -1):
        s = [s[r * 4 + ((c - r + 4) & 3)] for r in range(4) for c in range(4)]
        s = [INV_SBOX[x] for x in s]
        for i in range(16):
            s[i] ^= sk[16 * rnd + i]
        for c in range(4):
            a0, a1, a2, a3 = s[c], s[4 + c], s[8 + c], s[12 + c]
            s[c] = _gmul(0x0E, a0) ^ _gmul(0x0B, a1) ^ _gmul(0x0D, a2) ^ _gmul(0x09, a3)
            s[4 + c] = _gmul(0x09, a0) ^ _gmul(0x0E, a1) ^ _gmul(0x0B, a2) ^ _gmul(0x0D, a3)
            s[8 + c] = _gmul(0x0D, a0) ^ _gmul(0x09, a1) ^ _gmul(0x0E, a2) ^ _gmul(0x0B, a3)
            s[12 + c] = _gmul(0x0B, a0) ^ _gmul(0x0D, a1) ^ _gmul(0x09, a2) ^ _gmul(0x0E, a3)
    s = [s[r * 4 + ((c - r + 4) & 3)] for r in range(4) for c in range(4)]
    s = [INV_SBOX[x] for x in s]
    for i in range(16):
        s[i] ^= sk[i]
    return bytes(s[r * 4 + c] for c in range(4) for r in range(4))


class DoubleAesCbc(object):
    kind = "aes_double_cbc"

    def __init__(self, key, iv):
        if len(key) != 32 or len(iv) != 16:
            raise ValueError("double AES-128-CBC 需要 32 字节 key / 16 字节 iv")
        self.iv = bytes(iv)
        self.sk1 = _key_expand(bytes(key[0:16]))
        self.sk2 = _key_expand(bytes(key[16:32]))

    def _layer_enc(self, sk, data):
        total = (len(data) + 15) & ~15
        if total == 0:
            total = 16
        buf = bytearray(total + 16)
        buf[16:16 + len(data)] = data
        buf[0:16] = self.iv
        prev = self.iv
        for off in range(0, total, 16):
            ct = _block_encrypt(sk, bytes(x ^ y for x, y in zip(buf[16 + off:16 + off + 16], prev)))
            buf[16 + off:16 + off + 16] = ct
            prev = ct
        out = bytearray(total + 16)
        out[0:16] = self.iv
        out[16:] = buf[16:]
        return bytes(out)

    def _layer_dec(self, sk, data):
        if len(data) % 16 or len(data) < 32:
            raise ValueError("密文长度非法: %d" % len(data))
        total = len(data) - 16
        out = bytearray(total)
        prev = data[0:16]
        for off in range(0, total, 16):
            ct = data[16 + off:16 + off + 16]
            dec = _block_decrypt(sk, ct)
            out[off:off + 16] = bytes(x ^ y for x, y in zip(dec, prev))
            prev = ct
        return bytes(out)

    def encrypt(self, data):
        return binascii.hexlify(self._layer_enc(self.sk2, self._layer_enc(self.sk1, data))).decode().upper()

    def decrypt(self, hextext):
        raw = binascii.unhexlify(re.sub(r"\s+", "", hextext))
        pt = self._layer_dec(self.sk1, self._layer_dec(self.sk2, raw))
        return pt.rstrip(b"\x00")


# --------------------------- Algo-ID -> key/iv -----------------------------
# 仅收录官方客户端在广东两台 BRAS 上会下发、且我们已还原的算法（double AES-128-CBC）
ALGOS = {}


def _load_algos():
    from esurfing_algos import ALGOS as GEN, BAD_ALGOS
    ALGOS.update(GEN)
    return BAD_ALGOS


try:
    BAD_ALGOS = _load_algos()
except Exception:                                    # 允许单独运行做自检
    BAD_ALGOS = set()
    ALGOS = {
        "6067E3B6-3AB5-45AE-8CEC-E8DACB3C76DE": (
            "aes_double_cbc",
            bytes([0x57, 0x5D, 0x46, 0x41, 0x24, 0x5C, 0x5B, 0x4A, 0x51, 0x70, 0x7C, 0x78, 0x7B, 0x5C, 0x6F, 0x4C,
                   0x52, 0x4E, 0x79, 0x41, 0x3E, 0x26, 0x2F, 0x29, 0x5F, 0x5B, 0x47, 0x4E, 0x6A, 0x3E, 0x3B, 0x49]),
            bytes([0x57, 0x7B, 0x61, 0x63, 0x67, 0x62, 0x6F, 0x2D, 0x7D, 0x70, 0x3A, 0x71, 0x2F, 0x4B, 0x49, 0x48]),
        ),
    }

CIPHERS = {"aes_double_cbc": DoubleAesCbc}


def make_cipher(algo_id):
    entry = ALGOS.get(algo_id)
    if not entry:
        return None
    kind, key, iv = entry
    cls = CIPHERS.get(kind)
    if cls is None:
        return None
    return cls(key, iv)


# ---------------------------------------------------------------------------
def iface_mac(iface):
    with open("/sys/class/net/%s/address" % iface) as f:
        return f.read().strip()


def iface_ip(iface):
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show", "dev", iface],
                                      stderr=subprocess.DEVNULL).decode()
    except Exception:
        return None
    m = re.search(r"inet ([0-9.]+)/", out)
    return m.group(1) if m else None


def default_iface():
    try:
        out = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], stderr=subprocess.DEVNULL).decode()
        m = re.search(r"dev (\S+)", out)
        return m.group(1) if m else "eth0"
    except Exception:
        return "eth0"


def default_gateway():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], stderr=subprocess.DEVNULL).decode()
        m = re.search(r"default via ([0-9.]+)", out)
        return m.group(1) if m else ""
    except Exception:
        return ""


class PortalError(Exception):
    def __init__(self, msg, code=None, sub=None):
        super().__init__(msg)
        self.code = code
        self.sub = sub


class Portal(object):
    def __init__(self, ip, mac, channel="windows", schoolid="", domain="", area="",
                 source_ip=None, timeout=10, verbose=False):
        self.ip = ip
        self.mac = mac
        self.ua, self.ostag = CHANNELS[channel]
        self.schoolid = schoolid
        self.domain = domain
        self.area = area
        self.source_ip = source_ip or ip
        self.timeout = timeout
        self.verbose = verbose
        self.refresh_identity()
        self.algo_id = ZERO_UUID
        self.cipher = None
        self.ticket = ""
        self.last_redirect = ""
        self.server = DEFAULT_SERVERS[0] if DEFAULT_SERVERS else ""
        self.ticket_url = self.auth_url = self.keep_url = self.term_url = ""

    # ---- identity ----
    def refresh_identity(self):
        self.host_name = "%010x" % random.getrandbits(40)
        self.client_id = str(uuid.uuid4())

    def log(self, *a):
        if self.verbose:
            print("[*]", *a)

    # ---- http ----
    def _request(self, method, url, body=None, headers=None):
        m = re.match(r"http://([^/:]+)(?::(\d+))?(/.*)$", url)
        if not m:
            raise PortalError("URL 非法: %s" % url)
        conn = http.client.HTTPConnection(m.group(1), int(m.group(2) or 80),
                                          timeout=self.timeout,
                                          source_address=(self.source_ip, 0) if self.source_ip else None)
        try:
            conn.request(method, m.group(3), body=body, headers=headers or {})
            r = conn.getresponse()
            raw = r.read()
            hd = {k.lower(): v for k, v in r.getheaders()}
            return r.status, hd, raw
        finally:
            conn.close()

    def post(self, url, body):
        data = body.encode() if isinstance(body, str) else body
        headers = {
            "CDC-Checksum": hashlib.md5(data).hexdigest(),
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": self.ua,
            "Accept": ACCEPT,
            "Client-ID": self.client_id,
            "Algo-ID": self.algo_id,
            "CDC-SchoolId": self.schoolid,
            "CDC-Domain": self.domain,
            "CDC-Area": self.area,
        }
        st, hd, raw = self._request("POST", url, data, headers)
        self.log("POST %s -> %s Error-Code=%s len=%d" % (url, st, hd.get("error-code"), len(raw)))
        return st, hd, raw

    def get(self, url):
        st, hd, raw = self._request("GET", url, None, {
            "User-Agent": self.ua, "Accept": ACCEPT})
        self.log("GET %s -> %s" % (url, st))
        return st, hd, raw

    # ---- 门户发现 ----
    def discover(self):
        """返回 (portal_url, wlanacip)；顺手把 wlanuserip 校正为本机 IP

        已认证的网络上探测不会跳转，此时退化为直接访问两台认证服务器的
        index.cgi，从它返回的 <config> 块里取 wlanacip。
        """
        for url in DETECT_URLS:
            try:
                st, hd, _ = self.get(url)
            except Exception as e:
                self.log("探测 %s 失败: %r" % (url, e))
                continue
            loc = hd.get("location", "")
            if loc.startswith("http"):
                self.last_redirect = loc
                if "wlanuserip" in loc:
                    self.log("发现跳转: %s" % loc)
                    m = re.search(r"wlanuserip=([0-9.]+)", loc)
                    if m:
                        self.ip = m.group(1)
                        self.source_ip = self.ip
                    m = re.search(r"wlanacip=([0-9.]+)", loc)
                    return loc, (m.group(1) if m else "")
        # 兜底：直接问认证服务器
        for srv in DEFAULT_SERVERS:
            try:
                st, hd, raw = self.get("http://%s:%d/index.cgi?wlanuserip=%s" % (srv, PORT, self.ip))
                txt = raw.decode("utf-8", "replace")
                m = re.search(r"wlanacip=([0-9.]+)", txt)
                if m:
                    self.log("从 index.cgi 兜底取到 wlanacip=%s" % m.group(1))
                    return "http://%s:%d/index.cgi?wlanuserip=%s&wlanacip=%s" % (
                        srv, PORT, self.ip, m.group(1)), m.group(1)
            except Exception as e:
                self.log("兜底探测 %s 失败: %r" % (srv, e))
        return None, ""

    def configure(self, server, ac_ip, index_url=None, portal_html=None):
        self.server = server or self.server
        if "://" in self.server:
            self.server = re.sub(r"^https?://", "", self.server)
        base = "http://%s:%d" % (self.server, PORT)
        self.ticket_url = "%s/ticket.cgi?wlanuserip=%s&wlanacip=%s" % (base, self.ip, ac_ip)
        self.auth_url = "%s/auth.cgi" % base
        self.keep_url = "%s/keep.cgi" % base
        self.term_url = "%s/term.cgi" % base

        html = portal_html
        if html is None:
            try:
                _, _, raw = self.get(index_url or
                                     "%s/index.cgi?wlanuserip=%s&wlanacip=%s" % (base, self.ip, ac_ip))
                html = raw.decode("utf-8", "replace")
            except Exception as e:
                self.log("取门户页面失败: %r" % e)
                html = ""
        if "config.campus.js.chinatelecom.com" in html:
            start = "<!--//config.campus.js.chinatelecom.com"
            end = "//config.campus.js.chinatelecom.com-->"
            if start in html and end in html:
                conf = html.split(start, 1)[1].split(end, 1)[0]
                m = re.search(r"<ticket-url><!\[CDATA\[(.*?)\]\]></ticket-url>", conf, re.S)
                if m:
                    self.ticket_url = m.group(1).strip()
                    self.log("门户给的 ticket-url: %s" % self.ticket_url)

    # ---- ZSM / 算法 ----
    @staticmethod
    def parse_zsm(data):
        """返回 (str1, algo_id)"""
        if data[:3] != b"001":
            return None, None
        off, strs = 3, []
        for _ in range(3):
            if off >= len(data):
                break
            n = data[off]
            off += 1
            strs.append(data[off:off + n])
            off += n
        uu = re.compile(rb"^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$")
        for s in reversed(strs):
            if uu.match(s):
                return (strs[0].decode("latin-1"), s.decode().upper())
        return None, None

    def fetch_algo(self, tries=40):
        """反复要 ZSM，直到拿到「服务端会认、我们又实现了」的 Algo-ID"""
        for i in range(tries):
            try:
                st, hd, raw = self.post(self.ticket_url, self.algo_id)
            except Exception as e:
                raise PortalError("请求 ZSM 失败: %r" % e)
            if raw[:3] == b"001":
                _, algo = self.parse_zsm(raw)
                if algo and algo not in BAD_ALGOS and algo in ALGOS:
                    self.algo_id = algo
                    self.cipher = make_cipher(algo)
                    self.log("采用 Algo-ID %s (第 %d 次)" % (algo, i + 1))
                    return algo
                self.log("丢弃 ZSM Algo-ID=%s%s" % (
                    algo, "（黑名单）" if algo in BAD_ALGOS else "（未实现）"))
            else:
                self.log("ZSM 响应异常 Error-Code=%s len=%d" % (hd.get("error-code"), len(raw)))
            self.refresh_identity()
            time.sleep(0.3)
        raise PortalError("连续 %d 次都没拿到可用算法" % tries)

    # ---- 报文 ----
    def _now(self):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def xml_ticket(self, gwip=""):
        return ('<?xml version="1.0" encoding="utf-8"?>\n<request>\n'
                "    <user-agent>%s</user-agent>\n"
                "    <client-id>%s</client-id>\n"
                "    <local-time>%s</local-time>\n"
                "    <host-name>%s</host-name>\n"
                "    <ipv4>%s</ipv4>\n"
                "    <ipv6></ipv6>\n"
                "    <mac>%s</mac>\n"
                "    <ostag>%s</ostag>\n"
                "    <gwip>%s</gwip>\n"
                "</request>\n") % (self.ua, self.client_id, self._now(), self.host_name,
                                   self.ip, self.mac, self.ostag, gwip)

    def xml_login(self, userid, passwd):
        return ('<?xml version="1.0" encoding="utf-8"?>\n<request>\n'
                "    <user-agent>%s</user-agent>\n"
                "    <client-id>%s</client-id>\n"
                "    <ticket>%s</ticket>\n"
                "    <local-time>%s</local-time>\n"
                "    <userid>%s</userid>\n"
                "    <passwd>%s</passwd>\n"
                "</request>\n") % (self.ua, self.client_id, self.ticket, self._now(),
                                   userid, passwd)

    def xml_keep(self):
        return ('<?xml version="1.0" encoding="utf-8"?>\n<request>\n'
                "    <user-agent>%s</user-agent>\n"
                "    <client-id>%s</client-id>\n"
                "    <local-time>%s</local-time>\n"
                "    <host-name>%s</host-name>\n"
                "    <ipv4>%s</ipv4>\n"
                "    <ticket>%s</ticket>\n"
                "    <ipv6></ipv6>\n"
                "    <mac>%s</mac>\n"
                "    <ostag>%s</ostag>\n"
                "</request>\n") % (self.ua, self.client_id, self._now(), self.host_name,
                                   self.ip, self.ticket, self.mac, self.ostag)

    # ---- 认证动作 ----
    def get_ticket(self, gwip=""):
        body = self.cipher.encrypt(self.xml_ticket(gwip).encode())
        for _ in range(3):
            st, hd, raw = self.post(self.ticket_url, body)
            code = hd.get("error-code")
            if code == "200" and raw[:3] == b"001":
                _, algo = self.parse_zsm(raw)
                self.log("服务端要求换算法: %s" % algo)
                self.algo_id = algo
                self.cipher = make_cipher(algo)
                if self.cipher is None:
                    raise PortalError("服务端要求的算法 %s 尚未实现" % algo)
                body = self.cipher.encrypt(self.xml_ticket(gwip).encode())
                continue
            if not raw:
                raise PortalError("取 ticket 失败 (Error-Code=%s)" % code, code=code,
                                  sub=hd.get("sub-error"))
            pt = self.cipher.decrypt(raw.decode())
            self.log("ticket 响应: %r" % pt)
            m = re.search(rb"<ticket>(.*?)</ticket>", pt, re.S)
            if not m:
                raise PortalError("ticket 响应异常: %r" % pt[:200], code=code)
            self.ticket = m.group(1).decode().strip()
            return self.ticket
        raise PortalError("取 ticket 重试次数超限")

    def login(self, userid, passwd):
        body = self.cipher.encrypt(self.xml_login(userid, passwd).encode())
        st, hd, raw = self.post(self.auth_url, body)
        code = hd.get("error-code")
        if not raw:
            return False, code, hd.get("sub-error"), b""
        pt = self.cipher.decrypt(raw.decode())
        self.log("login 响应: %r" % pt)
        txt = pt.decode("utf-8", "replace")
        # 服务端会给出真正该用的 keep / term 地址（keep 通常在另一台 BRAS: .142）
        for tag, attr in (("keep-url", "keep_url"), ("term-url", "term_url")):
            m = re.search(r"<%s><!\[CDATA\[(.*?)\]\]></%s>" % (tag, tag), txt, re.S)
            if m:
                setattr(self, attr, m.group(1).strip())
                self.log("%s = %s" % (tag, getattr(self, attr)))
        return (b"<keep-retry>" in pt), code, hd.get("sub-error"), pt

    def keep(self):
        body = self.cipher.encrypt(self.xml_keep().encode())
        st, hd, raw = self.post(self.keep_url, body)
        if not raw:
            return None, hd.get("error-code"), b""
        pt = self.cipher.decrypt(raw.decode())
        m = re.search(rb"<interval>(.*?)</interval>", pt)
        return (int(m.group(1)) if m else None), hd.get("error-code"), pt

    def term(self):
        body = self.cipher.encrypt(self.xml_keep().encode())
        st, hd, raw = self.post(self.term_url, body)
        return hd.get("error-code")


# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
CONF_PATHS = ["/etc/esurfing.conf",
              os.path.expanduser("~/.config/esurfing.conf"),
              os.path.join(_HERE, "esurfing.conf")]


def load_conf():
    for p in CONF_PATHS:
        try:
            with open(p, encoding="utf-8") as f:
                return dict(line.strip().split("=", 1) for line in f
                            if "=" in line and not line.strip().startswith("#")), p
        except Exception:
            continue
    return {}, None


ACIP_CACHE = "/run/esurfing.acip"


def cached_acip():
    for path in (ACIP_CACHE, "/tmp/esurfing.acip"):
        try:
            return open(path).read().strip()
        except Exception:
            continue
    return ""


def remember_acip(acip):
    for path in (ACIP_CACHE, "/tmp/esurfing.acip"):
        try:
            with open(path, "w") as f:
                f.write(acip + "\n")
            return
        except Exception:
            continue


def ip_in(net, ip):
    """ip 是否属于 net（任意一边不合法都返回 False）"""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net)
    except Exception:
        return False


def _valid_net(s):
    """合法 CIDR 才返回，否则返回空串（占位符 / 写错的网段都当没配）"""
    s = (s or "").strip()
    if not s:
        return ""
    try:
        ipaddress.ip_network(s, strict=False)
        return s
    except Exception:
        return ""


def _is_ipv4(s):
    try:
        ipaddress.IPv4Address((s or "").strip())
        return True
    except Exception:
        return False


def probe_online(ip=None, timeout=6):
    """能直接拿到外网页面（200 且不是门户跳转页）说明已经放行"""
    for host in ("www.baidu.com", "www.qq.com"):
        try:
            conn = http.client.HTTPConnection(host, 80, timeout=timeout,
                                              source_address=(ip, 0) if ip else None)
            conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0"})
            r = conn.getresponse()
            body = r.read(256)
            conn.close()
            if r.status == 200 and b"<html" in body.lower():
                return True
        except Exception:
            continue
    return False


def build_portal(a, ip, mac):
    return Portal(ip=ip, mac=mac, channel=a.channel, schoolid=a.schoolid,
                  domain=a.domain, area=a.area, source_ip=ip, verbose=a.verbose)


def authenticate(a, p, acip):
    """要算法 -> 取 ticket；返回 ticket"""
    servers = [a.server] if a.server else DEFAULT_SERVERS
    if not servers:
        raise PortalError("没有认证服务器：请在 esurfing.conf 里填 servers=，或用 --server 指定")
    err = None
    for srv in servers:
        try:
            p.configure(srv, acip)
            algo = p.fetch_algo()
            print("[+] 算法 %s（服务器 %s）" % (algo, p.server))
            return p.get_ticket(default_gateway())
        except Exception as e:
            err = e
            print("[!] 服务器 %s 失败: %s" % (srv, e))
    raise PortalError("所有认证服务器都失败: %s" % err)


def session_loop(a, p):
    """已登录后的心跳循环；会话掉了就返回，由外层重来"""
    interval = 60
    fail = 0
    while True:
        time.sleep(interval)
        try:
            iv, code, body = p.keep()
        except Exception as e:
            print("[!] 心跳异常: %r" % e)
            fail += 1
        else:
            if iv:
                interval = max(a.interval_min, iv)
            if code in (None, "0"):
                fail = 0
                print("[*] 心跳正常，下一页 %ss" % interval)
                continue
            fail += 1
            print("[!] 心跳 Error-Code=%s body=%r" % (code, body[:160]))
        if fail >= 3:
            print("[!] 会话已失效，重新认证")
            return


def main():
    global DEFAULT_SERVERS, PORT, CAMPUS_NET, EIA_NET, EIA_PORTAL
    conf, conf_path = load_conf()

    # 校区相关参数一律从配置来，仓库里的 esurfing.conf 是占位符
    if conf.get("servers"):
        raw = [s.strip() for s in conf["servers"].split(",") if s.strip()]
        DEFAULT_SERVERS = [s for s in raw if _is_ipv4(s)]
        if len(DEFAULT_SERVERS) != len(raw) or not DEFAULT_SERVERS:
            print("[!] 配置里的 servers 有占位符/非法 IP，已忽略；请填真实的认证服务器")
    if conf.get("port", "").strip().isdigit():
        PORT = int(conf["port"].strip())
    CAMPUS_NET = _valid_net(conf.get("campus_net", ""))
    EIA_NET = _valid_net(conf.get("eia_net", ""))
    EIA_PORTAL = conf.get("eia_portal", "").strip()
    if conf.get("campus_net", "").strip() and not CAMPUS_NET:
        print("[!] 配置里的 campus_net 不是合法网段，已忽略（占位符要换成真值）")
    if conf.get("eia_net", "").strip() and not EIA_NET:
        print("[!] 配置里的 eia_net 不是合法网段，已忽略（占位符要换成真值）")

    ap = argparse.ArgumentParser(description="广东天翼校园网认证客户端 (cdcportal)")
    ap.add_argument("-u", "--user", default=conf.get("user"))
    ap.add_argument("-p", "--passwd", default=conf.get("passwd"))
    ap.add_argument("-i", "--iface", default=conf.get("iface"))
    ap.add_argument("--ip", default=conf.get("ip"))
    ap.add_argument("--mac", default=conf.get("mac"))
    ap.add_argument("--channel", default=conf.get("channel", "windows"), choices=list(CHANNELS))
    ap.add_argument("--server", default=conf.get("server"), help="认证服务器 IP（默认用 conf 里的 servers）")
    ap.add_argument("--acip", default=conf.get("acip"))
    ap.add_argument("--schoolid", default=conf.get("schoolid", ""))
    ap.add_argument("--domain", default=conf.get("domain", ""))
    ap.add_argument("--area", default=conf.get("area", ""))
    ap.add_argument("--test-ticket", action="store_true", help="只验证算法/取 ticket")
    ap.add_argument("--logout", action="store_true")
    ap.add_argument("--once", action="store_true", help="认证一次就退出（不做守护循环）")
    ap.add_argument("--force", action="store_true", help="即使已在线也重新认证")
    ap.add_argument("--check-interval", type=int, default=60, help="在线状态复查间隔（秒）")
    ap.add_argument("--interval-min", type=int, default=20)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    if a.acip and not _is_ipv4(a.acip):
        print("[!] acip 不是合法 IP，已忽略：%s（占位符要换成真值）" % a.acip)
        a.acip = ""
    if a.server and not _is_ipv4(a.server):
        print("[!] --server 不是合法 IP，已忽略：%s" % a.server)
        a.server = ""

    acip = a.acip or cached_acip()
    while True:
        iface = a.iface or default_iface()
        ip = a.ip or iface_ip(iface)
        mac = a.mac or (iface_mac(iface) if iface else None)
        if not ip:
            print("[!] %s 上没有 IP（没插网线 / 没跑 DHCP？）30s 后重试" % iface)
            if a.once or a.test_ticket or a.logout:
                return 1
            time.sleep(30)
            continue
        if not mac:
            print("[!] 取不到 %s 的 MAC" % iface)
            return 1

        # 只在配置好的天翼地址池里认证；落到学校准入网就提示去登记
        if not a.force and CAMPUS_NET and not ip_in(CAMPUS_NET, ip):
            print("[!] %s 上的地址 %s 不在 %s，不是天翼的地址池" % (iface, ip, CAMPUS_NET))
            if EIA_NET and ip_in(EIA_NET, ip):
                print("    这是学校自己的准入网，说明本机 MAC 还没登记。")
                print("    用浏览器打开 %s（必须 http://，别用 https）"
                      % (EIA_PORTAL or "准入网网关"))
                print("    用 学号 + 密码 登录一次，重连后地址就会进 %s。" % CAMPUS_NET)
            print("    （确认无误仍要强制认证可加 --force）")
            if a.once or a.test_ticket or a.logout:
                return 1
            time.sleep(30)
            continue

        if not a.force and not (a.test_ticket or a.logout) and probe_online(ip):
            print("[i] 网络已在线（%s），%ss 后复查" % (ip, a.check_interval))
            if a.once:
                return 0
            time.sleep(a.check_interval)
            continue

        p = build_portal(a, ip, mac)
        print("[i] %s  ip=%s  mac=%s  UA=%s" % (iface, ip, mac, p.ua))
        try:
            portal_url, found = p.discover()
            if found:
                acip = found
                remember_acip(found)
            if not acip:
                lr = getattr(p, "last_redirect", "")
                if lr and "wlanuserip" not in lr:
                    print("[!] 跳转到了 %s" % lr)
                    print("[!] 这看起来是学校自己的准入门户，不是天翼网络，本客户端不适用；")
                    print("    去那个网页上用学号登录一次，让 MAC 进入白名单后再跑本脚本。")
                print("[!] 探测不到 wlanacip，请用 --acip 指定，或在 esurfing.conf 里填 acip=")
                return 1
            print("[i] wlanuserip=%s wlanacip=%s" % (p.ip, acip))

            ticket = authenticate(a, p, acip)
            print("[+] ticket = %s" % ticket)
            if a.test_ticket:
                return 0
            if a.logout:
                print("[+] term Error-Code=%s" % p.term())
                return 0
            if not (a.user and a.passwd):
                print("[!] 需要账号密码：-u/-p 或写进 /etc/esurfing.conf")
                return 1

            ok, code, sub, pt = p.login(a.user, a.passwd)
            if not ok:
                print("[-] 登录被拒 Error-Code=%s Sub-Error=%s resp=%r" % (code, sub, pt[:300]))
                return 2
            print("[+] 登录请求已受理  keep=%s" % p.keep_url)
            if a.once:
                return 0
            session_loop(a, p)
        except KeyboardInterrupt:
            print("\n[i] 退出，发送下线请求…")
            try:
                print("[i] term Error-Code=%s" % p.term())
            except Exception as e:
                print("[!] 下线失败: %r" % e)
            return 0
        except Exception as e:
            print("[!] %s" % e)
            if a.once or a.test_ticket:
                return 1
            time.sleep(15)


if __name__ == "__main__":
    sys.exit(main() or 0)
