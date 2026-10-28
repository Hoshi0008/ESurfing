#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esurfing_win.py —— Windows 专用版 广东天翼校园网认证客户端 (cdcportal / gd-portal)

和 esurfing.py 是同一个协议的实现，区别只在「怎么找到网卡」：
  * 用 GetAdaptersAddresses() (iphlpapi) 枚举适配器，不再依赖 /sys/class/net 和 ip 命令
  * 自动认出校园网网卡、自动取 IPv4 / MAC / 网关，不用手抄 --ip / --mac
  * 配置放在 %LOCALAPPDATA%\\esurfing\\，带 UTF-8 日志文件和大小轮转
  * 单实例互斥，支持开机自启（启动文件夹 + pythonw 无窗口）
  * 心跳之外还每 --net-check 秒真连一次外网，防止「心跳正常但网已经断了」

只依赖 Python3 标准库，不需要 pip install，不需要管理员权限。
配套文件：esurfing_algos.py（算法表，必须和本文件放同一目录）

常见用法
--------
    :: 0) 先连上校园 WiFi（SSID 见 esurfing.conf 里的 ssid）
    netsh wlan connect name="<你的SSID>"

    :: 1) 看所有网卡 / 看当前状态
    python esurfing_win.py --list
    python esurfing_win.py --status

    :: 2) 交互式生成配置文件（一次就够）
    python esurfing_win.py --setup

    :: 3) 前台跑一次，看日志确认能登上去（Ctrl+C 会自动下线）
    python esurfing_win.py -v

    :: 4) 常驻 + 开机自动启动（无窗口）
    python esurfing_win.py --install-startup
    :: 想取消：python esurfing_win.py --uninstall-startup

    :: 手动常驻（关掉窗口就停）
    python esurfing_win.py -v

    :: 只验证算法能不能跑通，不登录
    python esurfing_win.py --test-ticket -v

    :: 强制下线
    python esurfing_win.py --logout

手工指定网卡（默认 auto，会优先挑 WiFi）：
    python esurfing_win.py -i WLAN            # 按友好名
    python esurfing_win.py -i 20              # 按接口索引
    python esurfing_win.py -i RTL8852AE       # 按驱动描述子串
"""
import argparse
import binascii
import ctypes
import hashlib
import http.client
import ipaddress
import os
import random
import re
import socket
import struct
import sys
import time
import uuid
from ctypes import wintypes

APP = "esurfing"
VERSION = "1.0"

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
DEFAULT_SERVERS = []
PORT = 7001
DETECT_URLS = ["http://connect.rom.miui.com/generate_204",
               "http://www.baidu.com/",
               "http://www.qq.com/"]

# 校区相关的值全部来自 esurfing.conf（仓库里那份是占位符），这里只放兜底空值
ACIP_FALLBACK = ""
CAMPUS_NET = ""
EIA_NET = ""
EIA_PORTAL = ""

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
ALGOS = {}


def _load_algos():
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import esurfing_algos as m
    return m.ALGOS, m.BAD_ALGOS


try:
    _gen, BAD_ALGOS = _load_algos()
    ALGOS.update(_gen)
except Exception as _e:                              # 允许单独运行做自检
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


# ===========================================================================
#  Windows 平台层：枚举网卡 / 取 IP、MAC、网关
# ===========================================================================
IF_TYPE_IEEE80211 = 71
IF_TYPE_ETHERNET = 6
IF_TYPE_LOOPBACK = 24
IF_OPER_STATUS_UP = 1

# 注意：不能用 GetAdaptersInfo()——Win10/11 上它对 Wi-Fi 网卡会返回 0.0.0.0
# （老 API 的已知缺陷，但网关仍能读出来，很容易误判）。这里用 GetAdaptersAddresses。
_IPHLP = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
_K32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p),
                ("iSockaddrLength", ctypes.c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", wintypes.ULONG),
    ("PreferredLifetime", wintypes.ULONG),
    ("LeaseLifetime", wintypes.ULONG),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class _IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.ULONG),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", wintypes.ULONG),
    ("ZoneIndices", wintypes.ULONG * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_uint64),
    ("ReceiveLinkSpeed", ctypes.c_uint64),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", wintypes.ULONG),
    ("Ipv6Metric", wintypes.ULONG),
    ("Luid", ctypes.c_uint64),
    ("Dhcpv4Server", _SOCKET_ADDRESS),
    ("CompartmentId", wintypes.ULONG),
    ("NetworkGuid", ctypes.c_ubyte * 16),
    ("ConnectionType", ctypes.c_ubyte),
    ("TunnelType", ctypes.c_ubyte),
    ("Dhcpv6Server", _SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid", ctypes.c_ubyte * 130),
    ("Dhcpv6ClientDuidLength", wintypes.ULONG),
    ("Dhcpv6Iaid", wintypes.ULONG),
    ("FirstDnsSuffix", ctypes.c_void_p),
]

_IPHLP.GetAdaptersAddresses.argtypes = [wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG)]
_IPHLP.GetAdaptersAddresses.restype = wintypes.ULONG
_IPHLP.GetBestInterface.argtypes = [wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
_IPHLP.GetBestInterface.restype = wintypes.ULONG

_NET_GUID_KEY = ("SYSTEM\\CurrentControlSet\\Control\\Network\\"
                 "{4d36e972-e325-11ce-bfc1-08002be10318}")


def _friendly_name(guid):
    """兜底：从注册表把 {GUID} 换成「网络连接」里能看到的名字"""
    if not guid:
        return ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            _NET_GUID_KEY + "\\" + guid + "\\Connection") as k:
            return winreg.QueryValueEx(k, "Name")[0]
    except Exception:
        return ""


def _sockaddr_ip(sa):
    """从 SOCKET_ADDRESS 里取 IPv4 字符串（sockaddr_in: family(2) port(2) addr(4)）"""
    addr = sa.lpSockaddr
    if not addr or sa.iSockaddrLength < 8:
        return None
    if ctypes.c_ushort.from_address(addr).value != socket.AF_INET:
        return None
    return socket.inet_ntoa(ctypes.string_at(addr + 4, 4))


class Adapter(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)

    @property
    def is_wifi(self):
        return self.type == IF_TYPE_IEEE80211

    @property
    def label(self):
        return self.name or self.desc or self.guid or ("if%d" % self.index)

    def in_net(self, nets):
        return any(_ip_in(ip, n) for ip in self.ips for n in nets)

    def best_ip(self, nets=()):
        """挑一个 IPv4：优先落在指定网段里的，其次第一个"""
        for ip in self.ips:
            for n in nets:
                if _ip_in(ip, n):
                    return ip
        return self.ips[0] if self.ips else None

    def __str__(self):
        return "%-26s idx=%-3d %-15s gw=%-15s %-17s%s" % (
            self.label[:26], self.index,
            (self.ips[0] if self.ips else "-"),
            (self.gateways[0] if self.gateways else "-"),
            self.mac or "-",
            "  [Wi-Fi]" if self.is_wifi else "")


def _ip_in(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False


EIA_NET = ""


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


def _hint_net(ip):
    """不在天翼池时，给一句能直接照做的下一步（返回多行字符串或空串）"""
    if not ip or not EIA_NET:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
        inside = addr in ipaddress.ip_network(EIA_NET)
    except Exception:
        return ""
    if inside:
        return ("    这是学校自己的准入网：这台机器的 MAC 还没登记。\n"
                "    用浏览器打开 %s（必须 http://，别用 https），\n"
                "    用 学号 + 密码 登录一次，然后重连 WiFi，地址就会进天翼池。"
                % (EIA_PORTAL or "准入网网关"))
    return ""


def list_adapters():
    flags = (GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
             | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS)
    size = wintypes.ULONG(15 * 1024)
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        rc = _IPHLP.GetAdaptersAddresses(socket.AF_INET, flags, None, buf, ctypes.byref(size))
        if rc == 0:
            break
        if rc != 111:                                # ERROR_BUFFER_OVERFLOW
            raise OSError("GetAdaptersAddresses 失败: %d" % rc)
    else:
        raise OSError("GetAdaptersAddresses 反复缓冲区不足")

    out = []
    node = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while node:
        a = node.contents
        ips, gws = [], []
        u = a.FirstUnicastAddress
        while u:
            ip = _sockaddr_ip(u.contents.Address)
            if ip:
                ips.append(ip)
            u = u.contents.Next
        g = a.FirstGatewayAddress
        while g:
            ip = _sockaddr_ip(g.contents.Address)
            if ip:
                gws.append(ip)
            g = g.contents.Next
        mac = "-".join("%02x" % a.PhysicalAddress[i]
                       for i in range(min(a.PhysicalAddressLength, 8))) \
            if a.PhysicalAddressLength else ""
        guid = (a.AdapterName or b"").decode("ascii", "ignore")
        out.append(Adapter(
            guid=guid, index=a.IfIndex, type=a.IfType,
            desc=a.Description or "", name=a.FriendlyName or _friendly_name(guid),
            mac=mac, ips=ips, gateways=gws, oper=a.OperStatus,
            metric=a.Ipv4Metric, dhcp=bool(a.Flags & 0x4)))
        node = a.Next
    return out


def default_ifindex(dest="1.1.1.1"):
    """系统去 dest 会走哪块网卡"""
    try:
        addr = struct.unpack("<I", socket.inet_aton(dest))[0]
    except Exception:
        return 0
    idx = wintypes.DWORD(0)
    if _IPHLP.GetBestInterface(wintypes.ULONG(addr), ctypes.byref(idx)) == 0:
        return idx.value
    return 0


def find_adapter(spec, adapters=None, nets=()):
    """spec: auto / 名字 / 索引 / GUID / 描述子串"""
    ads = adapters if adapters is not None else list_adapters()
    if not spec or str(spec).strip().lower() == "auto":
        return pick_auto(ads, nets)
    s = str(spec).strip()
    if s.isdigit():                                  # 接口索引
        for a in ads:
            if a.index == int(s):
                return a
    for a in ads:                                    # 精确友好名 / GUID / 描述
        if s.lower() in (a.label.lower(), (a.guid or "").lower(),
                         (a.name or "").lower(), (a.desc or "").lower()):
            return a
    cand = [a for a in ads if s.lower() in (a.label + " " + (a.desc or "")).lower()]
    return cand[0] if cand else None


def pick_auto(adapters, nets=()):
    """自动挑：有 IP、有网关、非 loopback，优先「链路 UP」的接口；
    在此之上优先校园网段，其次优先 Wi-Fi，其次系统默认路由。

    注意必须看 OperStatus：Wi-Fi 掉线后适配器上还留着上次的 DHCP 地址，
    看起来完全正常，但发包会立刻 WSAEHOSTUNREACH(10065)。
    """
    nets = nets or ((ipaddress.ip_network(CAMPUS_NET, strict=False),) if CAMPUS_NET else ())
    usable = [a for a in adapters
              if a.ips and a.gateways and a.type != IF_TYPE_LOOPBACK
              and not all(ip.startswith("169.254.") for ip in a.ips)]
    if not usable:
        return None
    up = [a for a in usable if a.oper == IF_OPER_STATUS_UP]
    live = up or usable
    in_net = [a for a in live if a.in_net(nets)]
    pool = in_net or live
    wifi = [a for a in pool if a.is_wifi]
    if wifi:
        return wifi[0]
    bi = default_ifindex()
    for a in pool:
        if a.index == bi:
            return a
    return pool[0]


# ===========================================================================
#  配置 / 日志 / 单实例
# ===========================================================================
def _appdata(env):
    base = os.environ.get(env) or os.path.expanduser("~")
    return os.path.join(base, APP)


CONF_DIR = _appdata("LOCALAPPDATA")
CONF_PATH = os.path.join(CONF_DIR, "esurfing.conf")
ACIP_PATH = os.path.join(CONF_DIR, "acip.txt")
LOG_PATH = os.path.join(CONF_DIR, "esurfing_win.log")
LOCK_NAME = "esurfing_win_single_instance"
STARTUP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                           r"Microsoft\Windows\Start Menu\Programs\Startup")
STARTUP_VBS = os.path.join(STARTUP_DIR, "esurfing_win.vbs")

CONF_CANDIDATES = [
    CONF_PATH,                      # 你自己的真实配置，优先
    "/etc/esurfing.conf",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "esurfing.conf"),  # 仓库模板，兜底
]


def load_conf():
    for p in CONF_CANDIDATES:
        try:
            with open(p, encoding="utf-8-sig") as f:
                d = {}
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    d[k.strip()] = v.strip()
                if d:
                    return d, p
        except Exception:
            continue
    return {}, None


def save_conf(d):
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(CONF_PATH, "w", encoding="utf-8") as f:
        f.write("# esurfing_win.py 配置文件（UTF-8）\n")
        for k in ("user", "passwd", "iface", "acip", "channel",
                  "schoolid", "domain", "area", "net", "interval_min"):
            if d.get(k):
                f.write("%s = %s\n" % (k, d[k]))
    return CONF_PATH


def cached_acip():
    try:
        with open(ACIP_PATH) as f:
            return f.read().strip()
    except Exception:
        return ""


def remember_acip(acip):
    try:
        os.makedirs(CONF_DIR, exist_ok=True)
        with open(ACIP_PATH, "w") as f:
            f.write(acip + "\n")
    except Exception:
        pass


class Log(object):
    def __init__(self, verbose=False, to_file=True, quiet=False):
        self.verbose = verbose
        self.quiet = quiet
        self.path = LOG_PATH if to_file else None
        self._last_rotate = time.time()
        if self.path:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            except Exception:
                self.path = None

    def _rotate(self):
        try:
            if self.path and os.path.getsize(self.path) > 4 * 1024 * 1024:
                os.replace(self.path, self.path + ".1")
        except Exception:
            pass

    def __call__(self, msg, level="*"):
        line = "%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg)
        if not self.quiet:
            try:
                print(line, flush=True)
            except Exception:
                pass
        if self.path:
            try:
                if time.time() - self._last_rotate > 600:
                    self._last_rotate = time.time()
                    self._rotate()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass

    def v(self, msg):
        if self.verbose:
            self(msg, ":")


_single = None


def acquire_single_instance():
    """同一时间只允许一个实例，否则两个进程会互抢会话"""
    global _single
    _single = _K32.CreateMutexW(None, False, LOCK_NAME)
    if not _single:
        return True
    return ctypes.get_last_error() != 183          # ERROR_ALREADY_EXISTS


def official_client_running():
    """官方客户端在跑就别抢：它会反共享扫描，也会把会话挤掉"""
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq ESurfingClient.exe",
                              "/NH"], capture_output=True, timeout=10)
        return b"ESurfingClient.exe" in (out.stdout or b"")
    except Exception:
        return False


# ===========================================================================
#  协议（与 esurfing.py 一致，只把 gwip 变成实例属性）
# ===========================================================================
class PortalError(Exception):
    def __init__(self, msg, code=None, sub=None):
        super().__init__(msg)
        self.code = code
        self.sub = sub


class Portal(object):
    def __init__(self, ip, mac, channel="windows", schoolid="", domain="", area="",
                 source_ip=None, gwip="", timeout=10, log=None):
        self.ip = ip
        self.mac = mac
        self.ua, self.ostag = CHANNELS[channel]
        self.schoolid = schoolid
        self.domain = domain
        self.area = area
        self.source_ip = source_ip or ip
        self.gwip = gwip
        self.timeout = timeout
        self.log = log or Log()
        self.refresh_identity()
        self.algo_id = ZERO_UUID
        self.cipher = None
        self.ticket = ""
        self.last_redirect = ""
        self.server = DEFAULT_SERVERS[0]
        self.ticket_url = self.auth_url = self.keep_url = self.term_url = ""

    # ---- identity ----
    def refresh_identity(self):
        self.host_name = "%010x" % random.getrandbits(40)
        self.client_id = str(uuid.uuid4())

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
        self.log.v("POST %s -> %s Error-Code=%s len=%d" % (url, st, hd.get("error-code"), len(raw)))
        return st, hd, raw

    def get(self, url):
        st, hd, raw = self._request("GET", url, None, {
            "User-Agent": self.ua, "Accept": ACCEPT})
        self.log.v("GET %s -> %s" % (url, st))
        return st, hd, raw

    # ---- 门户发现 ----
    def discover(self):
        """返回 (portal_url, wlanacip)

        已认证的网络上探测不会跳转，此时退化为直接访问两台认证服务器的
        index.cgi，从它返回的 <config> 块里取 wlanacip。
        """
        for url in DETECT_URLS:
            try:
                st, hd, _ = self.get(url)
            except Exception as e:
                self.log.v("探测 %s 失败: %r" % (url, e))
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
                self.log.v("兜底探测 %s 失败: %r" % (srv, e))
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
                self.log.v("取门户页面失败: %r" % e)
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
                self.log.v("丢弃 ZSM Algo-ID=%s%s" % (
                    algo, "（黑名单）" if algo in BAD_ALGOS else "（未实现）"))
            else:
                self.log.v("ZSM 响应异常 Error-Code=%s len=%d" % (hd.get("error-code"), len(raw)))
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
    def get_ticket(self):
        body = self.cipher.encrypt(self.xml_ticket(self.gwip).encode())
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
                body = self.cipher.encrypt(self.xml_ticket(self.gwip).encode())
                continue
            if not raw:
                raise PortalError("取 ticket 失败 (Error-Code=%s)" % code, code=code,
                                  sub=hd.get("sub-error"))
            pt = self.cipher.decrypt(raw.decode())
            self.log.v("ticket 响应: %r" % pt)
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
        self.log.v("login 响应: %r" % pt)
        txt = pt.decode("utf-8", "replace")
        for tag, attr in (("keep-url", "keep_url"), ("term-url", "term_url")):
            m = re.search(r"<%s><!\[CDATA\[(.*?)\]\]></%s>" % (tag, tag), txt, re.S)
            if m:
                setattr(self, attr, m.group(1).strip())
                self.log.v("%s = %s" % (tag, getattr(self, attr)))
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


# ===========================================================================
#  主流程
# ===========================================================================
def nets_of(a):
    """把 --net 解析成网段元组；非法/占位符一律跳过，不抛异常"""
    if not a.net:
        return ()
    out = []
    for x in str(a.net).split(","):
        x = x.strip()
        if not x:
            continue
        try:
            out.append(ipaddress.ip_network(x, strict=False))
        except Exception:
            continue
    return tuple(out)


def select(a, log):
    """返回 (adapter, ip, mac, gwip)"""
    ads = list_adapters()
    nets = nets_of(a)
    ad = find_adapter(a.iface, ads, nets)
    if not ad:
        return None, None, None, None
    ip = ad.best_ip(nets) or (ad.ips[0] if ad.ips else None)
    if not ip:
        return ad, None, None, None
    gw = (ad.gateways or [""])[0]
    return ad, ip, ad.mac, gw


def authenticate(a, p, acip, log):
    """要算法 -> 取 ticket；返回 ticket"""
    servers = [a.server] if a.server else DEFAULT_SERVERS
    if not servers:
        raise PortalError("没有认证服务器：请在 esurfing.conf 里填 servers=，或用 --server 指定")
    err = None
    for srv in servers:
        try:
            p.configure(srv, acip)
            algo = p.fetch_algo()
            log("[+] 算法 %s（服务器 %s）" % (algo, p.server))
            return p.get_ticket()
        except Exception as e:
            err = e
            log("[!] 服务器 %s 失败: %s" % (srv, e), "-")
    raise PortalError("所有认证服务器都失败: %s" % err)


def session_loop(a, p, log):
    """已登录后的心跳循环；会话掉了就返回 False 让外层重来"""
    interval = 60
    fail = 0
    next_probe = time.time() + 30
    while True:
        time.sleep(interval)
        try:
            iv, code, body = p.keep()
        except Exception as e:
            log("[!] 心跳异常: %r" % e, "-")
            fail += 1
        else:
            if iv:
                interval = max(a.interval_min, iv)
            if code in (None, "0"):
                fail = 0
                log("[*] 心跳 OK，下一次 %ss" % interval)
            else:
                fail += 1
                log("[!] 心跳 Error-Code=%s body=%r" % (code, body[:160]), "-")
        if fail >= 3:
            log("[!] 连续 %d 次心跳失败，重新认证" % fail, "-")
            return False
        # 心跳通了不代表网通：每 net_check 秒真连一次外网
        if a.net_check and time.time() >= next_probe:
            next_probe = time.time() + a.net_check
            if not probe_online(p.source_ip):
                fail += 1
                log("[!] 心跳正常但外网不通（%d/3）" % fail, "-")
                if fail >= 2:
                    log("[!] 判定会话已失效，重新认证", "-")
                    return False
            else:
                log("[*] 外网连通性正常")
    return False


def cmd_setup(a):
    conf, path = load_conf()
    print("=== esurfing_win.py 配置向导 ===")
    print("（直接回车 = 用括号里的默认值）")
    cur = conf

    def ask(prompt, key, default=""):
        val = input("%s [%s]: " % (prompt, default or cur.get(key, "")))
        # 去掉粘贴带来的 BOM / 空白（BOM 混进账号里会直接登录失败）
        return (val or default or cur.get(key, "")).strip().strip("\ufeff").strip()

    d = {}
    d["user"] = ask("学号 / 账号", "user")
    d["passwd"] = ask("密码", "passwd")
    d["iface"] = ask("网卡（auto=自动挑 WiFi）", "iface", "auto")
    d["acip"] = ask("wlanacip（不确定就回车）", "acip", ACIP_FALLBACK)
    d["net"] = ask("只在这个网段认证（逗号分隔，留空=不限）", "net", CAMPUS_NET)
    d["channel"] = ask("伪装渠道 windows/linux/android", "channel", "windows")
    d["interval_min"] = ask("心跳最小间隔（秒）", "interval_min", "20")
    p = save_conf(d)
    print("\n[+] 已写入 %s" % p)
    print("    下次直接 `python esurfing_win.py -v` 即可")
    return 0


def _startup_cmd():
    py = sys.executable
    d, base = os.path.split(os.path.abspath(py))
    pww = os.path.join(d, "pythonw.exe")
    if os.path.exists(pww):
        py = pww
    script = os.path.abspath(__file__)
    return py, script


def cmd_install_startup(a):
    py, script = _startup_cmd()
    os.makedirs(STARTUP_DIR, exist_ok=True)
    body = ('\' esurfing_win.py autostart (generated)\n'
            'Set sh = CreateObject("WScript.Shell")\n'
            'sh.CurrentDirectory = "%s"\n'
            'sh.Run """%s"" ""%s"" --daemon", 0, False\n'
            % (os.path.dirname(script), py, script))
    with open(STARTUP_VBS, "w", encoding="utf-16") as f:
        f.write(body)
    print("[+] 已装到启动文件夹：\n    %s" % STARTUP_VBS)
    print("    登录 Windows 后会自动隐藏运行（日志 %s）" % LOG_PATH)
    print("    取消：python esurfing_win.py --uninstall-startup")
    return 0


def cmd_uninstall_startup(a):
    if os.path.exists(STARTUP_VBS):
        os.remove(STARTUP_VBS)
        print("[+] 已删除 %s" % STARTUP_VBS)
    else:
        print("[i] 没有装过自启动")
    return 0


def cmd_status(a, log):
    ads = list_adapters()
    nets = nets_of(a)
    print("=== 网卡 ===")
    for ad in ads:
        mark = ""
        if nets and ad.in_net(nets):
            mark = "  <-- 校园网段"
        print("  " + str(ad) + mark)
    ad, ip, mac, gw = select(a, log)
    print("\n=== 选中 ===")
    if not ad:
        print("  [!] 没有可用网卡（没连上 WiFi？）")
        return 1
    print("  网卡   : %s  (idx=%d%s)" % (ad.label, ad.index, ", Wi-Fi" if ad.is_wifi else ""))
    print("  描述   : %s" % ad.desc)
    print("  IP     : %s" % (ip or "-"))
    print("  网关   : %s" % (gw or "-"))
    print("  MAC    : %s" % (mac or "-"))
    print("  DHCP   : %s" % ("是" if ad.dhcp else "否"))
    if nets and ip and not any(_ip_in(ip, n) for n in nets):
        print("  [!] 这个 IP 不在 %s 里，可能不是校园网" % a.net)
        hint = _hint_net(ip)
        if hint:
            print(hint)
    acip = a.acip or cached_acip()
    print("\n=== 会话 ===")
    print("  wlanacip: %s%s" % (acip or "(未知，将现场探测)",
                                "  [缓存]" if not a.acip and acip else ""))
    if ip:
        online = probe_online(ip)
        print("  外网    : %s" % ("已认证，能直接上网" if online else "未认证 / 被门户拦着"))
    print("\n  配置文件: %s" % (load_conf()[1] or "(没有，先跑 --setup)"))
    print("  日志    : %s" % LOG_PATH)
    print("  官方客户端: %s" % ("在跑（会和本脚本抢会话，建议关掉）"
                                if official_client_running() else "没在跑"))
    return 0


def alive(a, log):
    """一轮完整的「选网卡 -> 上线 -> 心跳」，返回 True=会话结束时正常"""
    ad, ip, mac, gw = select(a, log)
    if not ad:
        log("[!] 找不到可用网卡（没连 WiFi？）", "-")
        return False
    if not ip:
        log("[!] %s 上没有 IPv4（还没拿到 DHCP？）" % ad.label, "-")
        return False
    if not mac:
        log("[!] 取不到 %s 的 MAC" % ad.label, "-")
        return False

    nets = nets_of(a)
    if nets and not any(_ip_in(ip, n) for n in nets):
        log("[!] %s=%s 不在 %s 内，跳过（--any-net 可强制）" % (ad.label, ip, a.net), "-")
        hint = _hint_net(ip)
        if hint:
            for line in hint.splitlines():
                log(line, "-")
        return False

    # 地址变了 = 换了 AP / 换了网，需要重新登录
    acip = a.acip or cached_acip()
    log("[i] %s  ip=%s  mac=%s  gw=%s" % (ad.label, ip, mac, gw or "-"))

    if not a.force and not (a.test_ticket or a.logout) and probe_online(ip):
        log("[i] 已在线，%ss 后复查" % a.check_interval)
        return True

    p = Portal(ip=ip, mac=mac, channel=a.channel, schoolid=a.schoolid,
               domain=a.domain, area=a.area, source_ip=ip, gwip=gw or "",
               log=log)
    log("[i] UA=%s" % p.ua)

    portal_url, found = p.discover()
    if found:
        acip = found
        remember_acip(found)
        log("[i] 探测到 wlanacip=%s" % found)
    if not acip:
        acip = ACIP_FALLBACK
        if acip:
            log("[!] 探测不到 wlanacip，用配置里的 acip=%s 兜底" % acip, "-")
        else:
            log("[!] 探测不到 wlanacip，请在 esurfing.conf 里填 acip=，或用 --acip 指定", "-")
            return False
    if p.ip != ip:
        log("[i] 门户把 wlanuserip 校正为 %s" % p.ip)
    log("[i] wlanuserip=%s wlanacip=%s" % (p.ip, acip))

    try:
        ticket = authenticate(a, p, acip, log)
    except Exception as e:
        lr = getattr(p, "last_redirect", "")
        if lr and "wlanuserip" not in lr:
            log("[!] 跳转到了 %s" % lr, "-")
            log("[!] 这看起来是学校 eIA BYOD 门户（172.x），不是天翼网络", "-")
        raise
    log("[+] ticket = %s" % ticket)
    if a.test_ticket:
        return True
    if a.logout:
        log("[+] term Error-Code=%s" % p.term())
        return True
    if not (a.user and a.passwd):
        log("[!] 需要账号密码：-u/-p 或跑一次 --setup", "-")
        return False

    ok, code, sub, pt = p.login(a.user, a.passwd)
    if not ok:
        log("[-] 登录被拒 Error-Code=%s Sub-Error=%s resp=%r" % (code, sub, pt[:300]), "-")
        return False
    log("[+] 登录成功  keep=%s" % p.keep_url)
    if a.once:
        return True
    return session_loop(a, p, log)


def main():
    global DEFAULT_SERVERS, PORT, CAMPUS_NET, EIA_NET, EIA_PORTAL, ACIP_FALLBACK
    conf, conf_path = load_conf()

    # 校区相关参数一律来自配置（仓库里的 esurfing.conf 是占位符）
    if conf.get("servers"):
        raw = [s.strip() for s in conf["servers"].split(",") if s.strip()]
        DEFAULT_SERVERS = [s for s in raw if _is_ipv4(s)]
    if conf.get("port", "").strip().isdigit():
        PORT = int(conf["port"].strip())
    CAMPUS_NET = _valid_net(conf.get("campus_net", "") or conf.get("net", ""))
    EIA_NET = _valid_net(conf.get("eia_net", ""))
    EIA_PORTAL = conf.get("eia_portal", "").strip()
    ACIP_FALLBACK = conf.get("acip", "").strip() if _is_ipv4(conf.get("acip", "")) else ""

    ap = argparse.ArgumentParser(
        description="Windows 版 广东天翼校园网认证客户端 (cdcportal)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="例: python esurfing_win.py --setup   然后   python esurfing_win.py -v")
    ap.add_argument("-u", "--user", default=conf.get("user"))
    ap.add_argument("-p", "--passwd", default=conf.get("passwd"))
    ap.add_argument("-i", "--iface", default=conf.get("iface", "auto"),
                    help="auto / 友好名(WLAN) / 索引(20) / 描述子串")
    ap.add_argument("--channel", default=conf.get("channel", "windows"), choices=list(CHANNELS))
    ap.add_argument("--server", default=conf.get("server"), help="认证服务器 IP（默认用 conf 里的 servers）")
    ap.add_argument("--acip", default=ACIP_FALLBACK)
    ap.add_argument("--schoolid", default=conf.get("schoolid", ""))
    ap.add_argument("--domain", default=conf.get("domain", ""))
    ap.add_argument("--area", default=conf.get("area", ""))
    ap.add_argument("--net", default=CAMPUS_NET,
                    help="只在这个网段认证，逗号分隔；给空串则不限制")
    ap.add_argument("--any-net", dest="net_any", action="store_true", help="不限网段")
    ap.add_argument("--interval-min", type=int, default=int(conf.get("interval_min", 20) or 20))
    ap.add_argument("--check-interval", type=int, default=60, help="已在线时的复查间隔")
    ap.add_argument("--net-check", type=int, default=int(conf.get("net_check", 300) or 300),
                    help="心跳之外每 N 秒真连一次外网校验（0=关）")
    ap.add_argument("--test-ticket", action="store_true", help="只验证算法/取 ticket")
    ap.add_argument("--logout", action="store_true")
    ap.add_argument("--once", action="store_true", help="认证一次就退出")
    ap.add_argument("--force", action="store_true", help="即使已在线也重新认证")
    ap.add_argument("--daemon", action="store_true", help="后台模式：不输出到控制台，只写日志")
    ap.add_argument("--allow-official", action="store_true", help="官方客户端在跑也照样执行")
    ap.add_argument("--list", action="store_true", help="列出所有网卡")
    ap.add_argument("--status", action="store_true", help="显示状态后退出")
    ap.add_argument("--setup", action="store_true", help="交互式写配置文件")
    ap.add_argument("--install-startup", action="store_true")
    ap.add_argument("--uninstall-startup", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    # pythonw 下 sys.stdout / sys.stderr 都是 None，必须先判空
    if sys.stdout is not None and not sys.stdout.isatty():   # 被重定向/管道时统一 UTF-8
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if a.net_any:
        a.net = ""

    if a.setup:
        return cmd_setup(a)
    if a.install_startup:
        return cmd_install_startup(a)
    if a.uninstall_startup:
        return cmd_uninstall_startup(a)

    log = Log(verbose=a.verbose, quiet=a.daemon)
    if (conf.get("campus_net") or conf.get("net")) and not CAMPUS_NET:
        log("[!] 配置里的 campus_net 不是合法网段，已忽略（占位符要换成真值）", "-")
    if conf.get("eia_net") and not EIA_NET:
        log("[!] 配置里的 eia_net 不是合法网段，已忽略（占位符要换成真值）", "-")
    if a.list:
        for ad in list_adapters():
            print("  " + str(ad))
        return 0
    if a.status:
        return cmd_status(a, log)

    if not acquire_single_instance():
        log("[!] 已经有一个 esurfing_win.py 在跑了，先关掉它", "-")
        return 1
    if not a.allow_official and official_client_running():
        log("[!] 官方 ESurfingClient.exe 正在运行，会和本脚本抢会话", "-")
        log("    关掉它，或者加 --allow-official", "-")
        return 1

    log("=== esurfing_win.py v%s 启动 pid=%d ===" % (VERSION, os.getpid()))
    log("[i] 配置: %s" % (conf_path or "(无，用命令行参数)"))
    log("[i] 日志: %s" % LOG_PATH)

    backoff = 5
    while True:
        try:
            if alive(a, log):
                if a.once or a.test_ticket or a.logout:
                    return 0
                backoff = 5
                time.sleep(a.check_interval)          # 已在线，正常轮询，不进退避
                continue
        except KeyboardInterrupt:
            log("\n[i] 收到 Ctrl+C，发送下线请求…")
            return 0
        except Exception as e:
            log("[!] %s" % e, "-")
            if a.once or a.test_ticket:
                return 1
        if a.once or a.test_ticket or a.logout:
            return 1
        log("[i] %ss 后重试" % backoff)
        try:
            time.sleep(backoff)
        except KeyboardInterrupt:
            return 0
        backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except SystemExit:
        raise
    except BaseException:                            # pythonw 下没控制台，把栈写进日志
        import traceback
        try:
            Log()(traceback.format_exc(), "!")
        except Exception:
            pass
        raise
