# 广东天翼校园网 (cdcportal) Linux 客户端

对 Windows 版「天翼校园网客户端」逆向得到的协议实现。
纯 Python3 标准库，无第三方依赖，可直接跑在 Arch / Debian / OpenWrt / Windows 上。

仓库：<https://github.com/Hoshi0008/ESurfing>

```
esurfing.py          客户端主程序（Linux / 通用）
esurfing_win.py      Windows 专用版（自动选网卡、网段守卫、开机自启、无窗口常驻）
esurfing_algos.py    Algo-ID -> (算法, key, iv) 表 + 失效算法黑名单
esurfing.conf        配置模板（占位符；真实值放系统位置，见第五节）
install.sh           安装到 /usr/local/bin + /etc/esurfing.conf（可选 systemd 单元）
LICENSE              MIT 许可证
.gitignore           忽略本地配置 / 日志 / 缓存
```

> 本包里的账号、密码、MAC、IP 均已置空，请自行填写。

---

## 一、校园网是怎么工作的

### 不是 PPPoE，也不是 802.1X，是 Portal 认证

校园网是**二层直达 BRAS 的 Portal 认证**（`cdc-http-pap`）。插上网线或连上 WiFi 后，
DHCP 直接给你一个校园网地址（网段见 `esurfing.conf` 的 `campus_net`）。此时**任何** HTTP 请求都会被网关 302 到
BRAS 上的认证门户：

```
http://<servers>:<port>/index.cgi?wlanuserip=<本机IP>&wlanacip=<AC地址>
```

在门户上完成一次"账号 + 密码 + 本机 IP/MAC"的认证，BRAS 就把这个 IP 放行。

所以 Linux 上**不需要任何驱动、不需要虚拟网卡**，只要把官方客户端那串 HTTP 请求
照发一遍就行——这就是本脚本做的事。

### 完整链路

```
① DHCP 拿到校园网地址（campus_net 段）
        │
        ▼
② 任意 HTTP 请求 → 302 到 http://<BRAS>:7001/index.cgi?wlanuserip=…&wlanacip=…
        │            （拿到 AC 地址 wlanacip，也就是"认证器"）
        ▼
③ POST ticket.cgi  （Algo-ID 首次为全 0）→ Error-Code: 200 + 加密的算法模块(ZSM)
        │                                    服务端会随机下发"失效算法"，丢掉重试
        ▼
④ POST ticket.cgi  （带上刚拿到的 Algo-ID）→ 明文 XML 里的 <ticket>
        │
        ▼
⑤ POST auth.cgi    → Error-Code: 0，并返回 keep-url / term-url / user-config
        │
        ▼
⑥ 按 keep-url 定时 POST keep.cgi（通常 300 秒一次）维持会话
        │
        ▼
⑦ 流量被放行：能访问外网；`generate_204` 返回 204 而不是 302
```

**判据只有一条：能不能拿到 200/204。** `auth.cgi` 回 `Error-Code=0` 只代表"请求已受理"，
不代表已经放行——两者经常不一致。

## 二、协议要点

### 每个 POST 都带的头

| 头 | 值 |
|---|---|
| `User-Agent` | `CCTP/WinSVR5/1068`（Windows 通道）／`CCTP/Linux64/1003`（Linux 通道） |
| `Algo-ID` | 当前算法 UUID，首次为全 0 |
| `Client-ID` | 随机 UUID（小写） |
| `CDC-Checksum` | `md5(POST body)` 小写 hex |
| `CDC-SchoolId` / `CDC-Domain` / `CDC-Area` | 学校参数，可留空 |
| `Content-Type` | `application/x-www-form-urlencoded` |

**UA 是关键**：老 UA（如 `CCTP/win1/5007`）会被直接判 `Error-Code=2`（客户端版本不正确），
必须是新版本 UA 服务端才会下发算法模块。

### 取算法（ZSM）

`POST ticket.cgi`，body 就是 Algo-ID 字符串。响应头 `Error-Code: 200`，body 是：

```
"001" | u8 len1 | str1 | u8 len2 | str2(=Algo-ID UUID) | <加密的算法模块>
```

`str2` 是本轮下发的 Algo-ID。服务端随机下发，其中一部分是**失效算法**（用它会被拒），
官方客户端的做法是丢弃→换一套随机 `host-name/client-id/mac`→重要，直到拿到可用的。
本脚本复刻了这个循环。

### 报文加密

XML 明文 → 算法加密 → **大写 hex** 作为 body；响应同样是 hex，解出来是 XML。

`aes_double_cbc` 系列（每个 Algo-ID 一套独立 key/iv）为「双层 AES-128-CBC」：

* 32 字节 key 拆成两层 16 字节；
* key schedule 是魔改版（先转置密钥，再 10 轮 S 盒/Rcon 混合）；
* 每层都是 **IV 前缀模式**：`输出 = IV || CBC(零填充明文)`，无 PKCS7；
* 加密两层（key[0:16] 再 key[16:32]），解密反序，末尾去掉 `\x00`。

### 四个接口

| 步骤 | 接口 | XML 内容 | 返回 |
|---|---|---|---|
| 取 ticket | `POST ticket.cgi` | `user-agent/client-id/local-time/host-name/ipv4/ipv6/mac/ostag/gwip` | `<ticket>…</ticket><expire>…</expire>` |
| 登录 | `POST auth.cgi` | `user-agent/client-id/ticket/local-time/userid/passwd` | `<keep-retry>5</keep-retry><keep-url>…` 等 |
| 心跳 | `POST keep.cgi` | `user-agent/client-id/local-time/host-name/ipv4/ticket/ipv6/mac/ostag` | `<interval>300</interval><level>0</level>` |
| 下线 | `POST term.cgi` | 同心跳 | — |

注意：

* `keep-url` 有时是**另一台** BRAS，必须用登录响应里给的那个；
* `local-time` 用 `%Y-%m-%d %H:%M:%S`，本机时钟要准；
* `host-name` 是随机 10 位小写 hex；`mac` 可以随便填（官方客户端也不发真实 MAC）；
  `ipv4` 必须是 BRAS 看到的那个 IP。

### 服务端下发的 `user-config`

登录响应里有一段策略配置，主要是**反共享**用：

* `against`：18 个"免费 WiFi / 随身 WiFi"进程名（猎豹、360、小度、腾讯全民 WiFi…）
* `device`：5 种 USB 随身 WiFi 的设备描述
* `shared`：`public/private/virtual` 三个开关
* `against-interval` / `logout-delay` / `sandbox`

**它检测的是"你在自己电脑上开热点"**，不是"一个账号几台设备"。本脚本不做这些检查。

## 三、快速开始

```sh
# 1. 网卡先拿到校园网 IP（DHCP）
sudo dhcpcd eno1            # 或 NetworkManager / systemd-networkd

# 2. 只验证协议与算法（不需要账号）
sudo ./esurfing.py -i eno1 --test-ticket -v

# 3. 正式认证（前台跑，Ctrl-C 会先发下线）
sudo ./esurfing.py -i eno1 -u <学号> -p '<密码>'

# 4. 装机自启
sudo ./install.sh
sudo vi /etc/esurfing.conf      # 填 user / passwd / iface
sudo systemctl enable --now esurfing
journalctl -u esurfing -f
```

Windows 上用另一个文件 `esurfing_win.py`（会自动选网卡，不用手抄 IP/MAC），见第十一节。

## 四、命令行选项

| 选项 | 说明 |
|---|---|
| `-u` / `--user` | 账号（学号） |
| `-p` / `--passwd` | 密码 |
| `-i` / `--iface` | 网卡名（`ip -br a` 看）。**Linux 上必填**，否则会按默认路由猜 |
| `--ip` | 本机在校园网里的 IP（`wlanuserip`）。不填就从网卡读 |
| `--mac` | 上报给门户的 MAC。**随便填**，和真实网卡 MAC 无关 |
| `--channel` | `windows`（默认）/ `linux` / `android` / `macos` / `ios`，决定 UA 和 ostag |
| `--server` | 认证服务器，默认用 conf 里的 `servers` |
| `--acip` | 认证器地址。能自动探测，探测不到才需要手填 |
| `--schoolid` / `--domain` / `--area` | 学校参数，多数学校可留空 |
| `--test-ticket` | 只跑"取算法 → 取 ticket"，不碰账号 |
| `--logout` | 只发下线请求（不需要账号密码） |
| `--once` | 认证一次就退出（不做心跳循环）。⚠️ 认证结果要靠心跳落地，测通网别用它 |
| `--force` | 即使"已在线"也重新认证。**没有短选项**，不是 `-f` |
| `--check-interval` | 已在线时多久复查一次（默认 60 秒） |
| `--interval-min` | 心跳间隔下限（默认 20 秒；服务端通常给 300 秒） |
| `-v` / `--verbose` | 打印每个请求的 URL、响应码、解密后的 XML |

退出码：`0` 成功 / `1` 参数或网络错误 / `2` 登录被服务端拒绝。

## 五、配置文件

**校区相关的值全部放在 `esurfing.conf` 里**，代码里不写死。仓库里那份是**占位符模板**，
你本地的真实值放在系统位置——不要改仓库那份，更不要提交。

查找顺序（先找到的生效）：

| 平台 | 顺序 |
|---|---|
| Linux | `/etc/esurfing.conf` → `~/.config/esurfing.conf` → `脚本目录/esurfing.conf` |
| Windows | `%LOCALAPPDATA%\esurfing\esurfing.conf` → `脚本目录\esurfing.conf` |

命令行参数优先级更高。

### 全部键

| 键 | 说明 |
|---|---|
| `user` / `passwd` | 账号 / 密码 |
| `iface` | 网卡；Windows 可写 `auto` |
| `channel` | `windows` / `linux` / `android` / `macos` / `ios` |
| `ssid` | 校园 WiFi 的 SSID（脚本不使用，供你参考/替换文档用） |
| `servers` | 认证服务器，逗号分隔，按顺序尝试 |
| `port` | 门户端口，多数 `7001` |
| `acip` | 认证器（AC）地址，探测不到时兜底 |
| `campus_net` | 天翼地址池，**只有落在这个网段才认证** |
| `eia_net` | 学校自己的准入网，落这里说明 MAC 没登记 |
| `eia_portal` | 准入网登录页，脚本会把这个地址打给你 |
| `schoolid` / `domain` / `area` | 学校参数，多数可留空 |
| `interval_min` | 心跳间隔下限（秒） |
| `net_check` | 心跳之外多久真连一次外网校验（Windows 版，0=关） |

`campus_net` / `eia_net` / `eia_portal` 三个是可选的：留空就不做网段判断、不打印登记提示。

### 示例（你自己的那份，放系统位置）

```ini
user=<学号>
passwd=<密码>
iface=wlan0
channel=windows
ssid=<你的校园网SSID>
servers=<认证服务器IP>
port=7001
acip=<AC地址>
campus_net=<天翼网段>
eia_net=<准入网网段>
eia_portal=http://<准入网网关>
schoolid=
domain=
area=
```

⚠️ 两个坑：

* 配置读取是**静默失败**的：文件不可读（比如 `600` 权限且不是 root 跑）就当没有配置，
  一路走到"需要账号密码"。非 root 运行请把配置放到 `~/.config/esurfing.conf`。
* 如果你把真实值直接写进了仓库里的 `esurfing.conf`，它会在 `git status` 里显示为已修改。
  别 `git add -A` —— 或者干脆 `git update-index --skip-worktree esurfing.conf` 让它在本地"隐身"。

## 六、无线：同一个 SSID 下的两张网

同一个 SSID 下其实有两套接入，用拿到的 IP 段就能分辨：

| 拿到的 IP | 是什么 | 本客户端能用吗 |
|---|---|---|
| `campus_net` 段 | 电信 BRAS（和有线同一张网） | ✅ 直接可用 |
| `<eia_net>` | 学校 eIA 准入网（华为 Agile Controller） | ❌ 先要"上户口" |

### 为什么会落到 <eia_net>：MAC 没登记

新设备的 MAC 不在放行表里就会被丢进准入网。解决办法不是换 AP（同一台 AP），
而是**去准入网里登记一次**：

1. 连上 SSID，拿到的会是 `<eia_net>`
2. 浏览器打开 **`http://`** 开头的站点（`<eia_portal>` 或 `http://neverssl.com`）

   ⚠️ 认证前不要用 HTTPS：门户会劫持 443，浏览器报
   `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` 就是这个原因，不是网络坏了。
   ⚠️ 也别测 `http://1.1.1.1`：它在 HSTS 预载列表里，浏览器会强制升级成 HTTPS。

3. 用学号 + 密码登录（密码规则以学校为准（学生常见是身份证后八位））
4. 重连一次，IP 进 `campus_net` 段
5. 回到本脚本认证

### 一定要把 MAC 固定住

放行表是按 MAC 记的，**每次随机 MAC 都等于一台新设备、都要重新登记**：

```sh
nmcli con mod <连接名> 802-11-wireless.cloned-mac-address permanent
```

⚠️ `ip link set address` 会被 NetworkManager 覆盖，必须写进连接配置，
并在连上之后用 `ip link show <网卡> | grep ether` 确认。

临时借用别人的 MAC（仅供调试）：

```sh
nmcli con mod <连接名> 802-11-wireless.cloned-mac-address <已放行的MAC>
```

同一个 MAC 不能在同一无线域里出现两台设备，会互相踢。但它跟"有线 vs 无线"不冲突：
有线和无线通常是两个不同子网，各记各的 MAC 表。

## 七、设备数量限制（PC 台数）

账号能同时在线几台由**服务端**决定，跟用哪个客户端无关。这里有两层容易混在一起：

### 1. 并发会话数

按 **(账号, wlanuserip)** 计，常见上限是 2 条。第 3 条会直接触发：

```
Error-Code = 13014000   # 终端数超出限制
```

⚠️ **同一台机器同时开有线和无线 = 2 条会话**，会把名额吃光，第三台上不来。

### 2. PC 台数（更严格的那层）

除了会话总数，很多校区还限制"接入了什么类型的设备"，典型策略是
**1 台 PC + 1 台移动端**。这一层最坑的地方是**判定延迟**：

| 时刻 | 现象 | 原因 |
|---|---|---|
| T+0 | 两台 PC 都认证成功，都能上网 | `auth.cgi` 只校验账号和 IP，不看设备 |
| T+几分钟 | 其中一台突然断网 | 设备类型靠**流量指纹**（TTL、TCP/IP 指纹、UA）判定，要观察到真实流量才下结论 |

实测：两台 PC 同时在线，**不超过 5 分钟**就会有一台失去外网访问。表现是
"用着用着就断了"，而且断之前日志里一切正常——因为 `auth` 一直回 `Error-Code=0`，
断网是 BRAS 侧单方面做的。

> 所以"登录成功"和"能上网"必须分开看：前者只代表请求已受理。

### 应对办法

1. **一台在线**，另一台要用时先让位：

   ```sh
   sudo python3 -u ./esurfing.py -i wlan0 --logout
   ```

2. **一台做代理**，另一台通过它上网——只占一个名额：

   ```sh
   microsocks -i 0.0.0.0 -p 1080     # 另一台把 socks5 指向 这台:1080
   ```

3. **换通道试试**：如果限制是"1 PC + 1 移动端"，第二台用移动端 UA 上线可能就不被算作 PC：

   ```sh
   ./esurfing.py -i wlan0 --channel android
   ```

   能否奏效取决于服务端是看自报字段还是看流量指纹，值得花 10 分钟对照一次
   （两台同时在线，等 10 分钟看是否还互踢）。

4. **第二台走另一套网**：学校自己的准入网（`<eia_net>`）不占天翼名额，代价是可能限速。

## 八、后台常驻 + 日志（不装 systemd）

⚠️ **必须用 `python3 -u` 或 `PYTHONUNBUFFERED=1`**。Python 的 stdout 重定向到文件时是
**块缓冲**（约 8 KB），几百字节的输出根本刷不出来——表现就是"日志里一个字都没有，
像是脚本什么都没干"。这不是没报错，是看不到。

```sh
# 起
sudo sh -c 'PYTHONUNBUFFERED=1 nohup python3 -u /usr/local/bin/esurfing.py \
    -i wlan0 -v --force >> /var/log/esurfing.log 2>&1 &'

tail -f /var/log/esurfing.log      # 看 [+] 登录请求已受理 / [*] 心跳正常
pgrep -af '[e]surfing'             # 确认进程还在（[e] 写法不会匹配到自己）

# 停（先干净下线再杀进程）
sudo python3 -u /usr/local/bin/esurfing.py -i wlan0 --logout
sudo pkill -f '[e]surfing.py'
```

## 九、排错

| 现象 | 原因 / 处理 |
|---|---|
| 一直"丢弃 ZSM" | 正常，服务端会随机发失效算法，重试即可 |
| `Error-Code=2` | UA 不对，必须是新版 UA |
| `Error-Code=140011` | 服务端认为 MAC 无效 → 确认 MAC 已登记 |
| `140100 / 13012000` | 账号或密码错 |
| `13014000` | 终端数超限 |
| 拿不到 `wlanacip` | 手动 `--acip <AC地址>` |
| 已认证但上不了网 | `--logout` 再重登，或等 BRAS 会话超时 |
| 连 WiFi 拿到 `<eia_net>` | MAC 没登记，见第六节 |
| 浏览器报 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` | 认证前访问了 HTTPS，改用 `http://` |
| 日志/终端"什么都没有" | Python 输出被块缓冲，用 `python3 -u` |
| `登录请求已受理` 但网页还是 302 | BRAS 没真正放行（多半并发终端占满）→ `--logout` 后重登 |
| `term` 返回 `Error-Code=14` | 当前本来就没有活会话 |

## 十、几个坑

* **认证结果要跑心跳才落地**，只发一次 `auth` 立刻退出，可能几秒后就被踢回去。
* **热点共享的检测是"客户端自报"的**。服务端下发的 18 个进程名、5 种 USB 随身 WiFi
  描述、`shared/public/private/virtual` 开关，都是让**客户端自己去查、自己上报**的。
  本脚本不做这些检查也不上报，因此这套机制不会命中。
  但这不等于共享一定安全：运营商侧是否另有流量指纹（TTL 递减、多设备并发）无法验证，
  条款上通常也禁止共享——技术上能跑通 ≠ 允许。
* **同账号并发终端数有限**（见第七节），超限时 `auth` 仍可能回 `Error-Code=0`，
  但 BRAS 不放行；也可能是"用一会儿突然断"，因为 PC 台数靠流量指纹延迟判定。
* **别在同一台机器上同时开有线和无线**——那是两条会话，会把名额吃光。

## 十一、Windows 版（esurfing_win.py）

协议和 `esurfing.py` 完全一样，区别只在「怎么找网卡」：Windows 没有 `/sys/class/net`、
也没有 `ip` 命令，这一版用 `GetAdaptersAddresses()`（iphlpapi，纯 ctypes）自己枚举适配器。

比 Linux 版多出来的能力：

* **自动选卡**：按「在校园网段 + 有网关 + 是 Wi-Fi」排序挑一张，不用手抄 `--ip/--mac`
* **网段守卫** `--net`：只在这个网段认证，不在就跳过（不会去认证手机热点）
* **额外连通性校验** `--net-check`：心跳之外每 N 秒真连一次外网，防「心跳正常但网已断」
* 配置与日志在 `%LOCALAPPDATA%\esurfing\`，日志 UTF-8、带大小轮转
* 单实例互斥；检测到官方 `ESurfingClient.exe` 在跑会拒绝启动（`--allow-official` 可绕过）
* 开机自启：写启动文件夹 + 用 `pythonw` 跑（无窗口）
* 失败指数退避 5 → 10 → 20 → 40 → 60 秒封顶，不会疯狂重试

### 选项

| 选项 | 说明 |
|---|---|
| `-u` / `--user` | 账号 |
| `-p` / `--passwd` | 密码 |
| `-i` / `--iface` | `auto`（默认）／友好名 `WLAN`／接口索引 `20`／描述子串 `RTL8852AE` |
| `--channel` | `windows`（默认）/ `linux` / `android` / `macos` / `ios` |
| `--server` | 认证服务器 IP（默认依次试两台） |
| `--acip` | 认证器地址（默认用缓存或现场探测） |
| `--schoolid` / `--domain` / `--area` | 学校参数，多数可留空 |
| `--net` | 只在这个网段认证（默认用 conf 里的 `campus_net`，逗号分隔可多个） |
| `--any-net` | 不限网段（等价于 `--net ""`） |
| `--interval-min` | 心跳间隔下限（默认 20 秒） |
| `--check-interval` | 已在线时的复查间隔（默认 60 秒） |
| `--net-check` | 每 N 秒真连一次外网校验（默认 300，`0`=关闭） |
| `--test-ticket` | 只验证算法 / 取 ticket，不登录 |
| `--logout` | 只发下线请求 |
| `--once` | 认证一次就退出（不做心跳循环） |
| `--force` | 即使已在线也重新认证 |
| `--daemon` | 后台模式：不输出到控制台，只写日志 |
| `--allow-official` | 官方客户端在跑也照样执行 |
| `--list` | 列出所有网卡（含是否在校园网段） |
| `--status` | 打印网卡 / 选中项 / 会话状态后退出 |
| `--setup` | 交互式生成配置文件 |
| `--install-startup` / `--uninstall-startup` | 装 / 卸开机自启 |
| `-v` / `--verbose` | 详细日志 |

### 用法

```
:: 0) 先连校园 WiFi（Windows 自己会拿 DHCP）
netsh wlan connect name="<ssid>"

:: 1) 看网卡 / 看状态
python esurfing_win.py --list
python esurfing_win.py --status

:: 2) 交互式生成配置（一次就够）
python esurfing_win.py --setup

:: 3) 前台跑，确认能登上去（Ctrl+C 会自动下线）
python esurfing_win.py -v

:: 4) 常驻 + 开机自启（无窗口）
python esurfing_win.py --install-startup
python esurfing_win.py --uninstall-startup
```

配置文件（`%LOCALAPPDATA%\esurfing\esurfing.conf`）：

```ini
user=<学号>
passwd=<密码>
iface=auto
channel=windows
net=<campus_net>
interval_min=20
```

日志：`%LOCALAPPDATA%\esurfing\esurfing_win.log`

### 注意事项

* **落到 `<eia_net>` 会直接告诉你怎么办**：脚本会打印
  「这是学校 eIA 准入网：这台机器的 MAC 还没登记」并给出 `<eia_portal>` 和登录方式，
  不会硬去认证一个不属于天翼的地址。
* **和官方客户端抢名额**：两者会争同一个会话，启动时检测到 `ESurfingClient.exe` 会拒绝运行。
* **同一台机器别同时开有线和无线**：那是两条会话（见第七节）。
* **`pythonw` 下没有控制台**，异常会写进日志文件，出问题先看那个。
* 只需要 Python 3，**不需要管理员权限、不需要 pip**。
* 本文件必须和 `esurfing_algos.py` 放在同一目录。

## 十二、许可证

[MIT License](LICENSE) © 2026 Hoshi0008

仅供学习与个人使用。使用前请自行确认所在学校 / 运营商的服务条款；
因使用本工具产生的任何后果由使用者自负。
