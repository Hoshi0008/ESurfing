#!/bin/sh
# 安装天翼校园网 Linux 客户端（Arch / Debian / OpenWrt 通用）
set -e

PREFIX=${PREFIX:-/usr/local}
BINDIR="$PREFIX/bin"
SRCDIR=$(cd "$(dirname "$0")" && pwd)

install -d "$BINDIR"
install -m 755 "$SRCDIR/esurfing.py" "$BINDIR/esurfing.py"
install -m 644 "$SRCDIR/esurfing_algos.py" "$BINDIR/esurfing_algos.py"
echo "已安装: $BINDIR/esurfing.py"

if [ ! -f /etc/esurfing.conf ]; then
    cat > /etc/esurfing.conf <<'EOF'
# 天翼校园网认证配置
# ---------------------------------------------------------------
# 带 <尖括号> 的值必须换成你所在学校的实际值，脚本不会猜。
# 参考仓库里的 esurfing.conf（占位符模板，注释更全）。
# ---------------------------------------------------------------

# 账号 / 密码（必填）
user=
passwd=
# 网卡（留空则按默认路由自动判断）
iface=
# 通道：windows / linux / android / macos / ios
channel=windows

# 校园 WiFi 的 SSID（脚本不用它，连网时用）
ssid=<你的校园网SSID>
# 认证服务器（BRAS / 门户），逗号分隔，按顺序尝试
servers=<认证服务器IP>,<备用认证服务器IP>
# 门户端口，多数是 7001
port=7001
# 认证器（AC）地址；探测不到时兜底，可留空
acip=<AC地址>
# 天翼地址池：本机地址落在里面才认证
campus_net=<天翼地址池网段>
# 学校自己的准入网 + 登录页（落这里说明 MAC 还没登记）
eia_net=<学校准入网网段>
eia_portal=http://<准入网网关>

# 学校参数（多数可留空）
schoolid=
domain=
area=
EOF
    chmod 600 /etc/esurfing.conf
    echo "已生成配置模板: /etc/esurfing.conf（请填写 user / passwd 和 servers 等）"
fi

if [ -d /etc/systemd/system ]; then
    cat > /etc/systemd/system/esurfing.service <<EOF
[Unit]
Description=Esurfing campus portal authenticator (China Telecom GD)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
ExecStart=$BINDIR/esurfing.py
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
    echo "已安装 systemd 单元: /etc/systemd/system/esurfing.service"
    echo "启用：systemctl enable --now esurfing"
fi
