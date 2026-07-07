#!/bin/bash
# pivot-setup.sh — T2 전용 "취약 dual-homed 피벗 호스트" (격리 클론 한정).
# 가입자평면(net_cellular)과 코어망(net_core) 양다리. 의도적 약한 SSH 자격 → 공격자가
# UE 위치에서 이 호스트를 장악한 뒤 net_core로 피벗(측면이동)하는 발판을 모델링.
# ⚠ 대회 실증용 의도적 취약. 실제 배치엔 절대 사용 금지.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q && apt-get install -y -q openssh-server iproute2 iputils-ping netcat-openbsd >/dev/null 2>&1 || true

# 의도적 약한 자격 (측면이동 초기접근 모델)
useradd -m -s /bin/bash pivot 2>/dev/null || true
echo 'pivot:pivot123' | chpasswd
mkdir -p /run/sshd
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 피벗이 net_core로 포워딩 가능하도록 (침투 후 proxychains/SOCKS 경유 대상)
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

echo "[pivot] dual-homed 기동: net_cellular 10.44.0.50 · net_core 10.50.0.99 (약자격 pivot:pivot123)"
exec /usr/sbin/sshd -D
