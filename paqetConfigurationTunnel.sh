#!/usr/bin/env bash

set -euo pipefail

############################################
# Global variables
############################################
BASE_DIR="/root/paqet"
CONFIG_DIR="$BASE_DIR/configs"
BIN_URL="https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.14/paqet-linux-amd64-v1.0.0-alpha.14.tar.gz"
BIN_NAME="paqet_linux_amd64"
SYSTEMD_DIR="/etc/systemd/system"

############################################
# Utility helpers
############################################
die() {
  echo "ERROR: $1"
  exit 1
}

pause() {
  read -rp "Press Enter to continue..."
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

############################################
# Bootstrap
############################################
bootstrap() {
  echo "== Bootstrapping system =="

  if ! grep -qi ubuntu /etc/os-release; then
    die "Unsupported OS. Ubuntu only."
  fi

  apt update -y
  apt upgrade -y

  apt install -y \
    iproute2 \
    iptables \
    iptables-persistent \
    curl \
    tar

  mkdir -p "$BASE_DIR" "$CONFIG_DIR"

  if [ ! -f "$BASE_DIR/$BIN_NAME" ]; then
    echo "Downloading paqet binary..."
    curl -L "$BIN_URL" -o /tmp/paqet.tar.gz
    tar -xzf /tmp/paqet.tar.gz -C "$BASE_DIR"
    chmod +x "$BASE_DIR/$BIN_NAME"
  fi
}

############################################
# Detection helpers
############################################
detect_default_iface() {
  ip route show default | awk '{print $5}' | head -n1
}

detect_public_ipv4() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1 || true)
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return
  fi

  ip=$(hostname -I | awk '{print $1}' || true)
  [[ -n "$ip" ]] && echo "$ip"
}

detect_router_mac() {
  local iface="$1"
  local gw
  gw=$(ip route show default | awk '{print $3}' | head -n1)

  ping -c 1 -W 1 "$gw" >/dev/null 2>&1 || true

  ip neigh show dev "$iface" | awk '/REACHABLE/ {print $5; exit}' ||
  ip neigh show dev "$iface" | awk '{print $5; exit}' ||
  arp -n | awk '{print $3; exit}'
}

############################################
# Input helpers
############################################
confirm_or_manual() {
  local detected="$1"
  local label="$2"

  echo "Detected $label: $detected"
  echo "[1] Use detected value"
  echo "[2] Enter manually"
  read -rp "Choice: " c

  if [[ "$c" == "1" ]]; then
    echo "$detected"
  else
    read -rp "Enter $label manually: " manual
    echo "$manual"
  fi
}

validate_port() {
  local port="$1"

  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  (( port >= 1 && port <= 65535 )) || return 1
  ! ss -lntup | grep -q ":$port " || return 1

  return 0
}

############################################
# systemd helpers
############################################
create_service() {
  local name="$1"
  local cfg="$2"
  local role="$3"

  cat > "$SYSTEMD_DIR/paqet-$name.service" <<EOF
[Unit]
Description=Paqet $role ($name)
After=network.target

[Service]
Type=simple
ExecStart=$BASE_DIR/$BIN_NAME run -c $cfg
Restart=always
RestartSec=5
User=root
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "paqet-$name"
  systemctl restart "paqet-$name"
}

############################################
# IPTABLES (Server only)
############################################
apply_iptables() {
  local port="$1"

  iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || \
  iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK

  iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || \
  iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK

  iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || \
  iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP

  iptables -t filter -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
  iptables -t filter -A INPUT -p tcp --dport "$port" -j ACCEPT

  iptables -t filter -C OUTPUT -p tcp --sport "$port" -j ACCEPT 2>/dev/null || \
  iptables -t filter -A OUTPUT -p tcp --sport "$port" -j ACCEPT

  iptables-save > /etc/iptables/rules.v4
}

############################################
# Tunnel creation
############################################
create_tunnel() {
  echo "Select role:"
  echo "1) Iran (Client)"
  echo "2) Kharej (Server)"
  read -rp "Choice: " role_choice

  [[ "$role_choice" == "1" || "$role_choice" == "2" ]] || die "Invalid role"

  local role
  [[ "$role_choice" == "1" ]] && role="client" || role="server"

  read -rp "Enter tunnel name: " name
  [[ -f "$CONFIG_DIR/$name.yaml" ]] && die "Tunnel already exists"

  local iface ip mac
  iface=$(confirm_or_manual "$(detect_default_iface)" "interface")
  ip=$(confirm_or_manual "$(detect_public_ipv4)" "IPv4 address")
  mac=$(confirm_or_manual "$(detect_router_mac "$iface")" "router MAC")

  if [[ "$role" == "client" ]]; then
    local client_port server_port transport_port protocol server_ip key

    while true; do
      read -rp "Iran (Client) listen port: " client_port
      validate_port "$client_port" && break
      echo "Invalid or busy port"
    done

    read -rp "Kharej (Server) service port: " server_port

    while true; do
      read -rp "Transport port: " transport_port
      validate_port "$transport_port" && break
      echo "Invalid or busy port"
    done

    read -rp "Protocol [tcp/udp] (default tcp): " protocol
    protocol=${protocol:-tcp}

    read -rp "Kharej public IPv4: " server_ip
    read -rp "KCP secret key: " key

    cat > "$CONFIG_DIR/$name.yaml" <<EOF
role: "client"

log:
  level: "info"

forward:
  - listen: "0.0.0.0:$client_port"
    target: "127.0.0.1:$server_port"
    protocol: "$protocol"

network:
  interface: "$iface"
  ipv4:
    addr: "$ip:0"
    router_mac: "$mac"

server:
  addr: "$server_ip:$transport_port"

transport:
  protocol: "kcp"
  kcp:
    block: "aes"
    key: "$key"
EOF

    create_service "$name" "$CONFIG_DIR/$name.yaml" "Client"

  else
    local transport_port key

    while true; do
      read -rp "Transport port: " transport_port
      validate_port "$transport_port" && break
      echo "Invalid or busy port"
    done

    read -rp "KCP secret key: " key

    cat > "$CONFIG_DIR/$name.yaml" <<EOF
role: "server"

log:
  level: "info"

listen:
  addr: ":$transport_port"

network:
  interface: "$iface"
  ipv4:
    addr: "$ip:$transport_port"
    router_mac: "$mac"

transport:
  protocol: "kcp"
  kcp:
    block: "aes"
    key: "$key"
EOF

    apply_iptables "$transport_port"
    create_service "$name" "$CONFIG_DIR/$name.yaml" "Server"
  fi

  systemctl status "paqet-$name" --no-pager
}

############################################
# Main menu
############################################
bootstrap

while true; do
  clear
  echo "========== PAQET TUNNEL MANAGER =========="
  echo "1) Create new tunnel"
  echo "2) List tunnels"
  echo "3) Show tunnel status"
  echo "4) Restart tunnel"
  echo "5) Delete tunnel"
  echo "0) Exit"
  read -rp "Choice: " choice

  case "$choice" in
    1) create_tunnel; pause ;;
    2) ls "$CONFIG_DIR" | sed 's/.yaml$//' || true; pause ;;
    3) read -rp "Tunnel name: " t; systemctl status "paqet-$t" --no-pager || true; pause ;;
    4) read -rp "Tunnel name: " t; systemctl restart "paqet-$t"; pause ;;
    5) read -rp "Tunnel name: " t; systemctl stop "paqet-$t"; rm -f "$CONFIG_DIR/$t.yaml" "$SYSTEMD_DIR/paqet-$t.service"; systemctl daemon-reload; pause ;;
    0) exit 0 ;;
    *) echo "Invalid option"; pause ;;
  esac
done
