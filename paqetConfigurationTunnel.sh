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


# Enable extra debug logs for router MAC detection (0 = off, 1 = on)
DEBUG_ROUTER_MAC=1

debug_router_log() {
  if [[ "${DEBUG_ROUTER_MAC}" == "1" ]]; then
    # send to stderr so it doesn't break menus
    echo "[DEBUG][router-mac] $*" >&2
  fi
}


PAQET_BIN="/root/paqet/paqet_linux_amd64"

check_paqet_binary() {
  echo "== Checking paqet binary =="

  # 1) Check existence
  if [[ ! -f "${PAQET_BIN}" ]]; then
    echo "ERROR: paqet binary not found at: ${PAQET_BIN}"
    echo "Make sure you have built or copied the correct 'paqet_linux_amd64' binary to this path."
    exit 1
  fi

  # 2) Check executability
  if [[ ! -x "${PAQET_BIN}" ]]; then
    echo "INFO: paqet binary is not executable. Fixing permissions..."
    chmod +x "${PAQET_BIN}" || {
      echo "ERROR: failed to chmod +x ${PAQET_BIN}"
      exit 1
    }
  fi

  # 3) Try a lightweight run and capture output + exit code
  # We use a harmless flag (help). If paqet supports 'version' you can swap to that.
  local output
  if ! output=$("${PAQET_BIN}" --help 2>&1 </dev/null | head -n 10); then
    # Any non-zero exit: inspect for GLIBC or other fatal issues
    if echo "${output}" | grep -q "GLIBC_"; then
      echo "ERROR: paqet binary is not compatible with this system's glibc."
      echo "Detected error:"
      echo "----------------------------------------"
      echo "${output}"
      echo "----------------------------------------"
      echo "You must rebuild paqet on this OS (Ubuntu 20.04) or copy a compatible 'paqet_linux_amd64' binary here."
      exit 1
    fi

    echo "ERROR: paqet binary failed to run correctly."
    echo "Output:"
    echo "----------------------------------------"
    echo "${output}"
    echo "----------------------------------------"
    echo "Fix the binary and try again."
    exit 1
  fi

  # 4) If we reach here, binary at least runs on this system
  echo "paqet binary seems to be compatible and runnable on this system."
  echo
}



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

print_step() {
  local title="$1"
  echo
  echo "----------------------------------------"
  echo "$title"
  echo "----------------------------------------"
  echo
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

  # Prefer existing binary over download (for filtered environments)
  if [ -f "$BASE_DIR/$BIN_NAME" ]; then
    echo "Found paqet binary in $BASE_DIR, skipping download."
  elif [ -f "/root/$BIN_NAME" ]; then
    echo "Found paqet binary in /root, moving to $BASE_DIR..."
    mv "/root/$BIN_NAME" "$BASE_DIR/$BIN_NAME"
    chmod +x "$BASE_DIR/$BIN_NAME"
  else
    echo "Downloading paqet binary from GitHub..."
    if ! curl -L "$BIN_URL" -o /tmp/paqet.tar.gz; then
      die "Failed to download paqet binary. Place $BIN_NAME in /root and rerun this script."
    fi
    tar -xzf /tmp/paqet.tar.gz -C "$BASE_DIR"
    chmod +x "$BASE_DIR/$BIN_NAME"
  fi
}

############################################
# Detection helpers
############################################
detect_default_iface() {
  ip route 2>/dev/null | awk '
    $1 == "default" {
      for (i = 1; i <= NF; i++) {
        if ($i == "dev" && (i+1) <= NF) {
          print $(i+1);
          exit;
        }
      }
    }
  '
}

detect_public_ipv4() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1 || true)
  if [[ -n "$ip" ]]; then
    echo "$ip"
    return
  fi

  ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  [[ -n "$ip" ]] && echo "$ip"
}

detect_router_mac() {
  local iface="$1"
  local gw mac i

  debug_router_log "detect_router_mac() called with iface=${iface}"

  # 1) Get default IPv4 gateway
  gw=$(ip route 2>/dev/null | awk '$1 == "default" {print $3; exit}')
  debug_router_log "ip route default gateway: '${gw}'"
  ip route 2>/dev/null | sed 's/^/[DEBUG][ip route] /' >&2

  if [[ -z "$gw" ]]; then
    debug_router_log "No default gateway found. Aborting auto-detection."
    return
  fi

  debug_router_log "Initial 'ip neigh show dev ${iface}':"
  ip neigh show dev "${iface}" 2>/dev/null | sed 's/^/[DEBUG][ip neigh initial] /' >&2

  # 2) Try to resolve MAC of the default gateway (up to 5 attempts)
  for i in {1..5}; do
    debug_router_log "Attempt #${i} to resolve MAC for gateway ${gw} on iface ${iface}"

    # warm ARP
    ping -c 1 -W 1 "${gw}" >/dev/null 2>&1 || debug_router_log "ping to gateway ${gw} failed or timed out"

    debug_router_log "'ip neigh show dev ${iface}' after ping attempt #${i}:"
    ip neigh show dev "${iface}" 2>/dev/null | sed "s/^/[DEBUG][ip neigh attempt ${i}] /" >&2

    # Generic parser: find gateway line, then look for 'lladdr' and take next field as MAC
    mac=$(
      ip neigh show dev "${iface}" 2>/dev/null \
        | awk -v gw="${gw}" '
          $1 == gw {
            for (i = 2; i <= NF; i++) {
              if ($i == "lladdr" && i + 1 <= NF) {
                print $(i + 1);
                exit;
              }
            }
          }'
    )

    debug_router_log "MAC candidate from gateway match on attempt #${i}: '${mac}'"

    if [[ -n "${mac}" ]]; then
      debug_router_log "Resolved router MAC from gateway entry: ${mac}"
      echo "${mac}"
      return
    fi

    sleep 1
  done

  debug_router_log "Failed to resolve MAC directly from gateway entry after retries."

  # 3) Fallback: any IPv4 neighbor with 'router' tag
  debug_router_log "Trying fallback: any IPv4 neighbor with 'router' tag on iface ${iface}"

  mac=$(
    ip neigh show dev "${iface}" 2>/dev/null \
      | awk '
        $1 ~ /^[0-9]+\./ && /router/ {
          for (i = 2; i <= NF; i++) {
            if ($i == "lladdr" && i + 1 <= NF) {
              print $(i + 1);
              exit;
            }
          }
        }'
  )

  debug_router_log "MAC candidate from 'router' tag fallback: '${mac}'"

  if [[ -n "${mac}" ]]; then
    debug_router_log "Resolved router MAC from 'router' tagged neighbor: ${mac}"
    echo "${mac}"
    return
  fi

  # 4) Fallback: any REACHABLE IPv4 neighbor
  debug_router_log "Trying fallback: any REACHABLE IPv4 neighbor on iface ${iface}"

  mac=$(
    ip neigh show dev "${iface}" 2>/dev/null \
      | awk '
        $1 ~ /^[0-9]+\./ && /REACHABLE/ {
          for (i = 2; i <= NF; i++) {
            if ($i == "lladdr" && i + 1 <= NF) {
              print $(i + 1);
              exit;
            }
          }
        }'
  )

  debug_router_log "MAC candidate from REACHABLE IPv4 fallback: '${mac}'"

  if [[ -n "${mac}" ]]; then
    debug_router_log "Resolved router MAC from REACHABLE IPv4 neighbor: ${mac}"
    echo "${mac}"
    return
  fi

  # 5) Fallback: first IPv4 neighbor
  debug_router_log "Trying fallback: first IPv4 neighbor on iface ${iface}"

  mac=$(
    ip neigh show dev "${iface}" 2>/dev/null \
      | awk '
        $1 ~ /^[0-9]+\./ {
          for (i = 2; i <= NF; i++) {
            if ($i == "lladdr" && i + 1 <= NF) {
              print $(i + 1);
              exit;
            }
          }
        }'
  )

  debug_router_log "MAC candidate from first IPv4 neighbor fallback: '${mac}'"

  if [[ -n "${mac}" ]]; then
    debug_router_log "Resolved router MAC from first IPv4 neighbor: ${mac}"
    echo "${mac}"
    return
  fi

  # 6) Last fallback: ARP table
  debug_router_log "Trying fallback: ARP table (arp -n)"

  mac=$(arp -n 2>/dev/null | awk 'NR==2 {print $3}')
  debug_router_log "MAC candidate from arp -n fallback: '${mac}'"

  if [[ -n "${mac}" ]]; then
    debug_router_log "Resolved router MAC from arp table: ${mac}"
    echo "${mac}"
    return
  fi

  debug_router_log "All router MAC detection attempts failed. Returning empty result."
}



############################################
# Input helpers
############################################
# Usage: confirm_or_manual VAR_NAME DETECTED LABEL
confirm_or_manual() {
  local var_name="$1"
  local detected="$2"
  local label="$3"
  local value
  local choice

  echo
  echo ">>> $label configuration"

  if [[ -z "$detected" ]]; then
    echo "No $label detected automatically."
    read -rp "Enter $label manually: " value
  else
    echo "Detected $label: $detected"
    echo "[1] Use detected value"
    echo "[2] Enter manually"
    read -rp "Choice [1/2]: " choice
    if [[ "$choice" == "1" ]]; then
      value="$detected"
    else
      read -rp "Enter $label manually: " value
    fi
  fi

  printf -v "$var_name" '%s' "$value"
}

validate_port() {
  local port="$1"

  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  (( port >= 1 && port <= 65535 )) || return 1

  if command_exists ss; then
    ! ss -lntup 2>/dev/null | grep -q ":$port " || return 1
  fi

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

  # raw table - bypass conntrack
  iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK

  iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK

  # prevent TCP RST
  iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP

  # ensure ACCEPT on filter table
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
  print_step "[STEP 1] Select role"
  echo "1) Iran (Client)"
  echo "2) Kharej (Server)"
  read -rp "Choice: " role_choice

  [[ "$role_choice" == "1" || "$role_choice" == "2" ]] || die "Invalid role"

  local role
  [[ "$role_choice" == "1" ]] && role="client" || role="server"

  print_step "[STEP 2] Tunnel name"
  read -rp "Enter tunnel name: " name
  [[ -z "$name" ]] && die "Tunnel name cannot be empty"
  [[ -f "$CONFIG_DIR/$name.yaml" ]] && die "Tunnel already exists"

  print_step "[STEP 3] Interface detection"
  local iface ip mac
  confirm_or_manual iface "$(detect_default_iface)" "interface"

  print_step "[STEP 4] IPv4 detection"
  confirm_or_manual ip "$(detect_public_ipv4)" "IPv4 address"

  print_step "[STEP 5] Router MAC detection"
  confirm_or_manual mac "$(detect_router_mac "$iface")" "router MAC"

  if [[ "$role" == "client" ]]; then
    print_step "[STEP 6] Ports and protocol (Client)"
    local client_port server_port transport_port protocol server_ip key

    while true; do
      read -rp "Iran (Client) listen port: " client_port
      if validate_port "$client_port"; then
        break
      fi
      echo "Invalid or busy port, try again."
    done

    read -rp "Kharej (Server) service port: " server_port

    while true; do
      read -rp "Transport port: " transport_port
      if validate_port "$transport_port"; then
        break
      fi
      echo "Invalid or busy port, try again."
    done

    read -rp "Protocol [tcp/udp] (default tcp): " protocol
    protocol=${protocol:-tcp}

    print_step "[STEP 7] Server IP and key (Client)"
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
    print_step "[STEP 6] Transport port and key (Server)"
    local transport_port key

    while true; do
      read -rp "Transport port: " transport_port
      if validate_port "$transport_port"; then
        break
      fi
      echo "Invalid or busy port, try again."
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

  echo
  echo "========== TUNNEL SUMMARY =========="
  echo "Tunnel name: $name"
  echo "Role: $role"
  echo "Interface: $iface"
  echo "IPv4: $ip"
  echo "Router MAC: $mac"
  echo
  echo "Service status:"
  systemctl status "paqet-$name" --no-pager || true
}

############################################
# Edit tunnel (recreate)
############################################
edit_tunnel() {
  read -rp "Tunnel name to edit: " t
  local cfg="$CONFIG_DIR/$t.yaml"
  local svc="$SYSTEMD_DIR/paqet-$t.service"

  [[ -f "$cfg" ]] || die "Config for tunnel '$t' does not exist"

  echo "This will recreate the tunnel '$t' from scratch."
  read -rp "Are you sure? [y/N]: " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || return 0

  systemctl stop "paqet-$t" 2>/dev/null || true
  rm -f "$cfg" "$svc"
  systemctl daemon-reload

  create_tunnel
}

############################################
# Main menu
############################################
check_paqet_binary
bootstrap

while true; do
  clear
  echo "========== PAQET TUNNEL MANAGER =========="
  echo "1) Create new tunnel"
  echo "2) List tunnels"
  echo "3) Show tunnel status"
  echo "4) Edit tunnel"
  echo "5) Restart tunnel"
  echo "6) Delete tunnel"
  echo "0) Exit"
  read -rp "Choice: " choice

  case "$choice" in
    1)
      create_tunnel
      pause
      ;;
    2)
      echo
      echo "Existing tunnels:"
      if ls "$CONFIG_DIR"/*.yaml >/dev/null 2>&1; then
        ls "$CONFIG_DIR"/*.yaml | xargs -n1 basename | sed 's/\.yaml$//'
      else
        echo "(none)"
      fi
      pause
      ;;
    3)
      read -rp "Tunnel name: " t
      echo
      systemctl status "paqet-$t" --no-pager || echo "Service paqet-$t not found"
      pause
      ;;
    4)
      edit_tunnel
      pause
      ;;
    5)
      read -rp "Tunnel name: " t
      systemctl restart "paqet-$t" || echo "Failed to restart paqet-$t"
      pause
      ;;
    6)
      read -rp "Tunnel name: " t
      systemctl stop "paqet-$t" 2>/dev/null || true
      rm -f "$CONFIG_DIR/$t.yaml" "$SYSTEMD_DIR/paqet-$t.service"
      systemctl daemon-reload
      echo "Tunnel '$t' removed (if it existed)."
      pause
      ;;
    0)
      exit 0
      ;;
    *)
      echo "Invalid option"
      pause
      ;;
  esac
done
