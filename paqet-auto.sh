#!/usr/bin/env bash
# paqet-auto.sh
# Auto-generate Paqet client/server configs from udp2raw systemd services
# Modes:
#   --mode=iran    : process udp2raw client services (IR side)
#   --mode=kharej  : process udp2raw server service (foreign side)

set -euo pipefail

############################################
# Global config
############################################

BASE_DIR="/root/paqet"
CONFIG_DIR="$BASE_DIR/configs"
BIN_NAME="paqet_linux_amd64"
BIN_PATH="$BASE_DIR/$BIN_NAME"

DEBUG_ROUTER_MAC=0

DECOMM_UDP2RAW="no"
DECOMM_BACKHAUL="no"
MODE=""
ONLY_SERVICE=""

############################################
# Logging helpers
############################################

log_info()  { echo "[INFO]  $*"; }
log_warn()  { echo "[WARN]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }
die()       { log_error "$*"; exit 1; }

debug_router_log() {
  if [[ "$DEBUG_ROUTER_MAC" == "1" ]]; then
    echo "[DEBUG][router-mac] $*" >&2
  fi
}

############################################
# Arg parsing
############################################

usage() {
  cat <<EOF
Usage: $0 --mode=iran|kharej [--only=<service-name>] [--decommission-udp2raw=yes|no] [--decommission-backhaul=yes|no]

Examples:
  $0 --mode=iran
  $0 --mode=iran --only=udp2raw5186.service
  $0 --mode=kharej --decommission-udp2raw=yes
EOF
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode=*)
        MODE="${1#*=}"
        ;;
      --mode)
        shift
        MODE="${1:-}"
        ;;
      --only=*)
        ONLY_SERVICE="${1#*=}"
        ;;
      --only)
        shift
        ONLY_SERVICE="${1:-}"
        ;;
      --decommission-udp2raw=*)
        DECOMM_UDP2RAW="${1#*=}"
        ;;
      --decommission-udp2raw)
        shift
        DECOMM_UDP2RAW="${1:-}"
        ;;
      --decommission-backhaul=*)
        DECOMM_BACKHAUL="${1#*=}"
        ;;
      --decommission-backhaul)
        shift
        DECOMM_BACKHAUL="${1:-}"
        ;;
      -h|--help)
        usage
        ;;
      *)
        log_warn "Unknown argument: $1"
        usage
        ;;
    esac
    shift
  done

  [[ -z "$MODE" ]] && usage
  if [[ "$MODE" != "iran" && "$MODE" != "kharej" ]]; then
    die "Invalid --mode value: $MODE (expected iran|kharej)"
  fi

  case "$DECOMM_UDP2RAW" in
    yes|no|"") ;;
    *) die "Invalid --decommission-udp2raw value: $DECOMM_UDP2RAW (expected yes|no)" ;;
  esac

  case "$DECOMM_BACKHAUL" in
    yes|no|"") ;;
    *) die "Invalid --decommission-backhaul value: $DECOMM_BACKHAUL (expected yes|no)" ;;
  esac

  [[ -z "$DECOMM_UDP2RAW" ]] && DECOMM_UDP2RAW="no"
  [[ -z "$DECOMM_BACKHAUL" ]] && DECOMM_BACKHAUL="no"

  if [[ -n "$ONLY_SERVICE" && "$ONLY_SERVICE" != *.service ]]; then
    ONLY_SERVICE="${ONLY_SERVICE}.service"
  fi
}

############################################
# Bootstrap (OS + deps + paqet binary)
############################################

bootstrap_system() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must be run as root."
  fi

  if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
    log_warn "Non-Ubuntu system detected; proceeding but dependencies may fail."
  fi

  log_info "Ensuring required packages are installed..."
  apt-get update -y >/dev/null 2>&1 || log_warn "apt-get update failed (continuing)"
  apt-get install -y iproute2 iptables iptables-persistent curl tar >/dev/null 2>&1 || \
    log_warn "apt-get install failed for some packages (continuing)"

  mkdir -p "$BASE_DIR" "$CONFIG_DIR"

  if [[ -x "$BIN_PATH" ]]; then
    log_info "Found paqet binary at $BIN_PATH"
    return
  fi

  # Try to reuse existing binary in /root or current directory
  if [[ -x "/root/$BIN_NAME" ]]; then
    log_info "Found $BIN_NAME in /root, moving to $BASE_DIR"
    mv "/root/$BIN_NAME" "$BIN_PATH"
    chmod +x "$BIN_PATH"
    return
  fi

  if [[ -x "./$BIN_NAME" ]]; then
    log_info "Found $BIN_NAME in current directory, moving to $BASE_DIR"
    mv "./$BIN_NAME" "$BIN_PATH"
    chmod +x "$BIN_PATH"
    return
  fi

  # Fallback: download from GitHub
  local BIN_URL="https://github.com/hanselime/paqet/releases/download/v1.0.0-alpha.14/paqet-linux-amd64-v1.0.0-alpha.14.tar.gz"
  log_info "Downloading Paqet binary from GitHub..."
  if ! curl -L "$BIN_URL" -o /tmp/paqet.tar.gz; then
    die "Failed to download Paqet binary from $BIN_URL. Place $BIN_NAME in /root and rerun."
  fi
  tar -xzf /tmp/paqet.tar.gz -C "$BASE_DIR"
  rm -f /tmp/paqet.tar.gz

  if [[ ! -f "$BIN_PATH" ]]; then
    die "Extracted archive but $BIN_NAME not found in $BASE_DIR"
  fi

  chmod +x "$BIN_PATH"
  log_info "Paqet binary installed to $BIN_PATH"
}

check_paqet_binary() {
  log_info "Verifying Paqet binary at $BIN_PATH"

  if [[ ! -x "$BIN_PATH" ]]; then
    die "Paqet binary not executable at $BIN_PATH"
  fi

  local output
  if ! output=$("$BIN_PATH" --help 2>&1 | head -n 10); then
    if echo "$output" | grep -q "GLIBC_"; then
      die "Paqet binary is not compatible with this system's glibc: $output"
    fi
    die "Paqet binary failed to run: $output"
  fi
  log_info "Paqet binary seems runnable."
}

############################################
# Detection helpers (iface, IP, router MAC)
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

  gw=$(ip route 2>/dev/null | awk '$1 == "default" {print $3; exit}')
  debug_router_log "ip route default gateway: '${gw}'"
  ip route 2>/dev/null | sed 's/^/[DEBUG][ip route] /' >&2 || true

  if [[ -z "$gw" ]]; then
    debug_router_log "No default gateway found. Aborting auto-detection."
    return
  fi

  debug_router_log "Initial 'ip neigh show dev ${iface}':"
  ip neigh show dev "${iface}" 2>/dev/null | sed 's/^/[DEBUG][ip neigh initial] /' >&2 || true

  for i in {1..5}; do
    debug_router_log "Attempt #${i} to resolve MAC for gateway ${gw} on iface ${iface}"
    ping -c 1 -W 1 "${gw}" >/dev/null 2>&1 || debug_router_log "ping to gateway ${gw} failed or timed out"

    debug_router_log "'ip neigh show dev ${iface}' after ping attempt #${i}:"
    ip neigh show dev "${iface}" 2>/dev/null | sed "s/^/[DEBUG][ip neigh attempt ${i}] /" >&2 || true

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
    echo "${mac}"
    return
  fi

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
    echo "${mac}"
    return
  fi

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
    echo "${mac}"
    return
  fi

  mac=$(arp -n 2>/dev/null | awk 'NR==2 {print $3}')
  debug_router_log "MAC candidate from arp -n fallback: '${mac}'"

  if [[ -n "${mac}" ]]; then
    echo "${mac}"
    return
  fi

  debug_router_log "All router MAC detection attempts failed. Returning empty result."
}

############################################
# Port usage check
############################################

is_port_in_use() {
  local port="$1"
  # Check both TCP and UDP listeners
  if command -v ss >/dev/null 2>&1; then
    if ss -ltnup 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
      return 0
    fi
    if ss -lunp 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
      return 0
    fi
  else
    if netstat -ltnup 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
      return 0
    fi
    if netstat -lunp 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
      return 0
    fi
  fi
  return 1
}

############################################
# iptables tuning for server port (optional)
############################################

apply_iptables_server_port() {
  local port="$1"

  # raw table - bypass conntrack
  iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK || true

  iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK || true

  iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || \
    iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP || true

  iptables -t filter -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
    iptables -t filter -A INPUT -p tcp --dport "$port" -j ACCEPT || true

  iptables -t filter -C OUTPUT -p tcp --sport "$port" -j ACCEPT 2>/dev/null || \
    iptables -t filter -A OUTPUT -p tcp --sport "$port" -j ACCEPT || true

  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

############################################
# Parse udp2raw ExecStart
############################################
# Outputs via global vars:
#   PARSED_ROLE      (client|server)
#   PARSED_LPORT     (listen port)
#   PARSED_RIP       (remote IP)
#   PARSED_RPORT     (remote port)
#   PARSED_KEY
#   PARSED_RAW_MODE  (icmp|udp|faketcp|""|other)

PARSED_ROLE=""
PARSED_LPORT=""
PARSED_RIP=""
PARSED_RPORT=""
PARSED_KEY=""
PARSED_RAW_MODE=""

reset_parsed_vars() {
  PARSED_ROLE=""
  PARSED_LPORT=""
  PARSED_RIP=""
  PARSED_RPORT=""
  PARSED_KEY=""
  PARSED_RAW_MODE=""
}

parse_udp2raw_service() {
  local svc="$1"
  reset_parsed_vars

  if ! systemctl list-unit-files "$svc" >/dev/null 2>&1 && \
     ! systemctl status "$svc" >/dev/null 2>&1; then
    log_warn "Service $svc not found."
    return 1
  fi

  local exec_line
  exec_line=$(systemctl show -p ExecStart --value "$svc" 2>/dev/null || true)
  if [[ -z "$exec_line" ]]; then
    log_warn "Service $svc has empty ExecStart."
    return 1
  fi

  # systemd ExecStart may contain multiple commands separated by ';'
  # take the first command
  exec_line="${exec_line%%;*}"

  local want_l=0 want_r=0 want_k=0 want_rm=0
  local token val

  for token in $exec_line; do
    if [[ "$want_l" -eq 1 ]]; then
      val="$token"
      want_l=0
      [[ -n "$val" ]] && LADDR="$val"
      continue
    fi
    if [[ "$want_r" -eq 1 ]]; then
      val="$token"
      want_r=0
      [[ -n "$val" ]] && RADDR="$val"
      continue
    fi
    if [[ "$want_k" -eq 1 ]]; then
      val="$token"
      want_k=0
      [[ -n "$val" ]] && PARSED_KEY="$val"
      continue
    fi
    if [[ "$want_rm" -eq 1 ]]; then
      val="$token"
      want_rm=0
      [[ -n "$val" ]] && PARSED_RAW_MODE="$val"
      continue
    fi

    case "$token" in
      -c)
        PARSED_ROLE="client"
        ;;
      -s)
        PARSED_ROLE="server"
        ;;
      -l)
        want_l=1
        ;;
      -l*)
        val="${token#-l}"
        [[ -n "$val" ]] && LADDR="$val"
        ;;
      -r)
        want_r=1
        ;;
      -r*)
        val="${token#-r}"
        [[ -n "$val" ]] && RADDR="$val"
        ;;
      -k)
        want_k=1
        ;;
      -k*)
        val="${token#-k}"
        [[ -n "$val" ]] && PARSED_KEY="$val"
        ;;
      --raw-mode)
        want_rm=1
        ;;
      --raw-mode=*)
        val="${token#--raw-mode=}"
        [[ -n "$val" ]] && PARSED_RAW_MODE="$val"
        ;;
    esac
  done

  # Normalize raw-mode
  if [[ -n "$PARSED_RAW_MODE" ]]; then
    PARSED_RAW_MODE="$(echo "$PARSED_RAW_MODE" | tr 'A-Z' 'a-z')"
  fi

  # Extract ports/IP from LADDR/RADDR
  local LADDR="${LADDR:-}"
  local RADDR="${RADDR:-}"

  if [[ -n "$LADDR" ]]; then
    # Expect ip:port
    local lp="${LADDR##*:}"
    if [[ "$lp" =~ ^[0-9]+$ ]]; then
      PARSED_LPORT="$lp"
    fi
  fi

  if [[ -n "$RADDR" ]]; then
    # Could be "IP:PORT" or "\"IP\":PORT"
    local cleaned="$RADDR"
    cleaned="${cleaned%\"}"
    cleaned="${cleaned#\"}"
    local rip="${cleaned%:*}"
    local rp="${cleaned##*:}"
    if [[ "$rp" =~ ^[0-9]+$ ]]; then
      PARSED_RIP="$rip"
      PARSED_RPORT="$rp"
    fi
  fi

  # Basic validation
  local malformed_reason=""

  if [[ -z "$PARSED_ROLE" ]]; then
    malformed_reason="missing role (-c/-s)"
  elif [[ -z "$PARSED_LPORT" ]]; then
    malformed_reason="missing or invalid -l listen address"
  elif [[ -z "$PARSED_RIP" || -z "$PARSED_RPORT" ]]; then
    malformed_reason="missing or invalid -r remote address"
  elif [[ -z "$PARSED_KEY" ]]; then
    malformed_reason="missing -k key"
  fi

  if [[ -n "$malformed_reason" ]]; then
    log_warn "Service $svc malformed: $malformed_reason"
    return 1
  fi

  return 0
}

############################################
# Cron auto-comment helper
############################################

comment_cron_lines_matching() {
  local pattern="$1"

  if ! command -v crontab >/dev/null 2>&1; then
    log_warn "crontab command not found; skipping cron modifications for pattern '$pattern'."
    return
  fi

  local tmp
  tmp=$(mktemp)

  if ! crontab -l 2>/dev/null >"$tmp.orig"; then
    rm -f "$tmp.orig" "$tmp"
    log_info "No existing crontab for root; nothing to modify for pattern '$pattern'."
    return
  fi

  awk -v pat="$pattern" '
    BEGIN{}
    {
      line=$0
      # Already commented or PAQET_AUTO tagged
      if (line ~ /^[[:space:]]*#/ ) {
        print line
      }
      else if (index(line, pat) > 0) {
        print "# [PAQET_AUTO] " line
      } else {
        print line
      }
    }
  ' "$tmp.orig" >"$tmp"

  crontab "$tmp" || log_warn "Failed to install modified crontab."
  rm -f "$tmp" "$tmp.orig"
}

############################################
# Iran mode (client side)
############################################

process_iran() {
  log_info "Running in IRAN mode (client)."

  local services=()

  if [[ -n "$ONLY_SERVICE" ]]; then
    services+=("$ONLY_SERVICE")
  else
    # Collect udp2raw*.service under /etc/systemd/system
    while IFS= read -r path; do
      local name
      name="$(basename "$path")"
      services+=("$name")
    done < <(ls /etc/systemd/system/udp2raw*.service 2>/dev/null || true)
  fi

  if [[ "${#services[@]}" -eq 0 ]]; then
    log_warn "No udp2raw*.service found for IRAN mode."
  fi

  local iface ip mac
  iface="$(detect_default_iface || true)"
  ip="$(detect_public_ipv4 || true)"
  mac=""
  if [[ -n "$iface" ]]; then
    mac="$(detect_router_mac "$iface" || true)"
  fi

  if [[ -z "$iface" || -z "$ip" || -z "$mac" ]]; then
    log_warn "Failed to auto-detect iface/IP/router MAC (iface='$iface', ip='$ip', mac='$mac'). Some tunnels may fail."
  else
    log_info "Detected iface='$iface', ip='$ip', router_mac='$mac'"
  fi

  local svc
  for svc in "${services[@]}"; do
    log_info "Processing IR udp2raw service: $svc"

    if ! parse_udp2raw_service "$svc"; then
      log_warn "Skipping $svc due to malformed config."
      continue
    fi

    if [[ "$PARSED_ROLE" != "client" ]]; then
      log_warn "Service $svc role is '$PARSED_ROLE' (expected client); skipping in IRAN mode."
      continue
    fi

    local lport="$PARSED_LPORT"
    local rip="$PARSED_RIP"
    local rport="$PARSED_RPORT"
    local key="$PARSED_KEY"

    local tun_name="udp2raw${lport}"
    local cfg_path="$CONFIG_DIR/paqet-${tun_name}.yaml"
    local svc_name="paqet-${tun_name}.service"

    if [[ -f "$cfg_path" ]]; then
      log_info "Config $cfg_path already exists; skipping creation for $svc."
    else
      if [[ -z "$iface" || -z "$ip" || -z "$mac" ]]; then
        log_warn "Missing iface/IP/MAC; cannot create Paqet config for $svc."
      else
        log_info "Creating Paqet client config for $svc at $cfg_path"

        cat >"$cfg_path" <<EOF
role: "client"

log:
  level: "info"

forward:
  - listen: "0.0.0.0:${lport}"
    target: "127.0.0.1:${lport}"
    protocol: "tcp"

network:
  interface: "${iface}"
  ipv4:
    addr: "${ip}:0"
    router_mac: "${mac}"

server:
  addr: "${rip}:${rport}"

transport:
  protocol: "kcp"
  kcp:
    block: "aes"
    key: "${key}"
EOF

        log_info "Creating systemd unit $svc_name"
        cat >"/etc/systemd/system/${svc_name}" <<EOF
[Unit]
Description=Paqet Client (${tun_name})
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} run -c ${cfg_path}
Restart=always
RestartSec=5
User=root
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable "$svc_name" >/dev/null 2>&1 || true
        systemctl restart "$svc_name" || log_warn "Failed to restart $svc_name"
      fi
    fi

    # Always stop/disable the corresponding udp2raw service after conversion attempt
    log_info "Disabling original udp2raw service $svc on IR side."
    systemctl stop "$svc"  >/dev/null 2>&1 || true
    systemctl disable "$svc" >/dev/null 2>&1 || true
  done
}

############################################
# Kharej mode (server side)
############################################

process_kharej() {
  log_info "Running in KHAREJ mode (server)."

  local services=()

  if [[ -n "$ONLY_SERVICE" ]]; then
    services+=("$ONLY_SERVICE")
  else
    # Default: udp2raw.service
    services+=("udp2raw.service")
  fi

  local iface ip mac
  iface="$(detect_default_iface || true)"
  ip="$(detect_public_ipv4 || true)"
  mac=""
  if [[ -n "$iface" ]]; then
    mac="$(detect_router_mac "$iface" || true)"
  fi

  if [[ -z "$iface" || -z "$ip" || -z "$mac" ]]; then
    log_warn "Failed to auto-detect iface/IP/router MAC (iface='$iface', ip='$ip', mac='$mac'). Some tunnels may fail."
  else
    log_info "Detected iface='$iface', ip='$ip', router_mac='$mac'"
  fi

  local svc
  for svc in "${services[@]}"; do
    log_info "Processing KHAREJ udp2raw service: $svc"

    if ! parse_udp2raw_service "$svc"; then
      log_warn "Skipping $svc due to malformed config."
      continue
    fi

    if [[ "$PARSED_ROLE" != "server" ]]; then
      log_warn "Service $svc role is '$PARSED_ROLE' (expected server); skipping in KHAREJ mode."
      continue
    fi

    local lport="$PARSED_LPORT"       # transport port (server listen)
    local key="$PARSED_KEY"
    local raw_mode="$PARSED_RAW_MODE"

    local tun_name="udp2raw${lport}"
    local cfg_path="$CONFIG_DIR/paqet-${tun_name}.yaml"
    local svc_name="paqet-${tun_name}.service"

    if [[ -f "$cfg_path" ]]; then
      log_info "Config $cfg_path already exists; skipping creation for $svc."
      continue
    fi

    if [[ -z "$iface" || -z "$ip" || -z "$mac" ]]; then
      log_warn "Missing iface/IP/MAC; cannot create Paqet config for $svc."
      continue
    fi

    local raw_desc="${raw_mode:-unknown}"
    log_info "Service $svc raw-mode='${raw_desc}', listen_port=${lport}"

    local is_icmp=0
    if [[ "$raw_mode" == "icmp" ]]; then
      is_icmp=1
    fi

    if [[ "$is_icmp" -eq 0 ]]; then
      # Non-ICMP: stop/disable udp2raw before binding the same port with Paqet
      log_info "Non-ICMP raw-mode: stopping and disabling $svc before creating Paqet server."
      systemctl stop "$svc"   >/dev/null 2>&1 || true
      systemctl disable "$svc" >/dev/null 2>&1 || true

      # extra safety: ensure port now free
      if is_port_in_use "$lport"; then
        log_warn "Transport port ${lport} still in use after stopping $svc; cannot create Paqet server for $tun_name."
        continue
      fi
    else
      # ICMP mode: udp2raw uses ICMP; Paqet can safely bind TCP/UDP on same port,
      # but we still avoid obvious collisions with other daemons
      if is_port_in_use "$lport"; then
        log_warn "Transport port ${lport} already in use by another process; cannot create Paqet server for $tun_name."
        continue
      fi
    fi

    log_info "Creating Paqet server config for $svc at $cfg_path"

    cat >"$cfg_path" <<EOF
role: "server"

log:
  level: "info"

listen:
  addr: ":${lport}"

network:
  interface: "${iface}"
  ipv4:
    addr: "${ip}:${lport}"
    router_mac: "${mac}"

transport:
  protocol: "kcp"
  kcp:
    block: "aes"
    key: "${key}"
EOF

    log_info "Creating systemd unit $svc_name"
    cat >"/etc/systemd/system/${svc_name}" <<EOF
[Unit]
Description=Paqet Server (${tun_name})
After=network.target

[Service]
Type=simple
ExecStart=${BIN_PATH} run -c ${cfg_path}
Restart=always
RestartSec=5
User=root
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$svc_name" >/dev/null 2>&1 || true
    systemctl restart "$svc_name" || log_warn "Failed to restart $svc_name"

    # Optional iptables tuning
    apply_iptables_server_port "$lport"
  done
}

############################################
# Decommission helpers
############################################

decommission_udp2raw() {
  if [[ "$DECOMM_UDP2RAW" != "yes" ]]; then
    return
  fi

  log_info "Decommissioning udp2raw services (global)."

  local candidates=("udp2raw.service" "udp2raw2.service")
  local s
  for s in "${candidates[@]}"; do
    if systemctl list-unit-files "$s" >/dev/null 2>&1; then
      log_info "Stopping and disabling $s"
      systemctl stop "$s"   >/dev/null 2>&1 || true
      systemctl disable "$s" >/dev/null 2>&1 || true
    fi
  done

  log_info "Auto-commenting cron lines containing 'udp2raw'"
  comment_cron_lines_matching "udp2raw"
}

decommission_backhaul() {
  if [[ "$DECOMM_BACKHAUL" != "yes" ]]; then
    return
  fi

  log_info "Decommissioning backhaul services."

  local path
  while IFS= read -r path; do
    local name
    name="$(basename "$path")"
    log_info "Stopping and disabling $name"
    systemctl stop "$name"   >/dev/null 2>&1 || true
    systemctl disable "$name" >/dev/null 2>&1 || true
  done < <(ls /etc/systemd/system/backhaul*.service 2>/dev/null || true)

  log_info "Auto-commenting cron lines containing 'backhaul'"
  comment_cron_lines_matching "backhaul"
}

############################################
# Main
############################################

main() {
  parse_args "$@"
  bootstrap_system
  check_paqet_binary

  case "$MODE" in
    iran)
      process_iran
      ;;
    kharej)
      process_kharej
      ;;
    *)
      die "Unknown mode: $MODE"
      ;;
  esac

  decommission_udp2raw
  decommission_backhaul

  log_info "Done."
}

main "$@"
