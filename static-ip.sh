#!/usr/bin/env bash
set -Eeuo pipefail

# ubuntu-static-ip-ethernet-optimize.sh
# Ubuntu 24.04
#
# Purpose:
#   1. Convert the current DHCP IPv4/IPv6 address into persistent static Netplan config.
#   2. Apply persistent Ethernet optimization using ethtool + systemd.
#   3. Apply persistent sysctl network tuning.
#
# Usage:
#   sudo bash ubuntu-static-ip-ethernet-optimize.sh
#   sudo bash ubuntu-static-ip-ethernet-optimize.sh -i ens18
#   sudo bash ubuntu-static-ip-ethernet-optimize.sh -i ens18 -y
#   sudo bash ubuntu-static-ip-ethernet-optimize.sh --dry-run
#
# Recommended first run:
#   sudo bash ubuntu-static-ip-ethernet-optimize.sh -i ens18 --dry-run
#
# Then:
#   sudo bash ubuntu-static-ip-ethernet-optimize.sh -i ens18 -y

IFACE=""
APPLY_NOW="ask"
DRY_RUN="no"
DO_STATIC="yes"
DO_OPTIMIZE="yes"
DO_SYSCTL="yes"
DISABLE_CLOUD_INIT="yes"
TXQUEUELEN="10000"

usage() {
  cat <<EOF
Usage:
  sudo bash $0 [options]

Options:
  -i, --interface IFACE       Interface name, example: ens18, eno1, eth0
  -y, --yes                   Apply Netplan automatically
  --dry-run                   Show detected values but do not write changes
  --optimize-only             Only configure Ethernet optimization and sysctl tuning
  --static-only               Only configure static Netplan, no Ethernet optimization
  --no-sysctl                 Do not write sysctl tuning
  --keep-cloud-init           Do not disable cloud-init network regeneration
  --txqueuelen VALUE          Set interface txqueuelen, default: 10000
  -h, --help                  Show this help

Examples:
  sudo bash $0
  sudo bash $0 -i ens18
  sudo bash $0 -i ens18 -y
  sudo bash $0 -i ens18 --dry-run
  sudo bash $0 -i ens18 --optimize-only
EOF
}

die() {
  echo "[ERROR] $*" >&2
  exit 1
}

info() {
  echo "[INFO] $*"
}

warn() {
  echo "[WARN] $*"
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash $0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--interface)
      IFACE="${2:-}"
      [[ -n "$IFACE" ]] || die "Missing interface after $1"
      shift 2
      ;;
    -y|--yes)
      APPLY_NOW="yes"
      shift
      ;;
    --dry-run)
      DRY_RUN="yes"
      APPLY_NOW="no"
      shift
      ;;
    --optimize-only)
      DO_STATIC="no"
      DO_OPTIMIZE="yes"
      DO_SYSCTL="yes"
      shift
      ;;
    --static-only)
      DO_STATIC="yes"
      DO_OPTIMIZE="no"
      DO_SYSCTL="no"
      shift
      ;;
    --no-sysctl)
      DO_SYSCTL="no"
      shift
      ;;
    --keep-cloud-init)
      DISABLE_CLOUD_INIT="no"
      shift
      ;;
    --txqueuelen)
      TXQUEUELEN="${2:-}"
      [[ "$TXQUEUELEN" =~ ^[0-9]+$ ]] || die "Invalid txqueuelen value."
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

need_root

command -v ip >/dev/null 2>&1 || die "'ip' command not found."

if [[ "$DO_STATIC" == "yes" ]]; then
  command -v netplan >/dev/null 2>&1 || die "'netplan' command not found."
fi

# Detect interface
if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -o -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
fi

if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -o -6 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
fi

[[ -n "$IFACE" ]] || die "Could not auto-detect interface. Use: -i ens18"
ip link show dev "$IFACE" >/dev/null 2>&1 || die "Interface '$IFACE' does not exist."

TS="$(date +%Y%m%d-%H%M%S)"
SAFE_IFACE="$(echo "$IFACE" | sed 's/[^a-zA-Z0-9_.@-]/_/g')"

info "Interface: $IFACE"

# Detect IPv4
IPV4_ADDR="$(ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4; exit}' || true)"
GW4="$(ip -4 route show default dev "$IFACE" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' || true)"

# Detect IPv6 stable/global addresses, excluding temporary/deprecated/tentative
mapfile -t IPV6_ADDRS < <(
  ip -o -6 addr show dev "$IFACE" scope global 2>/dev/null \
  | awk '$0 !~ /temporary/ && $0 !~ /deprecated/ && $0 !~ /tentative/ && $0 !~ /dadfailed/ {print $4}' \
  | sort -u
)

GW6="$(ip -6 route show default dev "$IFACE" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' || true)"

# DNS detection
DNS_LIST=""

if command -v resolvectl >/dev/null 2>&1; then
  DNS_LIST="$(
    resolvectl dns "$IFACE" 2>/dev/null \
    | sed -E 's/^Link [0-9]+ \([^)]*\): //' \
    | xargs || true
  )"
fi

if [[ -z "$DNS_LIST" && -r /etc/resolv.conf ]]; then
  DNS_LIST="$(awk '/^nameserver / {print $2}' /etc/resolv.conf | xargs || true)"
fi

if [[ -z "$DNS_LIST" ]]; then
  warn "Could not detect DNS servers. Using Cloudflare fallback DNS."
  DNS_LIST="1.1.1.1 1.0.0.1 2606:4700:4700::1111 2606:4700:4700::1001"
fi

# Renderer detection. If not found, omit renderer and let Netplan use default.
RENDERER="$(
  grep -Rhs '^[[:space:]]*renderer:' /etc/netplan/*.yaml 2>/dev/null \
  | tail -n1 \
  | awk '{print $2}' \
  | tr -d '"' || true
)"

info "Detected IPv4 address: ${IPV4_ADDR:-none}"
info "Detected IPv4 gateway: ${GW4:-none}"

if [[ "${#IPV6_ADDRS[@]}" -gt 0 ]]; then
  info "Detected IPv6 address(es):"
  for ip6 in "${IPV6_ADDRS[@]}"; do
    echo "  - $ip6"
  done
else
  info "Detected IPv6 address(es): none"
fi

info "Detected IPv6 gateway: ${GW6:-none}"
info "Detected DNS: $DNS_LIST"
info "Detected Netplan renderer: ${RENDERER:-default}"

if [[ "$DO_STATIC" == "yes" ]]; then
  [[ -n "$IPV4_ADDR" || "${#IPV6_ADDRS[@]}" -gt 0 ]] || die "No global IPv4 or IPv6 address found on $IFACE."
fi

if [[ "$DRY_RUN" == "yes" ]]; then
  echo
  echo "[DRY-RUN] No changes were written."
  echo "[DRY-RUN] Static Netplan: $DO_STATIC"
  echo "[DRY-RUN] Ethernet optimization: $DO_OPTIMIZE"
  echo "[DRY-RUN] Sysctl tuning: $DO_SYSCTL"
  echo "[DRY-RUN] txqueuelen: $TXQUEUELEN"
  exit 0
fi

# Backup
BACKUP_DIR="/root/network-backup-${TS}"
mkdir -p "$BACKUP_DIR"

if [[ -d /etc/netplan ]]; then
  cp -a /etc/netplan "$BACKUP_DIR/netplan"
fi

if [[ -d /etc/cloud/cloud.cfg.d ]]; then
  mkdir -p "$BACKUP_DIR/cloud.cfg.d"
  cp -a /etc/cloud/cloud.cfg.d/. "$BACKUP_DIR/cloud.cfg.d/" 2>/dev/null || true
fi

if [[ -d /etc/systemd/system ]]; then
  cp -a "/etc/systemd/system/ethernet-optimize-${SAFE_IFACE}.service" "$BACKUP_DIR/" 2>/dev/null || true
fi

cp -a "/usr/local/sbin/ethernet-optimize-${SAFE_IFACE}.sh" "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/sysctl.d/99-network-performance.conf "$BACKUP_DIR/" 2>/dev/null || true

info "Backup created: $BACKUP_DIR"

# Disable cloud-init network regeneration
if [[ "$DO_STATIC" == "yes" && "$DISABLE_CLOUD_INIT" == "yes" && -d /etc/cloud/cloud.cfg.d ]]; then
  cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<'EOF'
network: {config: disabled}
EOF
  info "cloud-init network regeneration disabled."
fi

# Create Netplan static config
if [[ "$DO_STATIC" == "yes" ]]; then
  NETPLAN_FILE="/etc/netplan/99-static-${SAFE_IFACE}.yaml"

  {
    echo "network:"
    echo "  version: 2"

    if [[ -n "$RENDERER" ]]; then
      echo "  renderer: $RENDERER"
    fi

    echo "  ethernets:"
    echo "    $IFACE:"
    echo "      dhcp4: false"
    echo "      dhcp6: false"

    if [[ -n "$GW6" ]]; then
      echo "      accept-ra: false"
    else
      echo "      accept-ra: true"
    fi

    echo "      addresses:"

    if [[ -n "$IPV4_ADDR" ]]; then
      echo "        - \"$IPV4_ADDR\""
    fi

    for ip6 in "${IPV6_ADDRS[@]}"; do
      echo "        - \"$ip6\""
    done

    if [[ -n "$GW4" || -n "$GW6" ]]; then
      echo "      routes:"

      if [[ -n "$GW4" ]]; then
        echo "        - to: \"default\""
        echo "          via: \"$GW4\""
      fi

      if [[ -n "$GW6" ]]; then
        echo "        - to: \"default\""
        echo "          via: \"$GW6\""
        echo "          on-link: true"
      fi
    fi

    echo "      nameservers:"
    echo "        addresses:"
    for dns in $DNS_LIST; do
      echo "          - \"$dns\""
    done
  } > "$NETPLAN_FILE"

  chmod 600 "$NETPLAN_FILE"

  info "Netplan file created: $NETPLAN_FILE"
  info "Validating Netplan..."
  netplan generate
fi

# Install ethtool if needed
if [[ "$DO_OPTIMIZE" == "yes" ]]; then
  if ! command -v ethtool >/dev/null 2>&1; then
    info "Installing ethtool..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ethtool
  fi

  OPT_SCRIPT="/usr/local/sbin/ethernet-optimize-${SAFE_IFACE}.sh"
  OPT_SERVICE="/etc/systemd/system/ethernet-optimize-${SAFE_IFACE}.service"

  cat > "$OPT_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail

IFACE="$IFACE"
TXQUEUELEN="$TXQUEUELEN"

ip link show dev "\$IFACE" >/dev/null 2>&1 || exit 0

# Increase transmit queue length
ip link set dev "\$IFACE" txqueuelen "\$TXQUEUELEN" || true

command -v ethtool >/dev/null 2>&1 || exit 0

# Set RX/TX ring buffers to maximum supported values if available
MAX_RX=\$(
  ethtool -g "\$IFACE" 2>/dev/null \
  | awk '/Pre-set maximums:/,/Current hardware settings:/ {if(\$1=="RX:"){print \$2; exit}}' || true
)

MAX_TX=\$(
  ethtool -g "\$IFACE" 2>/dev/null \
  | awk '/Pre-set maximums:/,/Current hardware settings:/ {if(\$1=="TX:"){print \$2; exit}}' || true
)

if [[ "\${MAX_RX:-0}" =~ ^[0-9]+$ && "\$MAX_RX" -gt 0 ]]; then
  ethtool -G "\$IFACE" rx "\$MAX_RX" 2>/dev/null || true
fi

if [[ "\${MAX_TX:-0}" =~ ^[0-9]+$ && "\$MAX_TX" -gt 0 ]]; then
  ethtool -G "\$IFACE" tx "\$MAX_TX" 2>/dev/null || true
fi

# Enable useful offloads for throughput
for feature in rx tx sg tso gso gro; do
  ethtool -K "\$IFACE" "\$feature" on 2>/dev/null || true
done

# Disable LRO. Safer for routing, firewalling, bridges, and DNS servers.
ethtool -K "\$IFACE" lro off 2>/dev/null || true

# Adaptive interrupt coalescing if supported
ethtool -C "\$IFACE" adaptive-rx on adaptive-tx on 2>/dev/null || true

exit 0
EOF

  chmod +x "$OPT_SCRIPT"

  cat > "$OPT_SERVICE" <<EOF
[Unit]
Description=Persistent Ethernet optimization for $IFACE
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$OPT_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "ethernet-optimize-${SAFE_IFACE}.service"

  info "Ethernet optimization service enabled: ethernet-optimize-${SAFE_IFACE}.service"
fi

# Sysctl tuning
if [[ "$DO_SYSCTL" == "yes" ]]; then
  TCP_CC_LINE=""

  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    TCP_CC_LINE="net.ipv4.tcp_congestion_control = bbr"
  fi

  cat > /etc/sysctl.d/99-network-performance.conf <<EOF
# Network performance tuning generated by ubuntu-static-ip-ethernet-optimize.sh
# Generated: $TS

net.core.default_qdisc = fq_codel
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 250000
net.core.optmem_max = 65536

net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
$TCP_CC_LINE
EOF

  sysctl --system >/dev/null || true
  info "Sysctl tuning applied: /etc/sysctl.d/99-network-performance.conf"
fi

# Apply Netplan
if [[ "$DO_STATIC" == "yes" ]]; then
  if [[ "$APPLY_NOW" == "ask" ]]; then
    echo
    warn "Applying Netplan can disconnect SSH if the detected gateway/IP is wrong."
    read -r -p "Apply Netplan now? [y/N]: " ANSWER
    if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
      APPLY_NOW="yes"
    else
      APPLY_NOW="no"
    fi
  fi

  if [[ "$APPLY_NOW" == "yes" ]]; then
    if [[ -n "${SSH_CONNECTION:-}" && -t 0 ]]; then
      info "SSH session detected. Running: netplan try --timeout 120"
      netplan try --timeout 120
    else
      info "Applying Netplan..."
      netplan apply
    fi
    info "Netplan applied."
  else
    warn "Netplan was generated but not applied."
    echo "To apply manually:"
    echo "  sudo netplan try"
    echo "or:"
    echo "  sudo netplan apply"
  fi
fi

echo
echo "[OK] Finished."
echo
echo "Summary:"
echo "  Interface: $IFACE"
echo "  Backup: $BACKUP_DIR"
echo "  Static Netplan: $DO_STATIC"
echo "  Ethernet optimization: $DO_OPTIMIZE"
echo "  Sysctl tuning: $DO_SYSCTL"
echo
echo "Verify with:"
echo "  sudo netplan get"
echo "  ip addr show $IFACE"
echo "  ip route"
echo "  ip -6 route"
echo "  resolvectl status $IFACE"
echo "  ip link show $IFACE"
echo "  ethtool -g $IFACE"
echo "  ethtool -k $IFACE"
echo "  systemctl status ethernet-optimize-${SAFE_IFACE}.service --no-pager"
