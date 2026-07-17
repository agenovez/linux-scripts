#!/usr/bin/env bash
set -Eeuo pipefail

# static-ip-v2.sh
# Ubuntu 24.04 - reusable static IP + Ethernet optimization + IPv6 RA/watchdog fixes
#
# Purpose:
#   1. Convert the current DHCP IPv4/IPv6 address into persistent static Netplan config.
#   2. Keep IPv6 Router Advertisements enabled by default to avoid expiring RA/link-local gateway issues.
#   3. Add a persistent IPv6 watchdog that runs netplan apply only if IPv6 connectivity fails.
#   4. Apply persistent Ethernet optimization using ethtool + systemd.
#   5. Apply persistent sysctl network tuning.
#
# Recommended first run:
#   sudo bash static-ip-v2.sh -i ens18 --dry-run
#
# Apply:
#   sudo bash static-ip-v2.sh -i ens18 -y
#
# Optimization only:
#   sudo bash static-ip-v2.sh -i ens18 --optimize-only

IFACE=""
APPLY_NOW="ask"
DRY_RUN="no"
DO_STATIC="yes"
DO_OPTIMIZE="yes"
DO_SYSCTL="yes"
DO_WATCHDOG="auto"
DISABLE_CLOUD_INIT="yes"
TXQUEUELEN="10000"
IPV6_ACCEPT_RA="auto"
IPV6_WATCHDOG_TARGET="2606:4700:4700::1111"
IPV6_WATCHDOG_INTERVAL="1min"

usage() {
  cat <<USAGE
Usage:
  sudo bash $0 [options]

Options:
  -i, --interface IFACE          Interface name, example: ens18, eno1, eth0
  -y, --yes                      Apply Netplan automatically
  --dry-run                      Show detected values but do not write changes
  --optimize-only                Only configure Ethernet optimization, sysctl, and optional watchdog
  --static-only                  Only configure static Netplan; no Ethernet optimization or sysctl
  --no-sysctl                    Do not write sysctl tuning
  --no-optimize                  Do not configure Ethernet optimization
  --watchdog                     Force-enable IPv6 watchdog
  --no-watchdog                  Disable IPv6 watchdog
  --watchdog-target IPv6         IPv6 target for watchdog, default: 2606:4700:4700::1111
  --watchdog-interval INTERVAL   systemd timer interval, default: 1min
  --ipv6-accept-ra MODE          auto, true, or false. Default: auto
  --keep-cloud-init              Do not disable cloud-init network regeneration
  --txqueuelen VALUE             Set interface txqueuelen, default: 10000
  -h, --help                     Show this help

Examples:
  sudo bash $0 --dry-run
  sudo bash $0 -i ens18 --dry-run
  sudo bash $0 -i ens18 -y
  sudo bash $0 -i ens18 -y --watchdog
  sudo bash $0 -i ens18 -y --ipv6-accept-ra true
  sudo bash $0 -i ens18 --optimize-only
USAGE
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

is_ipv6() {
  [[ "$1" == *:* ]]
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
      DO_WATCHDOG="no"
      shift
      ;;
    --no-sysctl)
      DO_SYSCTL="no"
      shift
      ;;
    --no-optimize)
      DO_OPTIMIZE="no"
      shift
      ;;
    --watchdog)
      DO_WATCHDOG="yes"
      shift
      ;;
    --no-watchdog)
      DO_WATCHDOG="no"
      shift
      ;;
    --watchdog-target)
      IPV6_WATCHDOG_TARGET="${2:-}"
      [[ -n "$IPV6_WATCHDOG_TARGET" ]] || die "Missing IPv6 address after $1"
      shift 2
      ;;
    --watchdog-interval)
      IPV6_WATCHDOG_INTERVAL="${2:-}"
      [[ -n "$IPV6_WATCHDOG_INTERVAL" ]] || die "Missing interval after $1"
      shift 2
      ;;
    --ipv6-accept-ra)
      IPV6_ACCEPT_RA="${2:-}"
      [[ "$IPV6_ACCEPT_RA" =~ ^(auto|true|false)$ ]] || die "Invalid --ipv6-accept-ra value. Use: auto, true, false"
      shift 2
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
command -v awk >/dev/null 2>&1 || die "'awk' command not found."

if [[ "$DO_STATIC" == "yes" ]]; then
  command -v netplan >/dev/null 2>&1 || die "'netplan' command not found."
fi

# Detect default interface.
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

# Current IPv4 and gateway.
IPV4_ADDR="$(ip -o -4 addr show dev "$IFACE" scope global 2>/dev/null | awk '{print $4; exit}' || true)"
GW4="$(ip -4 route show default dev "$IFACE" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' || true)"

# Stable/global IPv6 addresses, excluding temporary/deprecated/tentative/dadfailed.
mapfile -t IPV6_ADDRS < <(
  ip -o -6 addr show dev "$IFACE" scope global 2>/dev/null \
  | awk '$0 !~ /temporary/ && $0 !~ /deprecated/ && $0 !~ /tentative/ && $0 !~ /dadfailed/ {print $4}' \
  | sort -u
)

IPV6_DEFAULT_ROUTE="$(ip -6 route show default dev "$IFACE" 2>/dev/null | head -n1 || true)"
GW6="$(printf '%s\n' "$IPV6_DEFAULT_ROUTE" | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' || true)"
IPV6_ROUTE_PROTO="$(printf '%s\n' "$IPV6_DEFAULT_ROUTE" | awk '{for(i=1;i<=NF;i++) if($i=="proto"){print $(i+1); exit}}' || true)"

RA_DETECTED="no"
if [[ "$IPV6_ROUTE_PROTO" == "ra" || "$GW6" == fe80:* || "$IPV6_DEFAULT_ROUTE" == *" proto ra "* ]]; then
  RA_DETECTED="yes"
fi

# DNS detection.
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

# Renderer detection. Safe with set -euo pipefail.
RENDERER="$(
  grep -Rhs '^[[:space:]]*renderer:' /etc/netplan/*.yaml 2>/dev/null \
  | tail -n1 \
  | awk '{print $2}' \
  | tr -d '"' || true
)"

# IPv6 RA policy.
if [[ "$IPV6_ACCEPT_RA" == "auto" ]]; then
  # Default to true when IPv6 is present. This prevents RA/link-local gateway expiration issues.
  if [[ "${#IPV6_ADDRS[@]}" -gt 0 || -n "$GW6" ]]; then
    ACCEPT_RA_VALUE="true"
  else
    ACCEPT_RA_VALUE="true"
  fi
else
  ACCEPT_RA_VALUE="$IPV6_ACCEPT_RA"
fi

# Watchdog policy.
if [[ "$DO_WATCHDOG" == "auto" ]]; then
  if [[ "${#IPV6_ADDRS[@]}" -gt 0 || -n "$GW6" ]]; then
    EFFECTIVE_WATCHDOG="yes"
  else
    EFFECTIVE_WATCHDOG="no"
  fi
else
  EFFECTIVE_WATCHDOG="$DO_WATCHDOG"
fi

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

info "Detected IPv6 default route: ${IPV6_DEFAULT_ROUTE:-none}"
info "Detected IPv6 gateway: ${GW6:-none}"
info "Detected IPv6 route proto: ${IPV6_ROUTE_PROTO:-none}"
info "Router Advertisement detected: $RA_DETECTED"
info "Netplan accept-ra value: $ACCEPT_RA_VALUE"
info "Detected DNS: $DNS_LIST"
info "Detected Netplan renderer: ${RENDERER:-default}"
info "IPv6 watchdog: $EFFECTIVE_WATCHDOG"

if [[ "$DO_STATIC" == "yes" ]]; then
  [[ -n "$IPV4_ADDR" || "${#IPV6_ADDRS[@]}" -gt 0 ]] || die "No global IPv4 or IPv6 address found on $IFACE."
fi

if [[ "$EFFECTIVE_WATCHDOG" == "yes" ]] && ! is_ipv6 "$IPV6_WATCHDOG_TARGET"; then
  die "Watchdog target must be an IPv6 address: $IPV6_WATCHDOG_TARGET"
fi

if [[ "$DRY_RUN" == "yes" ]]; then
  echo
  echo "[DRY-RUN] No changes were written."
  echo "[DRY-RUN] Static Netplan: $DO_STATIC"
  echo "[DRY-RUN] Ethernet optimization: $DO_OPTIMIZE"
  echo "[DRY-RUN] Sysctl tuning: $DO_SYSCTL"
  echo "[DRY-RUN] IPv6 watchdog: $EFFECTIVE_WATCHDOG"
  echo "[DRY-RUN] IPv6 watchdog target: $IPV6_WATCHDOG_TARGET"
  echo "[DRY-RUN] txqueuelen: $TXQUEUELEN"
  exit 0
fi

# Backup.
BACKUP_DIR="/root/network-backup-${TS}"
mkdir -p "$BACKUP_DIR"

if [[ -d /etc/netplan ]]; then
  cp -a /etc/netplan "$BACKUP_DIR/netplan"
fi

if [[ -d /etc/cloud/cloud.cfg.d ]]; then
  mkdir -p "$BACKUP_DIR/cloud.cfg.d"
  cp -a /etc/cloud/cloud.cfg.d/. "$BACKUP_DIR/cloud.cfg.d/" 2>/dev/null || true
fi

cp -a "/etc/systemd/system/ethernet-optimize-${SAFE_IFACE}.service" "$BACKUP_DIR/" 2>/dev/null || true
cp -a "/usr/local/sbin/ethernet-optimize-${SAFE_IFACE}.sh" "$BACKUP_DIR/" 2>/dev/null || true
cp -a "/etc/systemd/system/ipv6-netplan-watchdog-${SAFE_IFACE}.service" "$BACKUP_DIR/" 2>/dev/null || true
cp -a "/etc/systemd/system/ipv6-netplan-watchdog-${SAFE_IFACE}.timer" "$BACKUP_DIR/" 2>/dev/null || true
cp -a "/usr/local/sbin/ipv6-netplan-watchdog-${SAFE_IFACE}.sh" "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/sysctl.d/99-network-performance.conf "$BACKUP_DIR/" 2>/dev/null || true

info "Backup created: $BACKUP_DIR"

# Disable cloud-init network regeneration.
if [[ "$DO_STATIC" == "yes" && "$DISABLE_CLOUD_INIT" == "yes" && -d /etc/cloud/cloud.cfg.d ]]; then
  cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<'CLOUDINIT'
network: {config: disabled}
CLOUDINIT
  info "cloud-init network regeneration disabled."
fi

# Create Netplan static config.
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
    echo "      accept-ra: $ACCEPT_RA_VALUE"
    echo "      optional: true"
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
        echo "          metric: 100"
      fi

      if [[ -n "$GW6" ]]; then
        echo "        - to: \"default\""
        echo "          via: \"$GW6\""
        if [[ "$GW6" == fe80:* ]]; then
          echo "          on-link: true"
        fi
        echo "          metric: 90"
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

# Install ethtool if needed.
if [[ "$DO_OPTIMIZE" == "yes" ]]; then
  if ! command -v ethtool >/dev/null 2>&1; then
    info "Installing ethtool..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ethtool
  fi

  OPT_SCRIPT="/usr/local/sbin/ethernet-optimize-${SAFE_IFACE}.sh"
  OPT_SERVICE="/etc/systemd/system/ethernet-optimize-${SAFE_IFACE}.service"

  cat > "$OPT_SCRIPT" <<OPTSCRIPT
#!/usr/bin/env bash
set -euo pipefail

IFACE="$IFACE"
TXQUEUELEN="$TXQUEUELEN"

ip link show dev "\$IFACE" >/dev/null 2>&1 || exit 0

ip link set dev "\$IFACE" txqueuelen "\$TXQUEUELEN" || true

command -v ethtool >/dev/null 2>&1 || exit 0

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

for feature in rx tx sg tso gso gro; do
  ethtool -K "\$IFACE" "\$feature" on 2>/dev/null || true
done

# LRO stays disabled because it is safer for routing, bridging, firewalling, and DNS servers.
ethtool -K "\$IFACE" lro off 2>/dev/null || true

# Adaptive interrupt coalescing if supported.
ethtool -C "\$IFACE" adaptive-rx on adaptive-tx on 2>/dev/null || true

exit 0
OPTSCRIPT

  chmod +x "$OPT_SCRIPT"

  cat > "$OPT_SERVICE" <<OPTSERVICE
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
OPTSERVICE

  systemctl daemon-reload
  systemctl enable --now "ethernet-optimize-${SAFE_IFACE}.service"

  info "Ethernet optimization service enabled: ethernet-optimize-${SAFE_IFACE}.service"
fi

# IPv6 watchdog.
if [[ "$EFFECTIVE_WATCHDOG" == "yes" ]]; then
  WATCHDOG_SCRIPT="/usr/local/sbin/ipv6-netplan-watchdog-${SAFE_IFACE}.sh"
  WATCHDOG_SERVICE="/etc/systemd/system/ipv6-netplan-watchdog-${SAFE_IFACE}.service"
  WATCHDOG_TIMER="/etc/systemd/system/ipv6-netplan-watchdog-${SAFE_IFACE}.timer"

  cat > "$WATCHDOG_SCRIPT" <<WATCHDOGSCRIPT
#!/usr/bin/env bash
set -euo pipefail

IFACE="$IFACE"
TARGET="$IPV6_WATCHDOG_TARGET"
LOGTAG="ipv6-netplan-watchdog-$SAFE_IFACE"

ip link show dev "\$IFACE" >/dev/null 2>&1 || exit 0

# If IPv6 works, do nothing.
if ping -6 -I "\$IFACE" -c 2 -W 2 "\$TARGET" >/dev/null 2>&1; then
  exit 0
fi

logger -t "\$LOGTAG" "IPv6 check failed on \$IFACE to \$TARGET. Running netplan apply."

/usr/sbin/netplan apply || true

sleep 5

if ping -6 -I "\$IFACE" -c 2 -W 2 "\$TARGET" >/dev/null 2>&1; then
  logger -t "\$LOGTAG" "IPv6 recovered after netplan apply."
else
  logger -t "\$LOGTAG" "IPv6 still failing after netplan apply."
fi
WATCHDOGSCRIPT

  chmod +x "$WATCHDOG_SCRIPT"

  cat > "$WATCHDOG_SERVICE" <<WATCHDOGSERVICE
[Unit]
Description=IPv6 Netplan Watchdog for $IFACE
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$WATCHDOG_SCRIPT
WATCHDOGSERVICE

  cat > "$WATCHDOG_TIMER" <<WATCHDOGTIMER
[Unit]
Description=Run IPv6 Netplan Watchdog for $IFACE

[Timer]
OnBootSec=2min
OnUnitActiveSec=$IPV6_WATCHDOG_INTERVAL
AccuracySec=15s
Unit=ipv6-netplan-watchdog-${SAFE_IFACE}.service

[Install]
WantedBy=timers.target
WATCHDOGTIMER

  systemctl daemon-reload
  systemctl enable --now "ipv6-netplan-watchdog-${SAFE_IFACE}.timer"

  info "IPv6 watchdog timer enabled: ipv6-netplan-watchdog-${SAFE_IFACE}.timer"
fi

# Sysctl tuning.
if [[ "$DO_SYSCTL" == "yes" ]]; then
  TCP_CC_LINE=""

  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    TCP_CC_LINE="net.ipv4.tcp_congestion_control = bbr"
  fi

  cat > /etc/sysctl.d/99-network-performance.conf <<SYSCTL
# Network performance tuning generated by static-ip-v2.sh
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
SYSCTL

  sysctl --system >/dev/null || true
  info "Sysctl tuning applied: /etc/sysctl.d/99-network-performance.conf"
fi

# Apply Netplan.
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
echo "  Netplan accept-ra: $ACCEPT_RA_VALUE"
echo "  Ethernet optimization: $DO_OPTIMIZE"
echo "  Sysctl tuning: $DO_SYSCTL"
echo "  IPv6 watchdog: $EFFECTIVE_WATCHDOG"
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
echo "  systemctl status ipv6-netplan-watchdog-${SAFE_IFACE}.timer --no-pager"
echo "  journalctl -t ipv6-netplan-watchdog-${SAFE_IFACE} -n 50 --no-pager"
