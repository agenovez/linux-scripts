#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# Pi-hole + Unbound + blocked-only persistent logging
# Autor: Adaptado para instalación limpia del proyecto Pi-hole
# Objetivo:
#   - Unbound como resolver recursivo local en 127.0.0.1:5335
#   - Pi-hole usando Unbound como único upstream
#   - Log DNS principal en RAM: /run/pihole/pihole.log
#   - Persistencia solo de consultas bloqueadas:
#       /var/log/pihole/blocked-only.log
#   - Rotación 90 días solo para blocked-only.log
# Para ejecutar forzando IPv6 apagado manualmente:
#    UNBOUND_IPV6=no sudo -E bash pihole-unbound-blocked-only-clean.sh
# Para modo automático, que es el recomendado:
#    UNBOUND_IPV6=auto sudo -E bash pihole-unbound-blocked-only-clean.sh
# ==========================================================

# --------------------------
# Variables principales
# --------------------------
UNBOUND_PORT="5335"
PIHOLE_UPSTREAM="127.0.0.1#5335"

RAM_LOG_DIR="/run/pihole"
RAM_DNSMASQ_LOG="/run/pihole/pihole.log"

PIHOLE_LOG_DIR="/var/log/pihole"
FTL_LOG="/var/log/pihole/FTL.log"
BLOCKED_ONLY_LOG="/var/log/pihole/blocked-only.log"

TMPFILES_CONF="/etc/tmpfiles.d/pihole-run.conf"
FTL_DROPIN_DIR="/etc/systemd/system/pihole-FTL.service.d"
FTL_DROPIN_FILE="/etc/systemd/system/pihole-FTL.service.d/10-run-log-path.conf"

BLOCKED_SERVICE="/etc/systemd/system/pihole-blocked-only-log.service"
LOGROTATE_CONF="/etc/logrotate.d/pihole-blocked-only"

UNBOUND_CONF="/etc/unbound/unbound.conf.d/pi-hole.conf"
ROOT_HINTS="/var/lib/unbound/root.hints"

BACKUP_DIR="/root/pihole-clean-backup-$(date +%F-%H%M%S)"

# Si desea que el script instale Pi-hole si no existe:
# Ejecute así:
#   INSTALL_PIHOLE_IF_MISSING=1 sudo -E bash pihole-unbound-blocked-only-clean.sh
INSTALL_PIHOLE_IF_MISSING="${INSTALL_PIHOLE_IF_MISSING:-0}"

# IPv6 en Unbound:
# Para su caso dejamos IPv6 desactivado por defecto porque así quedó estable.
# Cambie a "yes" solo si el servidor tiene IPv6 funcional.
UNBOUND_IPV6="${UNBOUND_IPV6:-no}"


# --------------------------
# Funciones auxiliares
# --------------------------
info() {
    echo -e "\n[INFO] $*"
}

ok() {
    echo "[OK] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Ejecute este script como root o con sudo."
    fi
}

backup_if_exists() {
    local item="$1"
    if [[ -e "$item" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$item" "$BACKUP_DIR"/
        ok "Backup creado de $item en $BACKUP_DIR"
    fi
}


# --------------------------
# Inicio
# --------------------------
require_root

info "Validando sistema base..."

if ! id pihole >/dev/null 2>&1; then
    warn "El usuario 'pihole' no existe todavía."
fi

if ! command -v pihole-FTL >/dev/null 2>&1; then
    if [[ "$INSTALL_PIHOLE_IF_MISSING" == "1" ]]; then
        info "Pi-hole no está instalado. Instalando Pi-hole usando el instalador oficial interactivo..."
        apt-get update
        apt-get install -y curl ca-certificates
        curl -sSL https://install.pi-hole.net | bash
    else
        die "Pi-hole no está instalado. Instale Pi-hole primero o ejecute:
INSTALL_PIHOLE_IF_MISSING=1 sudo -E bash $0"
    fi
fi

if ! id pihole >/dev/null 2>&1; then
    die "El usuario 'pihole' no existe. Verifique la instalación de Pi-hole."
fi

info "Creando backups de configuración relevante..."
backup_if_exists "/etc/pihole/pihole.toml"
backup_if_exists "$UNBOUND_CONF"
backup_if_exists "$TMPFILES_CONF"
backup_if_exists "$BLOCKED_SERVICE"
backup_if_exists "$LOGROTATE_CONF"


# --------------------------
# Paquetes necesarios
# --------------------------
info "Instalando paquetes necesarios..."
apt-get update
apt-get install -y \
    unbound \
    dnsutils \
    wget \
    ca-certificates \
    logrotate \
    procps

ok "Paquetes instalados."


# --------------------------
# Root hints para Unbound
# --------------------------
info "Descargando root hints para Unbound..."

mkdir -p /var/lib/unbound

if wget -q -O "$ROOT_HINTS" https://www.internic.net/domain/named.root; then
    chown unbound:unbound "$ROOT_HINTS"
    chmod 0644 "$ROOT_HINTS"
    ok "Root hints descargado en $ROOT_HINTS"
else
    warn "No se pudo descargar root.hints. Unbound puede funcionar con datos del paquete, pero revise conectividad."
fi


# --------------------------
# Configuración Unbound
# --------------------------
info "Configurando Unbound exclusivamente en 127.0.0.1:${UNBOUND_PORT}..."

# Respaldar toda la configuración de Unbound, no solo un archivo
backup_if_exists "/etc/unbound"

mkdir -p "$UNBOUND_CONF_DIR"
mkdir -p "$UNBOUND_DISABLED_DIR"

# Evitar configuraciones residuales que puedan forzar ::1:53 o 0.0.0.0:53
# Se conserva root-auto-trust-anchor-file.conf si existe.
if compgen -G "${UNBOUND_CONF_DIR}/*.conf" > /dev/null; then
    find "$UNBOUND_CONF_DIR" -maxdepth 1 -type f -name "*.conf" \
        ! -name "root-auto-trust-anchor-file.conf" \
        -exec mv {} "$UNBOUND_DISABLED_DIR"/ \;
    ok "Configuraciones previas de Unbound movidas a: $UNBOUND_DISABLED_DIR"
fi

# Archivo principal limpio: solo incluye conf.d
cat > "$UNBOUND_MAIN_CONF" <<EOF
include-toplevel: "${UNBOUND_CONF_DIR}/*.conf"
EOF

cat > "$UNBOUND_CONF" <<EOF
server:
    verbosity: 0

    # IMPORTANTE:
    # Unbound NO debe escuchar en puerto 53.
    # Pi-hole usa :53 y Unbound queda como resolver interno en 127.0.0.1:${UNBOUND_PORT}.
    interface: 127.0.0.1
    port: ${UNBOUND_PORT}

    do-ip4: yes
    do-ip6: ${UNBOUND_IPV6_EFFECTIVE}
    prefer-ip6: no

    do-udp: yes
    do-tcp: yes

    access-control: 127.0.0.0/8 allow

    root-hints: "${ROOT_HINTS}"

    hide-identity: yes
    hide-version: yes

    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes

    use-caps-for-id: no
    edns-buffer-size: 1232

    prefetch: yes
    prefetch-key: yes
    qname-minimisation: yes
    aggressive-nsec: yes

    rrset-cache-size: 256m
    msg-cache-size: 128m

    cache-min-ttl: 60
    cache-max-ttl: 86400

    so-rcvbuf: 1m
    so-sndbuf: 1m

    num-threads: 2

    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
EOF

ok "Archivo Unbound generado: $UNBOUND_CONF"

info "Ajustando buffers del kernel para Unbound..."
cat > /etc/sysctl.d/99-pihole-unbound.conf <<EOF
net.core.rmem_max=1048576
net.core.wmem_max=1048576
EOF

sysctl --system >/dev/null || warn "No se pudo aplicar sysctl completamente. Revise manualmente."

info "Validando configuración de Unbound..."
unbound-checkconf

#MEJORAS
info "Validando que el puerto ${UNBOUND_PORT} no esté ocupado por otro proceso..."

if ss -lntup 2>/dev/null | grep -q ":${UNBOUND_PORT} "; then
    warn "El puerto TCP ${UNBOUND_PORT} ya aparece en uso:"
    ss -lntup | grep ":${UNBOUND_PORT} " || true
fi

if ss -lnup 2>/dev/null | grep -q ":${UNBOUND_PORT} "; then
    warn "El puerto UDP ${UNBOUND_PORT} ya aparece en uso:"
    ss -lnup | grep ":${UNBOUND_PORT} " || true
fi

systemctl reset-failed unbound || true
systemctl daemon-reload
systemctl enable unbound
systemctl restart unbound

ok "Unbound configurado y reiniciado."


# --------------------------
# Directorios y logs
# --------------------------
info "Preparando logs: temporal en RAM y persistente solo para bloqueados..."

install -d -o pihole -g pihole -m 0755 "$RAM_LOG_DIR"
touch "$RAM_DNSMASQ_LOG"
chown pihole:pihole "$RAM_DNSMASQ_LOG"
chmod 0644 "$RAM_DNSMASQ_LOG"

install -d -o pihole -g pihole -m 0755 "$PIHOLE_LOG_DIR"
touch "$FTL_LOG" "$BLOCKED_ONLY_LOG"
chown pihole:pihole "$FTL_LOG" "$BLOCKED_ONLY_LOG"
chmod 0644 "$FTL_LOG" "$BLOCKED_ONLY_LOG"

ok "Logs preparados."


# --------------------------
# tmpfiles: recrear /run/pihole al arrancar
# --------------------------
info "Creando tmpfiles.d para recrear /run/pihole en cada reinicio..."

cat > "$TMPFILES_CONF" <<EOF
d ${RAM_LOG_DIR} 0755 pihole pihole -
f ${RAM_DNSMASQ_LOG} 0644 pihole pihole -
EOF

systemd-tmpfiles --create "$TMPFILES_CONF"

ok "tmpfiles configurado."


# --------------------------
# Drop-in systemd para asegurar pihole.log antes de FTL
# --------------------------
info "Creando drop-in de systemd para asegurar que pihole.log exista antes de arrancar FTL..."

mkdir -p "$FTL_DROPIN_DIR"

cat > "$FTL_DROPIN_FILE" <<EOF
[Service]
ExecStartPre=/usr/bin/install -d -o pihole -g pihole -m 0755 ${RAM_LOG_DIR}
ExecStartPre=/usr/bin/touch ${RAM_DNSMASQ_LOG}
ExecStartPre=/usr/bin/chown pihole:pihole ${RAM_DNSMASQ_LOG}
ExecStartPre=/usr/bin/chmod 0644 ${RAM_DNSMASQ_LOG}
EOF

systemctl daemon-reload

ok "Drop-in aplicado para pihole-FTL."


# --------------------------
# Configuración Pi-hole FTL
# --------------------------
info "Configurando Pi-hole FTL..."

# Upstream único hacia Unbound
pihole-FTL --config dns.upstreams "[\"${PIHOLE_UPSTREAM}\"]"

# Log DNS principal en RAM
pihole-FTL --config files.log.dnsmasq "$RAM_DNSMASQ_LOG"

# Log FTL normal en disco; no es el log masivo de consultas
pihole-FTL --config files.log.ftl "$FTL_LOG"

# No conservar histórico masivo en DB
pihole-FTL --config database.maxDBdays 0

# Debe estar activo para generar el log temporal que filtraremos.
# La persistencia de permitidos no queda en disco porque el log está en /run.
pihole-FTL --config dns.queryLogging true

ok "FTL configurado."


# --------------------------
# Servicio blocked-only
# --------------------------
info "Creando servicio para guardar únicamente consultas bloqueadas..."

cat > "$BLOCKED_SERVICE" <<'EOF'
[Unit]
Description=Pi-hole blocked queries only logger
After=pihole-FTL.service
Requires=pihole-FTL.service

[Service]
Type=simple
ExecStart=/usr/bin/bash -lc 'exec /usr/bin/tail -n0 -F /run/pihole/pihole.log | /usr/bin/grep --line-buffered -Ei "gravity blocked|regex blacklisted|exact blacklisted|blocked during CNAME inspection|blocked|blacklisted" >> /var/log/pihole/blocked-only.log'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pihole-blocked-only-log.service

ok "Servicio blocked-only creado."


# --------------------------
# Logrotate para blocked-only
# --------------------------
info "Configurando logrotate por 90 días para blocked-only.log..."

cat > "$LOGROTATE_CONF" <<EOF
${BLOCKED_ONLY_LOG} {
    daily
    rotate 90
    compress
    missingok
    notifempty
    copytruncate
    create 0644 pihole pihole
}
EOF

ok "Logrotate configurado."


# --------------------------
# Reinicios
# --------------------------
info "Reiniciando servicios..."

systemctl restart unbound
systemctl restart pihole-FTL
systemctl restart pihole-blocked-only-log.service

ok "Servicios reiniciados."


# --------------------------
# Validaciones
# --------------------------
info "Validando puertos DNS..."
ss -lntup | grep -E ':53|:5335' || warn "No se observaron puertos 53/5335. Revise servicios."

info "Validando configuración actual de Pi-hole..."
echo "dns.upstreams:"
pihole-FTL --config dns.upstreams || true

echo "files.log.dnsmasq:"
pihole-FTL --config files.log.dnsmasq || true

echo "files.log.ftl:"
pihole-FTL --config files.log.ftl || true

echo "database.maxDBdays:"
pihole-FTL --config database.maxDBdays || true

info "Probando Unbound directamente..."
dig google.com @127.0.0.1 -p "$UNBOUND_PORT" +time=5 +tries=1 || warn "Falló prueba directa a Unbound con google.com"
dig dnssec.works @127.0.0.1 -p "$UNBOUND_PORT" +dnssec +time=5 +tries=1 || warn "Falló prueba DNSSEC válida contra Unbound"
dig fail01.dnssec.works @127.0.0.1 -p "$UNBOUND_PORT" +dnssec +time=5 +tries=1 || warn "Revise DNSSEC inválido contra Unbound"

info "Probando Pi-hole en puerto 53..."
dig google.com @127.0.0.1 -p 53 +time=5 +tries=1 || warn "Falló prueba contra Pi-hole en puerto 53"
dig fail01.dnssec.works @127.0.0.1 -p 53 +dnssec +time=5 +tries=1 || warn "Revise DNSSEC inválido contra Pi-hole"

info "Estado de servicios..."
systemctl --no-pager --full status unbound | sed -n '1,12p' || true
systemctl --no-pager --full status pihole-FTL | sed -n '1,12p' || true
systemctl --no-pager --full status pihole-blocked-only-log.service | sed -n '1,12p' || true

echo
echo "=========================================================="
echo "[FINALIZADO]"
echo "Pi-hole + Unbound + blocked-only logging configurado."
echo
echo "Log temporal de consultas:"
echo "  ${RAM_DNSMASQ_LOG}"
echo
echo "Log persistente solo de bloqueados:"
echo "  ${BLOCKED_ONLY_LOG}"
echo
echo "Upstream Pi-hole:"
echo "  ${PIHOLE_UPSTREAM}"
echo
echo "Backup de configuraciones previas:"
echo "  ${BACKUP_DIR}"
echo "=========================================================="
