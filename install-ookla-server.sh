#!/usr/bin/env bash
#
# install-ookla-server.sh
# Clean, auditable installer for OoklaServer on Ubuntu with a native systemd unit.
#
# Default behavior:
#   - Creates a dedicated system account: ookla
#   - Installs into: /opt/ookla
#   - Creates/enables: ookla-server.service
#   - Runs OoklaServer in the foreground under systemd (no PID file required)
#   - Preserves the downloaded vendor installer and its SHA-256 digest
#   - Does NOT enable or reconfigure UFW unless --configure-ufw is supplied
#
# Usage:
#   sudo bash install-ookla-server.sh
#   sudo bash install-ookla-server.sh --configure-ufw
#   sudo bash install-ookla-server.sh --user ookla --install-dir /opt/ookla
#
# Official installer source:
#   https://install.speedtest.net/ooklaserver/ooklaserver.sh
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly SCRIPT_NAME="${0##*/}"
readonly INSTALLER_URL="https://install.speedtest.net/ooklaserver/ooklaserver.sh"
readonly DEFAULT_USER="ookla"
readonly DEFAULT_INSTALL_DIR="/opt/ookla"
readonly DEFAULT_SERVICE_NAME="ookla-server"
readonly AUDIT_ROOT="/var/lib/ookla-installer"
readonly LOCK_FILE="/run/lock/ookla-server-install.lock"

SERVICE_USER="$DEFAULT_USER"
SERVICE_GROUP=""
INSTALLER_PATH=""
INSTALL_DIR="$DEFAULT_INSTALL_DIR"
SERVICE_NAME="$DEFAULT_SERVICE_NAME"
CONFIGURE_UFW=0
FORCE=0
TMP_DIR=""
LOG_FILE=""
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

usage() {
    cat <<EOF
Usage: sudo bash ${SCRIPT_NAME} [options]

Options:
  --user NAME           Service account (default: ${DEFAULT_USER})
  --install-dir PATH    Installation directory (default: ${DEFAULT_INSTALL_DIR})
  --service-name NAME   systemd unit name without .service
                         (default: ${DEFAULT_SERVICE_NAME})
  --configure-ufw       Add inbound UFW rules for TCP/UDP 8080 and 5060.
                         This does not enable UFW if it is inactive.
  --force               Back up and replace an existing installation/unit.
  -h, --help            Show this help.

Examples:
  sudo bash ${SCRIPT_NAME}
  sudo bash ${SCRIPT_NAME} --configure-ufw
  sudo bash ${SCRIPT_NAME} --user ookla --install-dir /opt/ookla
EOF
}

log() {
    printf '%s [%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$1" "$2"
}

info() { log INFO "$*"; }
warn() { log WARN "$*" >&2; }
die()  { log ERROR "$*" >&2; exit 1; }

cleanup() {
    local rc=$?
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
    if (( rc != 0 )); then
        warn "Installation failed with exit code ${rc}. Review: ${LOG_FILE:-console output}"
    fi
}
trap cleanup EXIT
trap 'die "Unexpected error on line ${LINENO}: ${BASH_COMMAND}"' ERR

require_root() {
    [[ ${EUID} -eq 0 ]] || die "Run this script as root, for example: sudo bash ${SCRIPT_NAME}"
}

parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            --user)
                [[ $# -ge 2 ]] || die "--user requires a value"
                SERVICE_USER="$2"
                shift 2
                ;;
            --install-dir)
                [[ $# -ge 2 ]] || die "--install-dir requires a value"
                INSTALL_DIR="$2"
                shift 2
                ;;
            --service-name)
                [[ $# -ge 2 ]] || die "--service-name requires a value"
                SERVICE_NAME="${2%.service}"
                shift 2
                ;;
            --configure-ufw)
                CONFIGURE_UFW=1
                shift
                ;;
            --force)
                FORCE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
}

validate_inputs() {
    [[ "$SERVICE_USER" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] \
        || die "Invalid service user: ${SERVICE_USER}"

    [[ "$SERVICE_NAME" =~ ^[A-Za-z0-9_.@-]+$ ]] \
        || die "Invalid systemd service name: ${SERVICE_NAME}"

    [[ "$INSTALL_DIR" == /* ]] || die "--install-dir must be an absolute path"
    [[ "$INSTALL_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] \
        || die "--install-dir contains unsupported characters; use letters, numbers, dot, underscore, hyphen, and slash only"

    case "$INSTALL_DIR" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/root/*|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            die "Refusing unsafe installation directory: ${INSTALL_DIR}"
            ;;
    esac

    [[ "$INSTALL_DIR" != *$'\n'* ]] || die "Installation path contains an invalid newline"
}

initialize_logging() {
    install -d -o root -g root -m 0750 "$AUDIT_ROOT"
    LOG_FILE="${AUDIT_ROOT}/install-${TIMESTAMP}.log"
    touch "$LOG_FILE"
    chmod 0640 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
}

acquire_lock() {
    install -d -m 0755 "$(dirname "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Another OoklaServer installation is already running"
}

check_platform() {
    [[ -r /etc/os-release ]] || die "Cannot determine the operating system"
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || die "This script supports Ubuntu only; detected: ${ID:-unknown}"
    [[ -d /run/systemd/system ]] || die "systemd is not running on this server"

    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) ;;
        *) die "Unsupported or unverified architecture: ${arch}. This installer is restricted to x86-64 for predictable deployment." ;;
    esac

    info "Platform: ${PRETTY_NAME:-Ubuntu}; architecture: ${arch}; kernel: $(uname -r)"
}

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    info "Refreshing APT metadata"
    apt-get update -y

    local packages=(ca-certificates curl wget tar gzip file procps iproute2 util-linux)
    if (( CONFIGURE_UFW == 1 )); then
        packages+=(ufw)
    fi

    info "Installing required packages: ${packages[*]}"
    apt-get install -y --no-install-recommends "${packages[@]}"
}

backup_existing() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local backup_base="${AUDIT_ROOT}/backup-${TIMESTAMP}"
    local existing=0

    [[ -e "$INSTALL_DIR" ]] && existing=1
    [[ -e "$unit_file" || -L "$unit_file" ]] && existing=1

    (( existing == 0 )) && return 0

    if (( FORCE == 0 )); then
        die "An existing installation or unit was found. Re-run with --force to back it up and replace it."
    fi

    info "Existing deployment detected; creating backup under ${backup_base}"
    install -d -o root -g root -m 0750 "$backup_base"

    systemctl disable --now "${SERVICE_NAME}.service" 2>/dev/null || true

    if [[ -e "$INSTALL_DIR" ]]; then
        mv -- "$INSTALL_DIR" "${backup_base}/installation"
    fi

    if [[ -e "$unit_file" || -L "$unit_file" ]]; then
        cp -a -- "$unit_file" "${backup_base}/${SERVICE_NAME}.service"
        rm -f -- "$unit_file"
    fi

    systemctl daemon-reload
}

create_service_account() {
    if getent passwd "$SERVICE_USER" >/dev/null; then
        info "Service account already exists: ${SERVICE_USER}"
    else
        info "Creating dedicated system account: ${SERVICE_USER}"
        if getent group "$SERVICE_USER" >/dev/null; then
            useradd \
                --system \
                --gid "$SERVICE_USER" \
                --home-dir "$INSTALL_DIR" \
                --shell /usr/sbin/nologin \
                --comment "Ookla Speedtest Server" \
                "$SERVICE_USER"
        else
            useradd \
                --system \
                --user-group \
                --home-dir "$INSTALL_DIR" \
                --shell /usr/sbin/nologin \
                --comment "Ookla Speedtest Server" \
                "$SERVICE_USER"
        fi
    fi

    SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
    info "Service identity: ${SERVICE_USER}:${SERVICE_GROUP}"
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$INSTALL_DIR"
}

download_installer() {
    TMP_DIR="$(mktemp -d -t ookla-install.XXXXXXXX)"
    local downloaded="${TMP_DIR}/ooklaserver.download"
    local audit_copy="${AUDIT_ROOT}/ooklaserver-${TIMESTAMP}.sh"
    local digest_file="${AUDIT_ROOT}/ooklaserver-${TIMESTAMP}.sha256"
    local metadata_file="${AUDIT_ROOT}/ooklaserver-${TIMESTAMP}.metadata"
    local execution_copy="${INSTALL_DIR}/ooklaserver-installer.sh"

    info "Downloading official installer from ${INSTALLER_URL}"
    curl \
        --fail \
        --show-error \
        --silent \
        --location \
        --proto '=https' \
        --tlsv1.2 \
        --connect-timeout 15 \
        --retry 3 \
        --retry-delay 2 \
        --output "$downloaded" \
        "$INSTALLER_URL"

    [[ -s "$downloaded" ]] || die "Downloaded installer is empty"
    head -n 1 "$downloaded" | grep -Eq '^#!.*(sh|bash)' \
        || die "Downloaded file does not appear to be a shell script"

    install -o root -g root -m 0644 "$downloaded" "$audit_copy"
    sha256sum "$audit_copy" | tee "$digest_file"
    chmod 0640 "$digest_file"

    {
        printf 'downloaded_at_utc=%s\n' "$TIMESTAMP"
        printf 'source_url=%s\n' "$INSTALLER_URL"
        printf 'sha256=%s\n' "$(sha256sum "$audit_copy" | awk '{print $1}')"
        printf 'ubuntu=%s\n' "${PRETTY_NAME:-unknown}"
        printf 'architecture=%s\n' "$(uname -m)"
        printf 'install_dir=%s\n' "$INSTALL_DIR"
        printf 'service_user=%s\n' "$SERVICE_USER"
        printf 'service_group=%s\n' "$SERVICE_GROUP"
        printf 'service_name=%s.service\n' "$SERVICE_NAME"
    } > "$metadata_file"
    chmod 0640 "$metadata_file"

    install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$downloaded" "$execution_copy"

    INSTALLER_PATH="$execution_copy"
    info "Installer preserved for audit: ${audit_copy}"
}

run_vendor_install() {
    local installer_path="$1"

    info "Running the vendor installer as unprivileged account ${SERVICE_USER}"

    # The vendor installer asks for confirmation. Supplying one affirmative answer
    # keeps this deployment reproducible while retaining the vendor's own workflow.
    runuser -u "$SERVICE_USER" -- env HOME="$INSTALL_DIR" \
        /bin/bash -c '
            set -e
            cd "$1"
            printf "y\n" | /bin/bash "$2" install
        ' _ "$INSTALL_DIR" "$installer_path"

    # The vendor installer may start a daemon itself. Stop it before systemd takes ownership.
    if [[ -x "${INSTALL_DIR}/ooklaserver.sh" ]]; then
        info "Stopping the installer-started daemon before systemd activation"
        runuser -u "$SERVICE_USER" -- env HOME="$INSTALL_DIR" \
            /bin/bash -c 'cd "$1"; ./ooklaserver.sh stop' _ "$INSTALL_DIR" || true
    fi

    pkill -TERM -u "$SERVICE_USER" -x OoklaServer 2>/dev/null || true
    sleep 2
    pkill -KILL -u "$SERVICE_USER" -x OoklaServer 2>/dev/null || true

    rm -f -- "$installer_path"

    [[ -f "${INSTALL_DIR}/OoklaServer" ]] \
        || die "Vendor installation completed but ${INSTALL_DIR}/OoklaServer was not found"

    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    chmod 0750 "${INSTALL_DIR}/OoklaServer"

    if [[ -f "${INSTALL_DIR}/ooklaserver.sh" ]]; then
        chmod 0750 "${INSTALL_DIR}/ooklaserver.sh"
    fi

    info "Installed binary details: $(file "${INSTALL_DIR}/OoklaServer")"
    sha256sum "${INSTALL_DIR}/OoklaServer" | tee "${AUDIT_ROOT}/OoklaServer-${TIMESTAMP}.sha256"
    chmod 0640 "${AUDIT_ROOT}/OoklaServer-${TIMESTAMP}.sha256"
}


configure_ookla_properties() {
    local properties_file="${INSTALL_DIR}/OoklaServer.properties"
    local backup_file="${AUDIT_ROOT}/OoklaServer.properties-${TIMESTAMP}.before"
    local tmp_file

    info "Configuring OoklaServer properties: ${properties_file}"

    if [[ -f "$properties_file" ]]; then
        install -o root -g root -m 0640 "$properties_file" "$backup_file"
        info "Previous properties preserved for audit: ${backup_file}"
    else
        install -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0640 /dev/null "$properties_file"
        info "Created properties file: ${properties_file}"
    fi

    set_ookla_property() {
        local key="$1"
        local value="$2"

        tmp_file="$(mktemp "${INSTALL_DIR}/.OoklaServer.properties.XXXXXX")"

        awk -v key="$key" -v replacement="${key} = ${value}" '
            BEGIN { written = 0 }
            {
                candidate = $0
                sub(/^[[:space:]]*/, "", candidate)
                split(candidate, fields, "=")
                found_key = fields[1]
                sub(/[[:space:]]*$/, "", found_key)

                if (found_key == key) {
                    if (!written) {
                        print replacement
                        written = 1
                    }
                    next
                }

                print
            }
            END {
                if (!written) {
                    print replacement
                }
            }
        ' "$properties_file" > "$tmp_file"

        chown "$SERVICE_USER:$SERVICE_GROUP" "$tmp_file"
        chmod 0640 "$tmp_file"
        mv -f -- "$tmp_file" "$properties_file"
    }

    set_ookla_property \
        "OoklaServer.allowedDomains" \
        "*.ookla.com, *.speedtest.net"

    set_ookla_property \
        "OoklaServer.ssl.useLetsEncrypt" \
        "true"

    chown "$SERVICE_USER:$SERVICE_GROUP" "$properties_file"
    chmod 0640 "$properties_file"

    grep -Fqx 'OoklaServer.allowedDomains = *.ookla.com, *.speedtest.net' "$properties_file" \
        || die "Failed to configure OoklaServer.allowedDomains"

    grep -Fqx 'OoklaServer.ssl.useLetsEncrypt = true' "$properties_file" \
        || die "Failed to enable OoklaServer.ssl.useLetsEncrypt"

    info "OoklaServer allowed domains and Let's Encrypt support configured"
}

write_systemd_unit() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local protect_home="true"

    if [[ "$INSTALL_DIR" == /home/* ]]; then
        protect_home="false"
        warn "ProtectHome is disabled because the selected installation path is under /home"
    fi

    info "Creating systemd unit: ${unit_file}"
    cat > "$unit_file" <<EOF
[Unit]
Description=Ookla Speedtest Server
Documentation=https://zdtm.my.site.com/ooklasupport/s/article/OoklaServer-Installation-Linux-Unix
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
Environment=HOME=${INSTALL_DIR}

# Run in the foreground so systemd tracks the real server process directly.
# Do not add --daemon and do not configure PIDFile=.
ExecStart=${INSTALL_DIR}/OoklaServer

Restart=always
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=30s
KillSignal=SIGTERM
KillMode=mixed
UMask=0027
LimitNOFILE=65535

# Conservative systemd hardening compatible with an auto-updating binary.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=${protect_home}
ReadWritePaths=${INSTALL_DIR}
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectHostname=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

    chown root:root "$unit_file"
    chmod 0644 "$unit_file"

    systemd-analyze verify "$unit_file"
    systemctl daemon-reload
}

configure_ufw() {
    (( CONFIGURE_UFW == 1 )) || return 0

    info "Adding UFW inbound rules for OoklaServer"
    ufw allow 8080/tcp comment 'OoklaServer TCP 8080'
    ufw allow 8080/udp comment 'OoklaServer UDP 8080'
    ufw allow 5060/tcp comment 'OoklaServer TCP 5060'
    ufw allow 5060/udp comment 'OoklaServer UDP 5060'

    if ufw status | grep -q '^Status: active'; then
        info "UFW is active; OoklaServer rules are effective"
    else
        warn "UFW is inactive. Rules were added, but this script intentionally did not enable the firewall."
    fi
}

start_and_verify() {
    info "Enabling and starting ${SERVICE_NAME}.service"
    systemctl enable --now "${SERVICE_NAME}.service"

    local attempt
    for attempt in {1..15}; do
        if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
            break
        fi
        sleep 1
    done

    if ! systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        systemctl status "${SERVICE_NAME}.service" --no-pager -l || true
        journalctl -u "${SERVICE_NAME}.service" -n 100 --no-pager || true
        die "The systemd service did not reach the active state"
    fi

    info "Service state: $(systemctl is-active "${SERVICE_NAME}.service")"
    info "Boot state: $(systemctl is-enabled "${SERVICE_NAME}.service")"

    local main_pid owner=""
    main_pid="$(systemctl show --property=MainPID --value "${SERVICE_NAME}.service" 2>/dev/null || true)"

    if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
        owner="$(ps -o user= -p "$main_pid" 2>/dev/null | awk 'NF {print $1; exit}' || true)"
    fi

    if [[ "$owner" == "$SERVICE_USER" ]]; then
        info "Process ownership verified: ${owner} (PID ${main_pid})"
    else
        warn "Could not conclusively verify process ownership (MainPID=${main_pid:-unknown}, owner=${owner:-unknown}); inspect systemctl status manually"
    fi

    info "Listening sockets associated with OoklaServer:"
    ss -lntup 2>/dev/null | grep -E 'OoklaServer|:(8080|5060)\b' || \
        warn "Ports 8080/5060 were not visible yet; the daemon may still be initializing or using a custom configuration"

    local health_ok=0
    for attempt in {1..10}; do
        if curl --fail --silent --show-error --max-time 3 \
            http://127.0.0.1:8080/ >/dev/null 2>&1; then
            health_ok=1
            break
        fi
        sleep 1
    done

    if (( health_ok == 1 )); then
        info "Local HTTP health check passed on 127.0.0.1:8080"
    else
        warn "Local HTTP health check on 127.0.0.1:8080 did not pass. Review the service logs and OoklaServer.properties."
    fi
}

print_summary() {
    cat <<EOF

Installation completed.

Service account : ${SERVICE_USER}:${SERVICE_GROUP}
Install path    : ${INSTALL_DIR}
Systemd unit   : ${SERVICE_NAME}.service
Audit log      : ${LOG_FILE}
Audit artifacts: ${AUDIT_ROOT}

Useful commands:
  systemctl status ${SERVICE_NAME}.service --no-pager -l
  journalctl -u ${SERVICE_NAME}.service -f
  systemctl restart ${SERVICE_NAME}.service
  systemctl is-enabled ${SERVICE_NAME}.service
  systemctl is-active ${SERVICE_NAME}.service
  ss -lntup | grep -E ':(8080|5060)\\b'

Important:
  Manage the process only through systemd. Do not run OoklaServer manually
  with sudo or with --daemon, because that bypasses systemd supervision.
EOF
}

main() {
    parse_args "$@"
    require_root
    validate_inputs
    initialize_logging
    acquire_lock

    info "Starting auditable OoklaServer installation"
    check_platform
    install_dependencies
    backup_existing
    create_service_account

    download_installer
    run_vendor_install "$INSTALLER_PATH"
    configure_ookla_properties
    write_systemd_unit
    configure_ufw
    start_and_verify
    print_summary
}

main "$@"
