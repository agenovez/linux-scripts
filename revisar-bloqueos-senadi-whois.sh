#!/usr/bin/env bash
set -Eeuo pipefail

# revisar-bloqueos-senadi-whois.sh
# Verifica resolución DNS, respuesta HTTP/HTTPS y consulta WHOIS de las IP encontradas.
# Genera evidencias con timestamp para reporte a autoridad competente.
#
# Uso:
#   chmod +x revisar-bloqueos-senadi-whois.sh
#   ./revisar-bloqueos-senadi-whois.sh bloqueos-senadi.txt 127.0.0.1
#   ./revisar-bloqueos-senadi-whois.sh bloqueos-senadi.txt 127.0.0.1 reporte-senadi
#
# Dependencias Debian/Ubuntu:
#   sudo apt update && sudo apt install -y dnsutils curl whois

LISTA="${1:-bloqueos-senadi.txt}"
RESOLVER="${2:-127.0.0.1}"
OUTDIR="${3:-reporte-senadi-$(date +%Y%m%d-%H%M%S)}"
TIMEOUT_DNS="${TIMEOUT_DNS:-5}"
TIMEOUT_HTTP="${TIMEOUT_HTTP:-8}"
TIMEOUT_WHOIS="${TIMEOUT_WHOIS:-12}"

command -v dig >/dev/null 2>&1 || { echo "ERROR: instale dnsutils/bind-utils para usar dig" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: instale curl" >&2; exit 1; }
command -v whois >/dev/null 2>&1 || { echo "ERROR: instale whois: sudo apt install -y whois" >&2; exit 1; }
command -v timeout >/dev/null 2>&1 || { echo "ERROR: falta timeout/coreutils" >&2; exit 1; }
[[ -f "$LISTA" ]] || { echo "ERROR: no existe la lista: $LISTA" >&2; exit 1; }

mkdir -p "$OUTDIR/dig" "$OUTDIR/whois"
CSV="$OUTDIR/reporte_senadi.csv"
TXT="$OUTDIR/resumen_senadi.txt"
WHOIS_CACHE="$OUTDIR/whois_cache.tsv"
: > "$WHOIS_CACHE"

csv_escape() {
  local s="${1//$'\n'/ }"
  s="${s//$'\r'/ }"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

sanitize_filename() { printf '%s' "$1" | tr -c 'A-Za-z0-9_.:-' '_'; }

is_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|: ]]
}

extract_whois_provider() {
  # Recibe texto WHOIS por stdin y devuelve una identificación corta del propietario/proveedor.
  awk -F: '
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*(OrgName|org-name|Organization|organisation|owner|responsible|descr|netname|NetName|cust-name|role|person)[[:space:]]*:/ {
      key=$1; sub(/^[[:space:]]+/,"",key); sub(/[[:space:]]+$/,"",key);
      val=$0; sub(/^[^:]+:[[:space:]]*/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val);
      if (val != "" && val !~ /^(Not disclosed|REDACTED|Private Customer)$/i) {
        print key "=" val; exit
      }
    }'
}

whois_provider_for_ip() {
  local ip="$1"
  [[ -z "$ip" ]] && { printf ''; return; }

  local cached
  cached="$(awk -F'\t' -v ip="$ip" '$1==ip {print $2; found=1; exit}' "$WHOIS_CACHE" 2>/dev/null || true)"
  if [[ -n "$cached" ]]; then
    printf '%s' "$cached"
    return
  fi

  local safe whoisfile provider
  safe="$(sanitize_filename "$ip")"
  whoisfile="$OUTDIR/whois/${safe}.whois.txt"

  {
    echo "# timestamp: $(date -Is)"
    echo "# ip: $ip"
    echo "# command: whois $ip"
    echo
    timeout "$TIMEOUT_WHOIS" whois "$ip" 2>&1 || true
  } > "$whoisfile"

  provider="$(tail -n +5 "$whoisfile" | extract_whois_provider || true)"
  [[ -z "$provider" ]] && provider="WHOIS_SIN_PROVEEDOR_IDENTIFICADO"

  printf '%s\t%s\n' "$ip" "$provider" >> "$WHOIS_CACHE"
  printf '%s' "$provider"
}

providers_for_ips() {
  local ips="$1"
  [[ -z "$ips" ]] && { printf ''; return; }
  local out="" ip provider
  IFS=';' read -ra arr <<< "$ips"
  for ip in "${arr[@]}"; do
    [[ -z "$ip" ]] && continue
    provider="$(whois_provider_for_ip "$ip")"
    if [[ -z "$out" ]]; then
      out="$ip => $provider"
    else
      out="$out; $ip => $provider"
    fi
  done
  printf '%s' "$out"
}

{
  echo "timestamp_inicio,resolver,dominio,dns_rcode,a_records,aaaa_records,cname,a_whois_provider,http_code,http_final_url,http_remote_ip,http_ip_whois_provider,https_code,https_final_url,https_remote_ip,https_ip_whois_provider,estado_estimado"
} > "$CSV"

TOTAL=0; BLOQUEADO=0; RESUELVE=0; ERRORES=0; WHOIS_IPS=0
START_TS="$(date -Is)"

while IFS= read -r raw || [[ -n "$raw" ]]; do
  domain="$(echo "$raw" | sed 's/#.*$//' | xargs | tr '[:upper:]' '[:lower:]')"
  [[ -z "$domain" ]] && continue
  [[ "$domain" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || { echo "Omitido dominio inválido: $domain" >&2; continue; }
  TOTAL=$((TOTAL+1))
  ts="$(date -Is)"

  digfile="$OUTDIR/dig/${domain}.dig.txt"
  {
    echo "# timestamp: $ts"
    echo "# resolver: $RESOLVER"
    echo "# domain: $domain"
    echo
    dig +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" A "$domain" AAAA
  } > "$digfile" 2>&1 || true

  rcode="$(awk '/status:/{for(i=1;i<=NF;i++) if($i=="status:") {gsub(",","",$(i+1)); print $(i+1); exit}}' "$digfile")"
  [[ -z "$rcode" ]] && rcode="NO_RESPONSE"

  a_records="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | sort -u | paste -sd ';' -)"
  aaaa_records="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" AAAA 2>/dev/null | grep -E ':' | sort -u | paste -sd ';' -)"
  cname="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" CNAME 2>/dev/null | paste -sd ';' -)"

  a_provider="$(providers_for_ips "$a_records")"

  http_line="$(curl -L -k --max-time "$TIMEOUT_HTTP" -o /dev/null -sS -w '%{http_code}|%{url_effective}|%{remote_ip}' "http://$domain/" 2>/dev/null || echo '000||')"
  https_line="$(curl -L -k --max-time "$TIMEOUT_HTTP" -o /dev/null -sS -w '%{http_code}|%{url_effective}|%{remote_ip}' "https://$domain/" 2>/dev/null || echo '000||')"
  IFS='|' read -r http_code http_url http_ip <<< "$http_line"
  IFS='|' read -r https_code https_url https_ip <<< "$https_line"

  http_provider=""
  https_provider=""
  [[ -n "${http_ip:-}" ]] && http_provider="$(whois_provider_for_ip "$http_ip")"
  [[ -n "${https_ip:-}" ]] && https_provider="$(whois_provider_for_ip "$https_ip")"

  estado="RESUELVE"
  if [[ "$rcode" =~ ^(NXDOMAIN|REFUSED|SERVFAIL|NO_RESPONSE)$ ]] || [[ -z "$a_records$aaaa_records" ]]; then
    estado="BLOQUEADO_O_NO_RESUELVE"
    BLOQUEADO=$((BLOQUEADO+1))
  else
    RESUELVE=$((RESUELVE+1))
  fi
  [[ "$rcode" == "NO_RESPONSE" ]] && ERRORES=$((ERRORES+1))

  {
    csv_escape "$ts"; printf ','; csv_escape "$RESOLVER"; printf ','; csv_escape "$domain"; printf ','
    csv_escape "$rcode"; printf ','; csv_escape "$a_records"; printf ','; csv_escape "$aaaa_records"; printf ','; csv_escape "$cname"; printf ','; csv_escape "$a_provider"; printf ','
    csv_escape "$http_code"; printf ','; csv_escape "$http_url"; printf ','; csv_escape "$http_ip"; printf ','; csv_escape "$http_provider"; printf ','
    csv_escape "$https_code"; printf ','; csv_escape "$https_url"; printf ','; csv_escape "$https_ip"; printf ','; csv_escape "$https_provider"; printf ','; csv_escape "$estado"; printf '\n'
  } >> "$CSV"

  echo "[$TOTAL] $domain DNS=$rcode A=[$a_records] WHOIS=[$a_provider] HTTP=$http_code HTTPS=$https_code ESTADO=$estado"
done < "$LISTA"

END_TS="$(date -Is)"
WHOIS_IPS="$(wc -l < "$WHOIS_CACHE" | xargs)"
{
  echo "REPORTE DE VERIFICACION SENADI"
  echo "Timestamp inicio: $START_TS"
  echo "Timestamp fin:    $END_TS"
  echo "Resolver usado:   $RESOLVER"
  echo "Lista fuente:     $LISTA"
  echo "Total evaluado:   $TOTAL"
  echo "No resuelve/bloqueado estimado: $BLOQUEADO"
  echo "Resuelve:         $RESUELVE"
  echo "Sin respuesta DNS: $ERRORES"
  echo "IPs consultadas en WHOIS: $WHOIS_IPS"
  echo "CSV: $CSV"
  echo "Evidencias dig:   $OUTDIR/dig/"
  echo "Evidencias whois: $OUTDIR/whois/"
  echo "Cache whois:      $WHOIS_CACHE"
  echo
  echo "Nota: Para evidencia de cumplimiento, ejecute contra el DNS de Pi-hole/recursivo de la red del ISP."
  echo "Nota: La columna *_whois_provider identifica el propietario/proveedor reportado por WHOIS para la IP observada."
} > "$TXT"

echo "Listo. Reporte CSV: $CSV"
echo "Resumen: $TXT"
echo "Evidencias WHOIS: $OUTDIR/whois/"
