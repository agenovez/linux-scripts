#!/usr/bin/env bash
set -Eeuo pipefail

# revisar-bloqueos-senadi.sh
# Verifica resolución DNS y respuesta HTTP/HTTPS de dominios SENADI.
# Uso:
#   chmod +x revisar-bloqueos-senadi.sh
#   ./revisar-bloqueos-senadi.sh bloqueos-senadi.txt 127.0.0.1
#   ./revisar-bloqueos-senadi.sh bloqueos-senadi.txt 8.8.8.8

LISTA="${1:-bloqueos-senadi.txt}"
RESOLVER="${2:-127.0.0.1}"
OUTDIR="${3:-reporte-senadi-$(date +%Y%m%d-%H%M%S)}"
TIMEOUT_DNS="${TIMEOUT_DNS:-5}"
TIMEOUT_HTTP="${TIMEOUT_HTTP:-8}"

command -v dig >/dev/null 2>&1 || { echo "ERROR: instale dnsutils/bind-utils para usar dig" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: instale curl" >&2; exit 1; }
[[ -f "$LISTA" ]] || { echo "ERROR: no existe la lista: $LISTA" >&2; exit 1; }

mkdir -p "$OUTDIR/dig"
CSV="$OUTDIR/reporte_senadi.csv"
TXT="$OUTDIR/resumen_senadi.txt"

csv_escape() { local s="${1//$'\n'/ }"; s="${s//\"/\"\"}"; printf '"%s"' "$s"; }

{
  echo "timestamp_inicio,resolver,dominio,dns_rcode,a_records,aaaa_records,cname,http_code,http_final_url,http_remote_ip,https_code,https_final_url,https_remote_ip,estado_estimado"
} > "$CSV"

TOTAL=0; BLOQUEADO=0; RESUELVE=0; ERRORES=0
START_TS="$(date -Is)"

while IFS= read -r raw || [[ -n "$raw" ]]; do
  domain="$(echo "$raw" | sed 's/#.*$//' | xargs | tr '[:upper:]' '[:lower:]')"
  [[ -z "$domain" ]] && continue
  [[ "$domain" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || { echo "Omitido dominio inválido: $domain" >&2; continue; }
  TOTAL=$((TOTAL+1))
  ts="$(date -Is)"

  digfile="$OUTDIR/dig/${domain}.dig.txt"
  dig +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" A "$domain" AAAA > "$digfile" 2>&1 || true
  rcode="$(awk '/status:/{for(i=1;i<=NF;i++) if($i=="status:") {gsub(",","",$(i+1)); print $(i+1); exit}}' "$digfile")"
  [[ -z "$rcode" ]] && rcode="NO_RESPONSE"

  a_records="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | paste -sd ';' -)"
  aaaa_records="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" AAAA 2>/dev/null | grep -E ':' | paste -sd ';' -)"
  cname="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" CNAME 2>/dev/null | paste -sd ';' -)"

  http_line="$(curl -L -k --max-time "$TIMEOUT_HTTP" -o /dev/null -sS -w '%{http_code}|%{url_effective}|%{remote_ip}' "http://$domain/" 2>/dev/null || echo '000||')"
  https_line="$(curl -L -k --max-time "$TIMEOUT_HTTP" -o /dev/null -sS -w '%{http_code}|%{url_effective}|%{remote_ip}' "https://$domain/" 2>/dev/null || echo '000||')"
  IFS='|' read -r http_code http_url http_ip <<< "$http_line"
  IFS='|' read -r https_code https_url https_ip <<< "$https_line"

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
    csv_escape "$rcode"; printf ','; csv_escape "$a_records"; printf ','; csv_escape "$aaaa_records"; printf ','; csv_escape "$cname"; printf ','
    csv_escape "$http_code"; printf ','; csv_escape "$http_url"; printf ','; csv_escape "$http_ip"; printf ','
    csv_escape "$https_code"; printf ','; csv_escape "$https_url"; printf ','; csv_escape "$https_ip"; printf ','; csv_escape "$estado"; printf '\n'
  } >> "$CSV"

  echo "[$TOTAL] $domain DNS=$rcode A=[$a_records] HTTP=$http_code HTTPS=$https_code ESTADO=$estado"
done < "$LISTA"

END_TS="$(date -Is)"
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
  echo "CSV: $CSV"
  echo "Evidencias dig: $OUTDIR/dig/"
  echo
  echo "Nota: Para evidencia de cumplimiento, ejecute contra el DNS de Pi-hole/recursivo de la red del ISP."
} > "$TXT"

echo "Listo. Reporte CSV: $CSV"
echo "Resumen: $TXT"
