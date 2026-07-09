#!/usr/bin/env bash
set -Eeuo pipefail

# Verifica dominios SENADI: DNS + HTTP/HTTPS + WHOIS por IP.
# Uso:
#   ./revisar-bloqueos-senadi-whois-v2.sh bloqueos-senadi.txt 1.1.1.1 reporte-senadi3
# Dependencias:
#   sudo apt install -y dnsutils curl whois coreutils gawk

LISTA="${1:-bloqueos-senadi.txt}"
RESOLVER="${2:-127.0.0.1}"
OUTDIR="${3:-reporte-senadi-$(date +%Y%m%d-%H%M%S)}"
TIMEOUT_DNS="${TIMEOUT_DNS:-5}"
TIMEOUT_HTTP="${TIMEOUT_HTTP:-8}"
TIMEOUT_WHOIS="${TIMEOUT_WHOIS:-12}"

for bin in dig curl whois timeout awk sed sort paste wc; do
  command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: falta dependencia: $bin" >&2; exit 1; }
done
[[ -f "$LISTA" ]] || { echo "ERROR: no existe la lista: $LISTA" >&2; exit 1; }
[[ -s "$LISTA" ]] || { echo "ERROR: la lista existe, pero está vacía: $LISTA" >&2; exit 1; }

mkdir -p "$OUTDIR/dig" "$OUTDIR/whois" "$OUTDIR/http"
CSV="$OUTDIR/reporte_senadi.csv"
TXT="$OUTDIR/resumen_senadi.txt"
WHOIS_CACHE="$OUTDIR/whois_cache.tsv"
DOMAINS_TMP="$OUTDIR/dominios_normalizados.txt"
SKIPPED="$OUTDIR/lineas_omitidas.txt"
: > "$WHOIS_CACHE"
: > "$SKIPPED"

# Extrae dominios aunque el archivo venga como lista simple, numerada o copiada desde PDF.
# Evita correos/URLs completas dejando solo el host.
awk '
  BEGIN{IGNORECASE=1}
  {
    original=$0
    gsub(/\r/,"",$0)
    sub(/#.*/,"",$0)
    gsub(/^\xef\xbb\xbf/,"",$0)
    gsub(/https?:\/\//," ",$0)
    gsub(/www\./,"www.",$0)
    n=split($0,a,/[^A-Za-z0-9._-]+/)
    found=0
    for(i=1;i<=n;i++){
      d=tolower(a[i])
      gsub(/^www\./,"",d)
      gsub(/^\.+|\.+$/,"",d)
      if(d ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/ && d !~ /@/){print d; found=1}
    }
    if(found==0 && original !~ /^[[:space:]]*($|#)/){print original >> skipped}
  }' skipped="$SKIPPED" "$LISTA" | sort -u > "$DOMAINS_TMP"

DOMAIN_COUNT="$(wc -l < "$DOMAINS_TMP" | tr -d ' ')"
if [[ "$DOMAIN_COUNT" -eq 0 ]]; then
  echo "ERROR: no se detectó ningún dominio válido dentro de: $LISTA" >&2
  echo "Revise lineas omitidas en: $SKIPPED" >&2
  exit 1
fi

echo "Dominios detectados: $DOMAIN_COUNT"
echo "Lista normalizada: $DOMAINS_TMP"

csv_escape() {
  local s="${1//$'\n'/ }"
  s="${s//$'\r'/ }"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}

sanitize_filename() { printf '%s' "$1" | tr -c 'A-Za-z0-9_.:-' '_'; }

extract_whois_provider() {
  awk -F: '
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*(OrgName|org-name|Organization|organisation|owner|responsible|descr|netname|NetName|cust-name|role|person|aut-num|mnt-by)[[:space:]]*:/ {
      key=$1; sub(/^[[:space:]]+/,"",key); sub(/[[:space:]]+$/,"",key)
      val=$0; sub(/^[^:]+:[[:space:]]*/,"",val); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val)
      if (val != "" && val !~ /^(Not disclosed|REDACTED|Private Customer)$/i) { print key "=" val; exit }
    }'
}

whois_provider_for_ip() {
  local ip="$1" cached safe whoisfile provider
  [[ -z "$ip" ]] && { printf ''; return; }
  cached="$(awk -F'\t' -v ip="$ip" '$1==ip {print $2; exit}' "$WHOIS_CACHE" 2>/dev/null || true)"
  if [[ -n "$cached" ]]; then printf '%s' "$cached"; return; fi

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
  local ips="$1" out="" ip provider
  [[ -z "$ips" ]] && { printf ''; return; }
  IFS=';' read -ra arr <<< "$ips"
  for ip in "${arr[@]}"; do
    [[ -z "$ip" ]] && continue
    provider="$(whois_provider_for_ip "$ip")"
    [[ -z "$out" ]] && out="$ip => $provider" || out="$out; $ip => $provider"
  done
  printf '%s' "$out"
}

{
  echo "timestamp_inicio,resolver,dominio,dns_rcode,a_records,aaaa_records,cname,a_whois_provider,http_code,http_final_url,http_remote_ip,http_ip_whois_provider,https_code,https_final_url,https_remote_ip,https_ip_whois_provider,estado_estimado"
} > "$CSV"

TOTAL=0; BLOQUEADO=0; RESUELVE=0; ERRORES=0
START_TS="$(date -Is)"

while IFS= read -r domain || [[ -n "$domain" ]]; do
  [[ -z "$domain" ]] && continue
  TOTAL=$((TOTAL+1))
  ts="$(date -Is)"
  safe_domain="$(sanitize_filename "$domain")"
  digfile="$OUTDIR/dig/${safe_domain}.dig.txt"

  {
    echo "# timestamp: $ts"
    echo "# resolver: $RESOLVER"
    echo "# domain: $domain"
    echo
    echo "## A"
    dig +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" A
    echo
    echo "## AAAA"
    dig +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" AAAA
    echo
    echo "## CNAME"
    dig +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" CNAME
  } > "$digfile" 2>&1 || true

  rcode="$(awk '/status:/{for(i=1;i<=NF;i++) if($i=="status:") {gsub(",","",$(i+1)); print $(i+1); exit}}' "$digfile")"
  [[ -z "$rcode" ]] && rcode="NO_RESPONSE"

  a_records="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | sort -u | paste -sd ';' - || true)"
  aaaa_records="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" AAAA 2>/dev/null | grep -E ':' | sort -u | paste -sd ';' - || true)"
  cname="$(dig +short +time="$TIMEOUT_DNS" +tries=1 "@$RESOLVER" "$domain" CNAME 2>/dev/null | sort -u | paste -sd ';' - || true)"
  a_provider="$(providers_for_ips "$a_records")"

  httpfile="$OUTDIR/http/${safe_domain}.http.txt"
  httpsfile="$OUTDIR/http/${safe_domain}.https.txt"
  http_line="$(curl -L -k --connect-timeout 4 --max-time "$TIMEOUT_HTTP" -o /dev/null -sS -w '%{http_code}|%{url_effective}|%{remote_ip}' "http://$domain/" 2>"$httpfile" || echo '000||')"
  https_line="$(curl -L -k --connect-timeout 4 --max-time "$TIMEOUT_HTTP" -o /dev/null -sS -w '%{http_code}|%{url_effective}|%{remote_ip}' "https://$domain/" 2>"$httpsfile" || echo '000||')"
  IFS='|' read -r http_code http_url http_ip <<< "$http_line"
  IFS='|' read -r https_code https_url https_ip <<< "$https_line"
  http_provider=""; https_provider=""
  [[ -n "${http_ip:-}" ]] && http_provider="$(whois_provider_for_ip "$http_ip")"
  [[ -n "${https_ip:-}" ]] && https_provider="$(whois_provider_for_ip "$https_ip")"

  estado="RESUELVE"
  if [[ "$rcode" =~ ^(NXDOMAIN|REFUSED|SERVFAIL|NO_RESPONSE)$ ]] || [[ -z "$a_records$aaaa_records" ]]; then
    estado="BLOQUEADO_O_NO_RESUELVE"; BLOQUEADO=$((BLOQUEADO+1))
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

  echo "[$TOTAL/$DOMAIN_COUNT] $domain DNS=$rcode A=[$a_records] HTTP=$http_code HTTPS=$https_code ESTADO=$estado"
done < "$DOMAINS_TMP"

END_TS="$(date -Is)"
WHOIS_IPS="$(wc -l < "$WHOIS_CACHE" | tr -d ' ')"
{
  echo "REPORTE DE VERIFICACION SENADI"
  echo "Timestamp inicio: $START_TS"
  echo "Timestamp fin:    $END_TS"
  echo "Resolver usado:   $RESOLVER"
  echo "Lista fuente:     $LISTA"
  echo "Dominios detectados: $DOMAIN_COUNT"
  echo "Total evaluado:   $TOTAL"
  echo "No resuelve/bloqueado estimado: $BLOQUEADO"
  echo "Resuelve:         $RESUELVE"
  echo "Sin respuesta DNS: $ERRORES"
  echo "IPs consultadas en WHOIS: $WHOIS_IPS"
  echo "CSV: $CSV"
  echo "Lista normalizada: $DOMAINS_TMP"
  echo "Lineas omitidas:  $SKIPPED"
  echo "Evidencias dig:   $OUTDIR/dig/"
  echo "Evidencias http:  $OUTDIR/http/"
  echo "Evidencias whois: $OUTDIR/whois/"
  echo "Cache whois:      $WHOIS_CACHE"
} > "$TXT"

echo "Listo. Reporte CSV: $CSV"
echo "Resumen: $TXT"
