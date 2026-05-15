#!/usr/bin/env bash
# Copyright (C) 2026 DigiCert, Inc.
#
# Licensed under the dual-license model:
#   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
#   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
#
# For commercial licensing, contact sales@digicert.com.

# Bulk local-CA/MTC demo:
#   1. Issue many ACME certificates into a fresh folder.
#   2. Fetch landmark/signatureless certificates for every order.
#   3. Verify all certificates.
#   4. Optionally revoke a few log indexes.
#   5. If revocation is enabled, verify again and confirm revoked certificates fail.
#
# Requirements:
#   - docker compose postgres is running
#   - ./bin/mtc-bridge is running with local_ca.enabled=true
#   - local_ca.mtc_mode=true, so raw ML-DSA-44 SPKIs can be embedded
#   - MTC_REVOCATION_ADMIN_TOKEN is set in the bridge environment and here
#     only when REVOKE_COUNT is greater than 0
#   - lego is on PATH
#   - openssl35 is on PATH and supports ML-DSA-44
#
# Useful overrides:
#   COUNT=10 ./bulk-local-ca-cert-demo.sh
#   DOMAIN_SUFFIX=yven.ch COUNT=1000 ./bulk-local-ca-cert-demo.sh
#   REVOKE_COUNT=5 REVOKE_START_INDEX=12 ./bulk-local-ca-cert-demo.sh

set -euo pipefail

COUNT="${COUNT:-1000}"
DOMAIN_SUFFIX="${DOMAIN_SUFFIX:-yven.ch}"
DOMAIN_PREFIX="${DOMAIN_PREFIX:-bulk-mtc}"
EMAIL="${EMAIL:-bulk-mtc@yven.ch}"
OUT_ROOT="${OUT_ROOT:-testcerts/bulk-$(date +%Y%m%d-%H%M%S)}"
ACME_SERVER="${ACME_SERVER:-https://localhost:8443/acme/directory}"
ACME_CA_CERT="${ACME_CA_CERT:-acme-keys/acme-cert.pem}"
BRIDGE_URL="${BRIDGE_URL:-http://localhost:8080}"
HTTP_PORT="${HTTP_PORT:-:5002}"
LANDMARK_MAX_ATTEMPTS="${LANDMARK_MAX_ATTEMPTS:-20}"
LANDMARK_SLEEP_SECONDS="${LANDMARK_SLEEP_SECONDS:-10}"
REVOKE_COUNT="${REVOKE_COUNT:-0}"
REVOKE_START_INDEX="${REVOKE_START_INDEX:-}"
VERIFY_BEFORE="${VERIFY_BEFORE:-1}"
VERIFY_AFTER="${VERIFY_AFTER:-1}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl35}"
KEY_ALGORITHM="${KEY_ALGORITHM:-ML-DSA-44}"

CERT_DIR="${OUT_ROOT}/certificates"
KEY_DIR="${OUT_ROOT}/keys"
CSR_DIR="${OUT_ROOT}/csrs"
LOG_DIR="${OUT_ROOT}/logs"
ORDERS_TSV="${OUT_ROOT}/orders.tsv"
REVOKED_TSV="${OUT_ROOT}/revoked.tsv"
SUMMARY="${OUT_ROOT}/summary.txt"

log() {
  printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

psql_query() {
  docker compose exec -T postgres psql -U mtcbridge -d mtcbridge -Atc "$1"
}

verify_cert() {
  local cert="$1"
  local log_file="$2"
  ./bin/mtc-verify-cert -cert "$cert" -bridge-url "$BRIDGE_URL" >"$log_file" 2>&1
}

fetch_landmark() {
  local order_id="$1"
  local output="$2"
  local headers="$3"

  for attempt in $(seq 1 "$LANDMARK_MAX_ATTEMPTS"); do
    local status
    status="$(curl -sS --cacert "$ACME_CA_CERT" \
      -D "$headers" \
      -o "$output" \
      -w '%{http_code}' \
      "${ACME_SERVER%/directory}/certificate/${order_id}/landmark" || true)"

    if [ "$status" = "200" ]; then
      return 0
    fi

    rm -f "$output"
    log "landmark not ready for order ${order_id} (HTTP ${status}, attempt ${attempt}/${LANDMARK_MAX_ATTEMPTS}); sleeping ${LANDMARK_SLEEP_SECONDS}s"
    sleep "$LANDMARK_SLEEP_SECONDS"
  done

  return 1
}

main() {
  require_cmd docker
  require_cmd curl
  require_cmd lego
  require_cmd python3
  require_cmd "$OPENSSL_BIN"

  [ -x ./bin/mtc-verify-cert ] || fail "missing ./bin/mtc-verify-cert; run make build"
  [ -f "$ACME_CA_CERT" ] || fail "missing ACME CA cert: $ACME_CA_CERT"
  if [ "$REVOKE_COUNT" -gt 0 ]; then
    [ -n "${MTC_REVOCATION_ADMIN_TOKEN:-}" ] || fail "MTC_REVOCATION_ADMIN_TOKEN must be set when REVOKE_COUNT is greater than 0"
  fi

  mkdir -p "$CERT_DIR" "$KEY_DIR" "$CSR_DIR" "$LOG_DIR"
  printf "domain\torder_id\tlog_index\tcert_serial\n" >"$ORDERS_TSV"
  printf "domain\torder_id\tlog_index\tcert_serial\n" >"$REVOKED_TSV"

  log "output folder: $OUT_ROOT"
  log "issuing $COUNT certificates with ${KEY_ALGORITHM} CSRs via ${OPENSSL_BIN}"

  for n in $(seq 1 "$COUNT"); do
    local name domain key_path csr_path
    name="$(printf '%s-%04d' "$DOMAIN_PREFIX" "$n")"
    domain="${name}.${DOMAIN_SUFFIX}"
    key_path="${KEY_DIR}/${domain}.key"
    csr_path="${CSR_DIR}/${domain}.csr"

    log "[$n/$COUNT] generating ${KEY_ALGORITHM} CSR for ${domain}"
    "$OPENSSL_BIN" genpkey \
      -algorithm "$KEY_ALGORITHM" \
      -out "$key_path" \
      >"${LOG_DIR}/${domain}.keygen.log" 2>&1

    "$OPENSSL_BIN" req -new \
      -key "$key_path" \
      -out "$csr_path" \
      -subj "/CN=${domain}/O=MTC Bulk Demo/C=CH" \
      -addext "subjectAltName=DNS:${domain}" \
      >"${LOG_DIR}/${domain}.csr.log" 2>&1

    log "[$n/$COUNT] issuing ${domain}"
    LEGO_CA_CERTIFICATES="$ACME_CA_CERT" \
      lego \
        --server "$ACME_SERVER" \
        --email "$EMAIL" \
        --accept-tos \
        --csr "$csr_path" \
        --path "$OUT_ROOT" \
        --http \
        --http.port "$HTTP_PORT" \
        run >"${LOG_DIR}/${domain}.lego.log" 2>&1

    local order_row order_id log_index cert_serial
    order_row="$(psql_query "
      select ao.id || E'\t' || le.idx || E'\t' || ao.cert_serial
      from acme_orders ao
      join log_entries le on le.serial_hex = ao.cert_serial
      where ao.status = 'valid'
        and ao.identifiers @> '[{\"type\":\"dns\",\"value\":\"${domain}\"}]'::jsonb
      order by ao.created_at desc
      limit 1;
    ")"
    [ -n "$order_row" ] || fail "could not find valid ACME order/log entry for ${domain}"

    IFS=$'\t' read -r order_id log_index cert_serial <<<"$order_row"
    printf "%s\t%s\t%s\t%s\n" "$domain" "$order_id" "$log_index" "$cert_serial" >>"$ORDERS_TSV"
  done

  log "issued all certificates; fetching landmark certificates"
  while IFS=$'\t' read -r domain order_id log_index cert_serial; do
    [ "$domain" != "domain" ] || continue
    local landmark_cert headers
    landmark_cert="${CERT_DIR}/${domain}.landmark.crt"
    headers="${LOG_DIR}/${domain}.landmark.headers"

    log "fetching landmark for ${domain} (order ${order_id}, index ${log_index})"
    if ! fetch_landmark "$order_id" "$landmark_cert" "$headers"; then
      fail "landmark certificate was not available for ${domain} after ${LANDMARK_MAX_ATTEMPTS} attempts"
    fi
  done <"$ORDERS_TSV"

  if [ "$VERIFY_BEFORE" = "1" ]; then
    log "verifying all standalone and landmark certificates"
    while IFS=$'\t' read -r domain order_id log_index cert_serial; do
      [ "$domain" != "domain" ] || continue
      verify_cert "${CERT_DIR}/${domain}.crt" "${LOG_DIR}/${domain}.verify.before.log"
      verify_cert "${CERT_DIR}/${domain}.landmark.crt" "${LOG_DIR}/${domain}.landmark.verify.before.log"
    done <"$ORDERS_TSV"
  fi

  local revoke_start="" revoke_end="" effective_revoke_count
  effective_revoke_count="$REVOKE_COUNT"
  if [ "$effective_revoke_count" -gt "$COUNT" ]; then
    effective_revoke_count="$COUNT"
  fi

  if [ "$effective_revoke_count" -gt 0 ]; then
    if [ -n "$REVOKE_START_INDEX" ]; then
      revoke_start="$REVOKE_START_INDEX"
    else
      revoke_start="$(awk 'NR==2 {print $3}' "$ORDERS_TSV")"
    fi
    [ -n "$revoke_start" ] || fail "could not determine revoke start index"
    revoke_end=$((revoke_start + effective_revoke_count))

    log "revoking range [${revoke_start}, ${revoke_end})"
    curl -sS -X POST "${BRIDGE_URL}/revocation" \
      -H "Authorization: Bearer ${MTC_REVOCATION_ADMIN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"start\":${revoke_start},\"end\":${revoke_end},\"reason\":0}" \
      | tee "${LOG_DIR}/revocation-response.json" \
      | python3 -m json.tool

    awk -v start="$revoke_start" -v end="$revoke_end" 'NR == 1 || ($3 >= start && $3 < end)' "$ORDERS_TSV" >"$REVOKED_TSV"
  else
    log "revocation disabled (set REVOKE_COUNT greater than 0 to enable it)"
  fi

  if [ "$VERIFY_AFTER" = "1" ] && [ "$effective_revoke_count" -gt 0 ]; then
    log "verifying all certificates after revocation"
    local revoked_failures=0 revoked_unexpected_pass=0 valid_failures=0 expected_revoked_certs=0
    expected_revoked_certs="$(awk 'NR > 1 {count++} END {print count + 0}' "$REVOKED_TSV")"
    while IFS=$'\t' read -r domain order_id log_index cert_serial; do
      [ "$domain" != "domain" ] || continue
      local cert_log landmark_log revoked
      cert_log="${LOG_DIR}/${domain}.verify.after.log"
      landmark_log="${LOG_DIR}/${domain}.landmark.verify.after.log"
      revoked=0
      if [ "$log_index" -ge "$revoke_start" ] && [ "$log_index" -lt "$revoke_end" ]; then
        revoked=1
      fi

      if verify_cert "${CERT_DIR}/${domain}.crt" "$cert_log"; then
        if [ "$revoked" = "1" ]; then
          revoked_unexpected_pass=$((revoked_unexpected_pass + 1))
        fi
      else
        if [ "$revoked" = "1" ]; then
          revoked_failures=$((revoked_failures + 1))
        else
          valid_failures=$((valid_failures + 1))
        fi
      fi

      if verify_cert "${CERT_DIR}/${domain}.landmark.crt" "$landmark_log"; then
        if [ "$revoked" = "1" ]; then
          revoked_unexpected_pass=$((revoked_unexpected_pass + 1))
        fi
      else
        if [ "$revoked" = "1" ]; then
          revoked_failures=$((revoked_failures + 1))
        else
          valid_failures=$((valid_failures + 1))
        fi
      fi
    done <"$ORDERS_TSV"

    {
      echo "output_root=${OUT_ROOT}"
      echo "count=${COUNT}"
      echo "orders_tsv=${ORDERS_TSV}"
      echo "revoked_tsv=${REVOKED_TSV}"
      echo "revoked_range=[${revoke_start},${revoke_end})"
      echo "expected_revoked_failures=$((expected_revoked_certs * 2))"
      echo "actual_revoked_failures=${revoked_failures}"
      echo "revoked_unexpected_pass=${revoked_unexpected_pass}"
      echo "valid_failures=${valid_failures}"
    } | tee "$SUMMARY"

    [ "$revoked_unexpected_pass" -eq 0 ] || fail "some revoked certificates still verified successfully"
    [ "$valid_failures" -eq 0 ] || fail "some non-revoked certificates failed verification"
  fi

  if [ "$effective_revoke_count" -eq 0 ] || [ "$VERIFY_AFTER" != "1" ]; then
    {
      echo "output_root=${OUT_ROOT}"
      echo "count=${COUNT}"
      echo "orders_tsv=${ORDERS_TSV}"
      echo "revoked_tsv=${REVOKED_TSV}"
      echo "revocation_enabled=$([ "$effective_revoke_count" -gt 0 ] && echo true || echo false)"
      if [ "$effective_revoke_count" -gt 0 ]; then
        echo "revoked_range=[${revoke_start},${revoke_end})"
      fi
    } | tee "$SUMMARY"
  fi

  log "done"
  log "certificates: $CERT_DIR"
  log "logs: $LOG_DIR"
  log "summary: $SUMMARY"
}

main "$@"
