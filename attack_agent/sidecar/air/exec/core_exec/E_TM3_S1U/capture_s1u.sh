#!/usr/bin/env sh
# capture_s1u (COLLECT): 가능하면 짧은 S1U(UDP/2152) pcap 캡처 후 artifacts 보고.
set -eu

emit_empty() {
  printf '%s\n' '{"artifacts":[],"values":{},"nonce_collision":null}'
}

if ! command -v tcpdump >/dev/null 2>&1; then
  emit_empty
  exit 0
fi

TIMEOUT_S="${TIMEOUT_S:-4}"
PKT_COUNT="${PKT_COUNT:-20}"
TMP="/tmp/s1u_${$}.pcap"

set +e
timeout "$TIMEOUT_S" tcpdump -i any -nn -s0 -c "$PKT_COUNT" udp port 2152 -w "$TMP" >/dev/null 2>&1
RC=$?
set -e

if [ -s "$TMP" ]; then
  SIZE=$(wc -c < "$TMP" 2>/dev/null || echo 0)
  printf '{"artifacts":["pcap"],"values":{"pcap_bytes":"%s"},"nonce_collision":null}\n' "$SIZE"
else
  emit_empty
fi

rm -f "$TMP" >/dev/null 2>&1 || true
exit 0
