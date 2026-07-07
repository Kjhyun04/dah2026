#!/usr/bin/env bash
# verify-all.sh — 전체 게이트 검증 (G0~G5). 콜드스타트 재현 확인용.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R=0
for v in 22-verify-epc 31-verify-ran 41-verify-sgi 51-verify-sitl 71-verify-aria 81-verify-web; do
  printf '\n\033[1;35m### %s ###\033[0m\n' "$v"
  bash "$HERE/$v.sh" || R=1
done
echo
if [ "$R" -eq 0 ]; then printf '\033[1;32m========== 전체 게이트 통과 ✅ — v2 재현 성립 ==========\033[0m\n'
else printf '\033[1;31m========== 일부 게이트 실패 ✗ ==========\033[0m\n'; fi
exit "$R"
