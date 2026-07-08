#!/usr/bin/env bash
# package.sh — 신규 인스턴스 배포용 아카이브 생성(소스+시크릿; .bak/logs/.git 제외).
set -euo pipefail
cd "$HOME"; OUT="$HOME/dah-testbed-deploy.tgz"
tar czf "$OUT" --exclude=".git" --exclude="*.bak" --exclude="logs" --exclude="__pycache__" testbed testbed-split
echo "생성: $OUT ($(du -h "$OUT" | cut -f1))"
echo "시크릿 포함(.env-aria/.mav-sign-key): $(tar tzf "$OUT" | grep -cE "\.env-aria|\.mav-sign-key")/2"
echo "배포문서 포함: $(tar tzf "$OUT" | grep -c "DEPLOY_NEW_INSTANCE.md")/1 · 총 $(tar tzf "$OUT" | grep -vc "/$") 파일"
