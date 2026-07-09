# web_backend — 평문 MAVLink(수동 tap, UDP 14560)을 받아 파싱한 뒤 WebSocket 으로 브로드캐스트하고 정적 페이지도 함께 서빙한다.
#   gcs_proxy 가 복호 평문을 fan-out(172.30.0.20:14560)로 보냄. 렌더는 브라우저(클라 GPU).
import asyncio, json, time, os, threading
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from pymavlink import mavutil

app = FastAPI()
clients = set()
loop = None
S = {"pos": None, "fix": 0, "hb": 0, "n": 0, "posn": 0, "t0": time.time()}

# 서명 C2 명령 발신부. 웹 제어 인터페이스가 gcs_proxy:14556 으로 보내며, MAVLink2 서명(link_id=5)을 붙인다.
SIGN_KEY = None
try:
    _kf = os.environ.get("MAV_SIGN_KEYFILE", "/sign.key")
    if os.path.exists(_kf): SIGN_KEY = bytes.fromhex(open(_kf).read().strip())
except Exception: SIGN_KEY = None
_cmd = None; _cmd_lock = threading.Lock()
def _sender():
    global _cmd
    if _cmd is None:
        _cmd = mavutil.mavlink_connection("udpout:172.30.0.10:14556", source_system=255, source_component=190)
        if SIGN_KEY:
            _cmd.setup_signing(SIGN_KEY, sign_outgoing=True, allow_unsigned_callback=lambda m, i: True, link_id=5)
    return _cmd
def _prime(c):
    for _ in range(3):
        c.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0); time.sleep(0.05)
def _do_cmd(t, v):
    with _cmd_lock:
        c = _sender(); _prime(c)
        if t == "mode":
            c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, int(v), 0, 0, 0, 0, 0)
        elif t == "arm":
            c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, int(v), 0, 0, 0, 0, 0, 0)
        elif t == "takeoff":
            c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, 4, 0, 0, 0, 0, 0)
            time.sleep(1.2); _prime(c)
            c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1, 0, 0, 0, 0, 0, 0)
            time.sleep(1.5); _prime(c)
            c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, float(v))
        else:
            return False
    return True

async def broadcast(d):
    dead = []
    msg = json.dumps(d)
    for ws in list(clients):
        try: await ws.send_text(msg)
        except Exception: dead.append(ws)
    for x in dead: clients.discard(x)

def on_msg(m):
    t = m.get_type()
    if t == "BAD_DATA": return
    S["n"] += 1
    d = {}
    if t == "GLOBAL_POSITION_INT":
        S["pos"] = {"lat": m.lat / 1e7, "lon": m.lon / 1e7, "alt": m.alt / 1000.0}
        S["posn"] += 1
        d["pos"] = S["pos"]; d["fix"] = S["fix"]
    elif t == "GPS_RAW_INT":
        S["fix"] = m.fix_type
    elif t == "HEARTBEAT":
        S["hb"] += 1
    if t in ("HEARTBEAT", "GLOBAL_POSITION_INT", "GPS_RAW_INT", "STATUSTEXT", "COMMAND_ACK", "SYS_STATUS"):
        extra = (": " + m.text) if t == "STATUSTEXT" else ""
        d["log"] = time.strftime("%H:%M:%S") + " " + t + extra
    if d and loop:
        loop.create_task(broadcast(d))

class MavProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.mav = mavutil.mavlink.MAVLink(None); self.mav.robust_parsing = True
    def datagram_received(self, data, addr):
        try: msgs = self.mav.parse_buffer(data) or []
        except Exception: msgs = []
        for m in msgs: on_msg(m)

@app.on_event("startup")
async def startup():
    global loop
    loop = asyncio.get_event_loop()
    await loop.create_datagram_endpoint(lambda: MavProto(), local_addr=("0.0.0.0", 14560))

@app.get("/")
async def index():
    with open("/app/frontend/index.html") as f:
        return HTMLResponse(f.read())

@app.get("/stats")
async def stats():
    dt = max(1e-3, time.time() - S["t0"])
    return JSONResponse({"msgs": S["n"], "positions": S["posn"], "hb": S["hb"], "fix": S["fix"],
                         "pos_rate": round(S["posn"] / dt, 2), "pos": S["pos"], "clients": len(clients)})

@app.post("/api/cmd")
async def api_cmd(body: dict):
    t = body.get("type"); v = body.get("value")
    ok = await loop.run_in_executor(None, _do_cmd, t, v)
    return JSONResponse({"ok": bool(ok), "type": t, "value": v, "signed": SIGN_KEY is not None})

@app.get("/api/signing")
async def api_signing():
    return JSONResponse({"signed": SIGN_KEY is not None})

@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept(); clients.add(sock)
    try:
        while True: await sock.receive_text()
    except Exception: pass
    finally: clients.discard(sock)
