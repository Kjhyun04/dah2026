/* viewer/static/app.js — 빌드툴 0 · 외부요청 0.
 * fetch("/api/snapshot") 초기 페인트 → EventSource("/sse") 증분 갱신.
 * 되먹임 0: 오직 GET read. 어떤 POST/PUT/입력도 서버로 보내지 않는다.
 */
"use strict";

// ── 상태(브라우저 로컬 표시 상태) ──────────────────────────────────────────
var state = {
  steps: [],        // 동작 스텝 누적
  campaign: null,   // campaign_result
  wire: [],         // 통신 복호 프레임 누적
  injections: [],   // 주입 레인 rows
  evaluation: null, // 감독
};

var MODE_NAMES = { 0: "STABILIZE", 4: "GUIDED", 5: "LOITER", 9: "LAND" };
function modeLabel(m, precomputed) {
  if (precomputed !== undefined && precomputed !== null) return precomputed;
  if (m === null || m === undefined || m === "") return "";
  return MODE_NAMES[m] !== undefined ? MODE_NAMES[m] : String(m);
}
function esc(s) {
  return String(s === null || s === undefined ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function el(id) { return document.getElementById(id); }

// ── 렌더: 배너 ─────────────────────────────────────────────────────────────
function renderBanner(banner) {
  var b = el("banner");
  if (banner && banner.mismatch) {
    b.textContent = "⚠ agent ≠ truth — 공격 agent 자기판정과 감독 ground-truth 불일치"
      + (banner.note ? " · " + banner.note : "");
    b.classList.remove("hidden");
  } else {
    if (banner && banner.note) b.title = banner.note;
    b.classList.add("hidden");
  }
}

// ── 렌더: 동작 패널 ────────────────────────────────────────────────────────
var VERDICT_CLASS = { OK: "v-ok", BLOCKED: "v-blocked", ERROR: "v-error", TIMEOUT: "v-timeout" };
function renderAction() {
  var sum = el("action-summary");
  if (state.campaign) {
    var c = state.campaign;
    var reached = c.goal_reached ? "goal_reached=true" : "goal_reached=false";
    sum.innerHTML =
      '<span class="badge ' + (c.goal_reached ? "b-win" : "b-lose") + '">' + esc(reached) + "</span>"
      + '<span class="badge">steps=' + esc(c.steps) + "</span>"
      + (Array.isArray(c.defenses_bypassed) && c.defenses_bypassed.length
          ? '<span class="badge">bypassed: ' + esc(c.defenses_bypassed.join(", ")) + "</span>" : "")
      + (Array.isArray(c.win_causes) && c.win_causes.length
          ? '<span class="badge">cause: ' + esc(c.win_causes.join(", ")) + "</span>" : "");
  } else {
    sum.innerHTML = '<span class="badge">count=' + esc(state.steps.length) + "</span>";
  }

  var ol = el("action-timeline");
  ol.innerHTML = "";
  for (var i = 0; i < state.steps.length; i++) {
    var st = state.steps[i];
    var vc = VERDICT_CLASS[st.verdict] || "v-unknown";
    var params = st.params && Object.keys(st.params).length
      ? Object.keys(st.params).map(function (k) { return k + "=" + st.params[k]; }).join(" ") : "";
    var li = document.createElement("li");
    li.className = "step " + vc;
    var pivot = st.blocked_by
      ? '<span class="pivot">blocked→pivot (' + esc(st.blocked_by) + ")</span>" : "";
    li.innerHTML =
      '<span class="sidx">#' + esc(st.step) + "</span>"
      + '<span class="tool">' + esc(st.tool_id) + "</span>"
      + (params ? '<span class="params">' + esc(params) + "</span>" : "")
      + '<span class="verdict ' + vc + '">' + esc(st.verdict || "?") + "</span>"
      + pivot;
    ol.appendChild(li);
  }
  if (state.steps.length === 0) {
    ol.innerHTML = '<li class="empty">스텝 없음 (recon-only 또는 미실행)</li>';
  }
}

// ── 렌더: 통신 패널 ────────────────────────────────────────────────────────
function renderComms() {
  var wb = el("comms-wire").querySelector("tbody");
  wb.innerHTML = "";
  for (var i = 0; i < state.wire.length; i++) {
    var f = state.wire[i];
    var tr = document.createElement("tr");
    tr.className = f.dir === "up" ? "dir-up" : "dir-down";
    var signed = f.signed === true ? "signed" : (f.signed === false ? "unsigned" : "—");
    var t = (f.t === null || f.t === undefined) ? "—"
      : (typeof f.t === "number" ? f.t.toFixed(2) : esc(f.t));
    tr.innerHTML =
      "<td>" + esc(t) + "</td>"
      + '<td class="dir">' + esc(f.dir) + "</td>"
      + "<td>" + esc(f.mtype) + "</td>"
      + "<td>" + esc(modeLabel(f.mode, f.mode_name)) + "</td>"
      + '<td class="sg">' + esc(signed) + "</td>";
    wb.appendChild(tr);
  }
  if (state.wire.length === 0) {
    wb.innerHTML = '<tr><td colspan="5" class="empty">복호 wire 없음</td></tr>';
  }

  var ib = el("comms-inject").querySelector("tbody");
  ib.innerHTML = "";
  for (var j = 0; j < state.injections.length; j++) {
    var r = state.injections[j];
    var trj = document.createElement("tr");
    trj.className = r.accepted ? "inj-acc" : "inj-blk";
    var label = r.accepted ? "accepted" : (r.blocked_by ? "blocked(" + r.blocked_by + ")" : (r.verdict || "?"));
    trj.innerHTML =
      "<td>#" + esc(r.step) + "</td>"
      + "<td>" + esc(r.tool_id) + "</td>"
      + '<td class="layer">' + esc(r.layer) + "</td>"
      + "<td>" + esc(modeLabel(r.mode)) + "</td>"
      + '<td class="lbl">' + esc(label) + "</td>";
    ib.appendChild(trj);
  }
  if (state.injections.length === 0) {
    ib.innerHTML = '<tr><td colspan="5" class="empty">주입 스텝 없음</td></tr>';
  }
}

function setCommsSource(src) {
  var pill = el("comms-source");
  if (!src || src === "none") { pill.textContent = ""; pill.className = "pill"; return; }
  pill.textContent = "wire: " + src;
  pill.className = "pill " + (src === "stream" ? "pill-ok" : "pill-recon");
}

// ── 렌더: 감독 패널 ────────────────────────────────────────────────────────
function renderSupervisor() {
  var body = el("supervisor-body");
  var ev = state.evaluation;
  if (!ev) { body.innerHTML = '<p class="empty">감독 evaluation 미탑재</p>'; return; }
  var v = ev.verdict || {};
  var gt = ev.ground_truth || {};
  var acc = v.autonomy_accuracy || {};
  var tv = v.truth_verdict || "?";
  var tvClass = tv === "success" ? "b-win" : (tv === "pending" ? "b-warn" : "b-lose");

  function row(k, val) {
    return '<div class="kv"><span class="k">' + esc(k) + '</span><span class="val">' + esc(val) + "</span></div>";
  }
  function agreeBadge(a) {
    if (a === true) return '<span class="badge b-win">agree</span>';
    if (a === false) return '<span class="badge b-lose">disagree</span>';
    return '<span class="badge b-warn">n/a</span>';
  }

  var html = "";
  html += '<div class="sup-verdict"><span class="badge ' + tvClass + '">truth: ' + esc(tv) + "</span>";
  if (v.target_mode !== undefined && v.target_mode !== null)
    html += '<span class="badge">target: ' + esc(modeLabel(v.target_mode)) + "</span>";
  html += "</div>";

  html += '<h3>autonomy_accuracy</h3><div class="acc">';
  html += row("agent_reached", acc.agent_reached);
  html += row("truth_reached", acc.truth_reached);
  html += '<div class="kv"><span class="k">agree</span><span class="val">' + agreeBadge(acc.agree) + "</span></div>";
  html += "</div>";

  html += "<h3>ground_truth</h3><div class=\"gt\">";
  html += row("signing_observed", gt.signing_observed);
  html += row("final_mode", modeLabel(gt.final_mode));
  html += row("modes_ever_reached", Array.isArray(gt.modes_ever_reached)
    ? gt.modes_ever_reached.map(function (m) { return modeLabel(m); }).join(", ") : "");
  html += row("heartbeats", gt.heartbeats);
  html += row("decrypted_frames", gt.decrypted_frames);
  if (v.reverted !== undefined) html += row("reverted", v.reverted);
  if (v.note) html += row("note", v.note);
  html += "</div>";

  body.innerHTML = html;
}

// ── 초기 페인트 + SSE ──────────────────────────────────────────────────────
function applySnapshot(snap) {
  state.steps = (snap.action && snap.action.steps) || [];
  state.campaign = (snap.action && snap.action.campaign) || null;
  state.wire = (snap.comms && snap.comms.wire) || [];
  state.injections = (snap.comms && snap.comms.injections) || [];
  state.evaluation = (snap.supervisor && snap.supervisor.evaluation) || null;
  setCommsSource(snap.comms && snap.comms.source);
  renderBanner(snap.banner);
  renderAction(); renderComms(); renderSupervisor();
}

function connect() {
  var es = new EventSource("/sse");
  es.addEventListener("open", function () {
    var c = el("conn"); c.textContent = "실시간 연결됨"; c.className = "pill pill-ok";
  });
  es.addEventListener("error", function () {
    var c = el("conn"); c.textContent = "재연결 중…"; c.className = "pill pill-wait";
  });
  es.addEventListener("snapshot", function (e) { applySnapshot(JSON.parse(e.data)); });
  es.addEventListener("action", function (e) {
    var d = JSON.parse(e.data);
    if (Array.isArray(d.steps)) state.steps = state.steps.concat(d.steps);
    if (d.campaign) state.campaign = d.campaign;
    renderAction();
  });
  es.addEventListener("comms", function (e) {
    var d = JSON.parse(e.data);
    if (Array.isArray(d.frames)) state.wire = state.wire.concat(d.frames);
    if (Array.isArray(d.injections)) state.injections = d.injections;
    renderComms();
  });
  es.addEventListener("supervisor", function (e) {
    var d = JSON.parse(e.data);
    state.evaluation = d.evaluation || null;
    renderSupervisor();
    if (d.banner) renderBanner(d.banner);
  });
}

function boot() {
  fetch("/api/snapshot")
    .then(function (r) { return r.json(); })
    .then(function (snap) { applySnapshot(snap); })
    .catch(function () { /* snapshot 실패해도 SSE snapshot 이벤트가 채운다 */ })
    .then(function () { connect(); });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else { boot(); }
