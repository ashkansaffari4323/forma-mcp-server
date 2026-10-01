#!/usr/bin/env node
// =============================================================================
// Autodesk Platform Services (APS) sign-in helper  —  auth.js
// =============================================================================
//
//   node auth.js              Sign in via browser, save aps-tokens.json
//   node auth.js --check      Test the saved token (lists your hubs)
//   node auth.js --refresh    Refresh the saved token without a browser
//   node auth.js --diagnose   Explain WHY auth is failing (AUTH-001 etc.)
//   node auth.js --url        Just print the sign-in URL, don't open a browser
//
// Options:
//   --port 8080                     Local callback port
//   --redirect http://localhost:8080/callback
//   --scopes "data:read account:read"
//   --3leg-only                     Skip the app-token preflight check
//
// Env (or a .env file next to this script):
//   APS_CLIENT_ID      (or FORMA_CLIENT_ID)     required
//   APS_CLIENT_SECRET  (or FORMA_CLIENT_SECRET) omit for a PKCE/public app
//   APS_REDIRECT_URI, AUTH_PORT, APS_SCOPES, TOKEN_FILE
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN  optional — when set, the
//     sign-in is also saved to Upstash so a server running elsewhere (e.g.
//     Render) sees the same tokens. See tokenStore.js.
//
// Saves aps-tokens.json (chmod 600) next to this file.
// =============================================================================

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { exec } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readTokens as readTokensShared, writeTokens as writeTokensShared, tokenStoreStatus } from "./tokenStore.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Override only for testing against a mock/proxy; leave unset in normal use.
const BASE = process.env.APS_BASE_URL || "https://developer.api.autodesk.com";

// ---------------------------------------------------------------------------
// tiny .env loader (no dependencies)
// ---------------------------------------------------------------------------
function loadDotEnv() {
  const file = path.join(__dirname, ".env");
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
}
loadDotEnv();

// ---------------------------------------------------------------------------
// args + config
// ---------------------------------------------------------------------------
const argv = process.argv.slice(2);
const has = (...names) => names.some((n) => argv.includes(n));
const opt = (name, fallback) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
};

const MODE = has("--check")
  ? "check"
  : has("--refresh")
  ? "refresh"
  : has("--diagnose")
  ? "diagnose"
  : has("--url", "--print-url")
  ? "url"
  : "login";

const CLIENT_ID = process.env.APS_CLIENT_ID || process.env.FORMA_CLIENT_ID || "";
const CLIENT_SECRET = process.env.APS_CLIENT_SECRET || process.env.FORMA_CLIENT_SECRET || "";
const IS_CONFIDENTIAL = Boolean(CLIENT_SECRET);

// Scopes. Note: `user-profile:read` is legacy — v2 uses `user:read`.
// We request both so /userprofile and ACC Admin both work.
const DEFAULT_SCOPES =
  "data:read data:write data:create data:search account:read account:write user:read viewables:read";
// Minimal fallback set used automatically if the full set is rejected.
const FALLBACK_SCOPES = "data:read account:read user:read";
const SCOPES = opt("--scopes", process.env.APS_SCOPES || DEFAULT_SCOPES);

const REDIRECT_URI =
  opt("--redirect", process.env.APS_REDIRECT_URI) ||
  `http://localhost:${Number(opt("--port", process.env.AUTH_PORT || 8080))}/callback`;

let redirectUrl;
try {
  redirectUrl = new URL(REDIRECT_URI);
} catch {
  fail(`APS_REDIRECT_URI is not a valid URL: ${REDIRECT_URI}`);
}
const PORT = Number(opt("--port", redirectUrl.port || process.env.AUTH_PORT || 8080));
const CALLBACK_PATH = redirectUrl.pathname || "/callback";

const TOKEN_FILE = process.env.TOKEN_FILE || path.join(__dirname, "aps-tokens.json");

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const c = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

function fail(msg) {
  console.error(`\n${c.red("✗")} ${msg}\n`);
  process.exit(1);
}

function basicAuthHeader() {
  return "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
}

/** POST to the v2 token endpoint. Handles public (PKCE) vs confidential clients. */
async function tokenRequest(params) {
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
  };
  const body = { ...params };
  if (IS_CONFIDENTIAL) headers.Authorization = basicAuthHeader();
  else body.client_id = CLIENT_ID; // public client sends client_id in the body

  const res = await fetch(`${BASE}/authentication/v2/token`, {
    method: "POST",
    headers,
    body: new URLSearchParams(body).toString(),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* keep raw text */
  }
  return { ok: res.ok, status: res.status, json, text };
}

/** Turn an APS auth error into an actionable explanation. */
function explainAuthError(status, json, text) {
  const code = json?.errorCode || json?.error || "";
  const msg = json?.developerMessage || json?.error_description || text || "";
  const lines = [`HTTP ${status}${code ? ` · ${code}` : ""}`, msg].filter(Boolean);

  if (code === "AUTH-001" || /does not have access to the api product/i.test(msg)) {
    lines.push(
      "",
      c.bold("This is an app-registration problem, not a bad password."),
      "Your client_id exists, but it is not provisioned for the API you are calling.",
      "",
      "Fix it in this order:",
      "  1. https://aps.autodesk.com/myapps  →  open the app for this client_id",
      "  2. Under 'APIs' enable at least:  Data Management API,",
      "     BIM 360 API / ACC API, Account Admin.  Save and wait ~5 minutes.",
      "  3. If you need Forma: the Forma API is gated — request access from",
      "     Autodesk; enabling it in My Apps alone is not enough.",
      "  4. ACC Account Admin → Settings → Custom Integrations → 'Add custom",
      "     integration' and paste the SAME client_id, so the account trusts the app.",
      "  5. Re-run:  node auth.js"
    );
  } else if (/invalid_client/i.test(code) || status === 401) {
    lines.push("", "The client_id / client_secret pair was rejected. Re-copy both from My Apps.");
  } else if (/invalid_scope/i.test(code + msg)) {
    lines.push("", `Scope rejected. Retry with:  node auth.js --scopes "${FALLBACK_SCOPES}"`);
  } else if (/redirect/i.test(msg)) {
    lines.push(
      "",
      `The callback URL must match EXACTLY what is registered on the app:`,
      `  ${REDIRECT_URI}`
    );
  } else if (/invalid_grant/i.test(code)) {
    lines.push("", "The code or refresh token is expired/used. Run a fresh sign-in: node auth.js");
  }
  return lines.join("\n");
}

// Writes to Upstash (if configured, via UPSTASH_REDIS_REST_URL/TOKEN) AND the
// local file, so a server running elsewhere (e.g. Render) sees the same
// sign-in you just created here. See tokenStore.js.
async function saveTokens(j, extra = {}) {
  const now = Date.now();
  const previous = await readTokens();
  const payload = {
    access_token: j.access_token,
    refresh_token: j.refresh_token ?? previous?.refresh_token ?? null,
    token_type: j.token_type || "Bearer",
    scope: j.scope || SCOPES,
    expires_in: j.expires_in,
    expires_at: now + (j.expires_in ?? 3600) * 1000,
    obtained_at: now,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    ...extra,
  };
  await writeTokensShared(TOKEN_FILE, payload);
  return payload;
}

async function readTokens() {
  return readTokensShared(TOKEN_FILE);
}

function escapeHtml(s) {
  return String(s).replace(
    /[&<>"']/g,
    (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]
  );
}

function page(res, status, title, message, good = false) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<body style="font-family:system-ui,sans-serif;max-width:560px;margin:60px auto;line-height:1.6;color:#222">
  <h2 style="color:${good ? "#137333" : "#c5221f"}">${escapeHtml(title)}</h2>
  <p style="white-space:pre-wrap">${escapeHtml(message)}</p>
</body>`);
}

function openBrowser(url) {
  const cmd =
    process.platform === "win32"
      ? `start "" "${url}"`
      : process.platform === "darwin"
      ? `open "${url}"`
      : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

// ---------------------------------------------------------------------------
// preflight: catch AUTH-001 BEFORE opening a browser
// ---------------------------------------------------------------------------
async function preflight() {
  if (!IS_CONFIDENTIAL || has("--3leg-only")) return true;
  process.stdout.write("Checking app registration… ");
  const r = await tokenRequest({ grant_type: "client_credentials", scope: "data:read" });
  if (r.ok) {
    console.log(c.green("ok"));
    return true;
  }
  console.log(c.red("failed"));
  console.error("\n" + explainAuthError(r.status, r.json, r.text) + "\n");
  console.error(
    c.yellow("Sign-in would fail for the same reason, so it was not started.") +
      "\nTo try the browser flow anyway:  node auth.js --3leg-only\n"
  );
  return false;
}

// ---------------------------------------------------------------------------
// MODE: diagnose
// ---------------------------------------------------------------------------
async function diagnose() {
  console.log(c.bold("\nAPS auth diagnosis\n" + "─".repeat(40)));
  console.log(`client_id     ${CLIENT_ID ? CLIENT_ID.slice(0, 6) + "…" + CLIENT_ID.slice(-4) : c.red("MISSING")}`);
  console.log(`client_secret ${IS_CONFIDENTIAL ? "set (confidential app)" : "not set (PKCE/public app)"}`);
  console.log(`redirect_uri  ${REDIRECT_URI}`);
  console.log(`scopes        ${SCOPES}`);
  console.log(`token file    ${TOKEN_FILE} ${fs.existsSync(TOKEN_FILE) ? "(exists)" : c.dim("(none yet)")}`);
  console.log(`token store   ${tokenStoreStatus()}`);

  const t = await readTokens();
  if (t) {
    const mins = Math.round((t.expires_at - Date.now()) / 60000);
    console.log(
      `saved token   ${mins > 0 ? c.green(`valid ~${mins} min`) : c.yellow("EXPIRED")}` +
        (t.refresh_token ? ", refresh_token present" : c.yellow(", no refresh_token"))
    );
    if (t.client_id && t.client_id !== CLIENT_ID)
      console.log(c.yellow("  ! saved token was issued for a DIFFERENT client_id"));
  }

  if (!CLIENT_ID) fail("APS_CLIENT_ID is not set.");

  if (IS_CONFIDENTIAL) {
    console.log("\n2-legged (app) token…");
    const r = await tokenRequest({ grant_type: "client_credentials", scope: "data:read" });
    console.log(r.ok ? c.green("  ✓ works") : "  " + explainAuthError(r.status, r.json, r.text).split("\n").join("\n  "));
  }

  if (t?.access_token) {
    console.log("\n3-legged (user) token → GET /project/v1/hubs …");
    const res = await fetch(`${BASE}/project/v1/hubs`, {
      headers: { Authorization: `Bearer ${t.access_token}` },
    });
    const body = await res.text();
    console.log(res.ok ? c.green("  ✓ works") : c.red(`  ✗ HTTP ${res.status} ${body.slice(0, 300)}`));
  }
  console.log("");
}

// ---------------------------------------------------------------------------
// MODE: refresh
// ---------------------------------------------------------------------------
async function refresh() {
  const t = await readTokens();
  if (!t?.refresh_token) fail(`No refresh_token in ${TOKEN_FILE}. Run: node auth.js`);
  const r = await tokenRequest({
    grant_type: "refresh_token",
    refresh_token: t.refresh_token,
    scope: t.scope || SCOPES,
  });
  if (!r.ok) {
    console.error("\n" + explainAuthError(r.status, r.json, r.text));
    fail("Refresh failed. Run a full sign-in: node auth.js");
  }
  const saved = await saveTokens(r.json);
  console.log(
    `${c.green("✓")} Refreshed. Valid for ~${Math.round(saved.expires_in / 60)} min → ${TOKEN_FILE}`
  );
}

// ---------------------------------------------------------------------------
// MODE: check
// ---------------------------------------------------------------------------
async function check() {
  let t = await readTokens();
  if (!t?.access_token) fail(`No token found at ${TOKEN_FILE}. Run: node auth.js`);
  if (t.expires_at - Date.now() < 60_000 && t.refresh_token) {
    console.log(c.dim("Token expired — refreshing first…"));
    await refresh();
    t = await readTokens();
  }
  const res = await fetch(`${BASE}/project/v1/hubs`, {
    headers: { Authorization: `Bearer ${t.access_token}` },
  });
  const text = await res.text();
  if (!res.ok) {
    let j = null;
    try {
      j = JSON.parse(text);
    } catch {}
    console.error("\n" + explainAuthError(res.status, j, text));
    fail("Token is not usable.");
  }
  const data = JSON.parse(text);
  console.log(`\n${c.green("✓")} Token works. Hubs you can see:\n`);
  for (const h of data.data || []) {
    console.log(`  • ${h.attributes?.name}`);
    console.log(`    ${c.dim(`${h.id}  (${h.attributes?.extension?.type || h.type})`)}`);
  }
  // Region 403s are normal — only the account's own region answers.
  const warn = (data.meta?.warnings || []).length;
  if (warn) console.log(c.dim(`\n  (${warn} region warnings ignored — expected for single-region accounts)`));
  console.log("");
}

// ---------------------------------------------------------------------------
// MODE: login (authorization code + PKCE)
// ---------------------------------------------------------------------------
async function login({ urlOnly = false } = {}) {
  if (!CLIENT_ID) {
    fail(
      "APS_CLIENT_ID is not set.\n  export APS_CLIENT_ID=...\n  export APS_CLIENT_SECRET=...   # omit for a PKCE app\n  (or put them in a .env file next to auth.js)"
    );
  }
  if (!urlOnly && !(await preflight())) process.exit(1);

  const state = crypto.randomBytes(16).toString("hex");
  // PKCE — required for public apps, harmless and safer for confidential ones.
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  const authUrl =
    `${BASE}/authentication/v2/authorize?` +
    new URLSearchParams({
      response_type: "code",
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      state,
      prompt: "login",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }).toString();

  if (urlOnly) {
    console.log(authUrl);
    return;
  }

  let settled = false;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (url.pathname === "/favicon.ico") {
      res.writeHead(204).end();
      return;
    }
    if (url.pathname !== CALLBACK_PATH) {
      page(res, 404, "Not found", `Waiting for ${CALLBACK_PATH}`);
      return;
    }

    const error = url.searchParams.get("error");
    if (error) {
      const desc = url.searchParams.get("error_description") || "";
      page(res, 400, "Sign-in failed", `${error}: ${desc}`);
      console.error(c.red(`\n✗ Autodesk returned: ${error} ${desc}`));
      if (/invalid_scope/i.test(error + desc))
        console.error(`\nTry:  node auth.js --scopes "${FALLBACK_SCOPES}"`);
      if (/redirect/i.test(error + desc))
        console.error(`\nRegister this exact Callback URL on the app:\n  ${REDIRECT_URI}`);
      settled = true;
      server.close(() => process.exit(1));
      return;
    }
    if (url.searchParams.get("state") !== state) {
      page(res, 400, "Sign-in failed", "State mismatch (possible stale tab). Close this tab and run node auth.js again.");
      return;
    }
    const code = url.searchParams.get("code");
    if (!code) {
      page(res, 400, "Sign-in failed", "No authorization code received.");
      return;
    }

    try {
      const r = await tokenRequest({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: codeVerifier,
      });
      if (!r.ok) throw new Error(explainAuthError(r.status, r.json, r.text));

      const saved = await saveTokens(r.json);
      page(res, 200, "Signed in ✓", "All done. Close this tab and go back to the terminal.", true);

      console.log(`\n${c.green("✓")} Signed in. Saved to ${TOKEN_FILE}`);
      console.log(`  scopes granted: ${saved.scope}`);
      console.log(`  access token valid ~${Math.round((saved.expires_in ?? 3600) / 60)} min`);
      console.log(
        saved.refresh_token
          ? "  refresh token stored — run `node auth.js --refresh` to renew without a browser."
          : c.yellow("  no refresh token returned (add the `offline_access` scope if you need one).")
      );
      console.log(c.dim("  Keep this file private. Restart server.js to pick it up."));
      console.log(`\nVerify now with:  ${c.bold("node auth.js --check")}\n`);

      settled = true;
      server.close(() => process.exit(0));
    } catch (e) {
      page(res, 500, "Sign-in failed", e.message);
      console.error("\n" + e.message + "\n");
      settled = true;
      server.close(() => process.exit(1));
    }
  });

  server.on("error", (e) => {
    if (e.code === "EADDRINUSE")
      fail(`Port ${PORT} is already in use. Try:  node auth.js --port 8081\n  (then register http://localhost:8081/callback on your app)`);
    fail(e.message);
  });

  server.listen(PORT, "127.0.0.1", () => {
    console.log(`\nWaiting for sign-in on ${c.bold(REDIRECT_URI)}`);
    console.log(c.dim("This exact Callback URL must be registered at aps.autodesk.com/myapps"));
    console.log(c.dim(`Mode: ${IS_CONFIDENTIAL ? "confidential app + PKCE" : "public app (PKCE)"}`));
    console.log("\nIf the browser doesn't open, paste this URL:\n");
    console.log(authUrl + "\n");
    openBrowser(authUrl);
  });

  // Don't hang forever on an abandoned sign-in.
  setTimeout(() => {
    if (!settled) {
      console.error(c.yellow("\n✗ Timed out after 5 minutes waiting for sign-in."));
      server.close(() => process.exit(1));
    }
  }, 5 * 60_000).unref();
}

// ---------------------------------------------------------------------------
try {
  if (MODE === "check") await check();
  else if (MODE === "refresh") await refresh();
  else if (MODE === "diagnose") await diagnose();
  else if (MODE === "url") await login({ urlOnly: true });
  else await login();
} catch (e) {
  fail(e?.stack || String(e));
}
