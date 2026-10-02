// Shared sign-in storage for auth.js and server.js.
//
// Why this exists: Render's free tier wipes its local disk on every restart.
// Autodesk refresh tokens are single-use, so once a restart reverts to an
// old/used token, sign-in breaks permanently until a human re-runs auth.js.
//
// Fix: store the token in Upstash (a free, REST-based Redis) instead of only
// a local file. Both auth.js (on your PC) and server.js (on Render) read and
// write the SAME remote copy, so a refresh survives restarts.
//
// If UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN aren't set, this
// quietly falls back to file-only behavior — nothing breaks for local/stdio use.

import fs from "node:fs";

// Read lazily (at call time), NOT once at module load. auth.js and server.js
// both load their .env file via a plain function call that runs AFTER their
// top-level `import` statements have already executed — and ES module imports
// are evaluated before the rest of the importing file runs. So if these were
// read once up here, they'd always see "not set", even once .env has loaded.
const upstashUrl = () => process.env.UPSTASH_REDIS_REST_URL;
const upstashToken = () => process.env.UPSTASH_REDIS_REST_TOKEN;
const KEY = () => process.env.UPSTASH_TOKEN_KEY || "forma-mcp:aps-tokens";
const hasUpstash = () => Boolean(upstashUrl() && upstashToken());

async function redisCmd(cmd) {
  const res = await fetch(upstashUrl(), {
    method: "POST",
    headers: { Authorization: `Bearer ${upstashToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error(`Upstash returned non-JSON (HTTP ${res.status}): ${text.slice(0, 200)}`);
  }
  if (!res.ok || j.error) throw new Error(`Upstash error: ${j.error || res.status}`);
  return j.result;
}

function readLocal(tokenFile) {
  try {
    return JSON.parse(fs.readFileSync(tokenFile, "utf8"));
  } catch {
    return null;
  }
}
function writeLocal(tokenFile, t) {
  try {
    const tmp = `${tokenFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(t, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, tokenFile);
  } catch {
    // Read-only or missing dir (e.g. some hosts) — Upstash copy is still authoritative.
  }
}

// Reads Upstash first (if configured) since that's the shared source of truth;
// falls back to the local file so things still work with no Upstash set up.
export async function readTokens(tokenFile) {
  if (hasUpstash()) {
    try {
      const v = await redisCmd(["GET", KEY()]);
      if (v) return JSON.parse(v);
    } catch (e) {
      console.error(`[tokenStore] Upstash read failed, falling back to local file: ${e.message}`);
    }
  }
  return readLocal(tokenFile);
}

// Writes to BOTH so a local run and a deployed run never disagree.
export async function writeTokens(tokenFile, t) {
  writeLocal(tokenFile, t);
  if (hasUpstash()) {
    await redisCmd(["SET", KEY(), JSON.stringify(t)]);
  }
}

export function tokenStoreStatus() {
  return hasUpstash() ? `Upstash (key: ${KEY()})` : "local file only (set UPSTASH_REDIS_REST_URL/TOKEN to persist on Render)";
}