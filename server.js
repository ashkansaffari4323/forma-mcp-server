import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Never console.log in stdio mode (it would corrupt the protocol). Use stderr.
const log = (...a) => console.error(...a);

// ---------------------------------------------------------------------------
// .env loader (no dependency). Runs BEFORE any config is read.
// Real environment variables always win over the file.
// ---------------------------------------------------------------------------
function loadDotEnv() {
  const file = process.env.ENV_FILE || path.join(__dirname, ".env");
  if (!fs.existsSync(file)) return null;
  let n = 0;
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim().replace(/^export\s+/, "");
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) {
      process.env[key] = val;
      n++;
    }
  }
  return { file, count: n };
}
const dotenvResult = loadDotEnv();

// ---------------------------------------------------------------------------
// Config (all via environment variables)
// ---------------------------------------------------------------------------
// NOTE: precedence is APS_* first, then FORMA_* — this MATCHES auth.js.
// (The old build had these reversed, so a stale FORMA_CLIENT_ID could make
//  server.js and auth.js silently use two different apps.)
const CLIENT_ID = process.env.APS_CLIENT_ID || process.env.FORMA_CLIENT_ID;
const CLIENT_SECRET = process.env.APS_CLIENT_SECRET || process.env.FORMA_CLIENT_SECRET;
const BASE = process.env.APS_BASE_URL || "https://developer.api.autodesk.com";

// v2 uses `user:read`. The legacy `user-profile:read` breaks /userprofile calls.
const USER_SCOPES =
  process.env.APS_SCOPES ||
  "data:read data:write data:create data:search account:read account:write user:read";
const APP_SCOPES = process.env.APS_APP_SCOPES || "data:read data:write account:read";

// Data region for your ACC projects: AUS. Needed by some APIs (Account Admin, etc.).
const REGION = process.env.APS_REGION || "AUS";
const VALID_REGIONS = ["US", "EMEA", "AUS", "APAC", "CAN", "DEU", "IND", "GBR", "JPN"];

// Write requests (POST/PUT/PATCH/DELETE) are OFF unless you turn them on.
const ALLOW_WRITES = process.env.ALLOW_WRITES === "true";

// Optional: expose only some tool groups. Example: TOOL_GROUPS=core,docs,build,cost
const GROUP_FILTER = process.env.TOOL_GROUPS
  ? new Set(process.env.TOOL_GROUPS.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean))
  : null;

const TOKEN_FILE = process.env.TOKEN_FILE || path.join(__dirname, "aps-tokens.json");
const MAX_CHARS = 50000;

// --- credential sanity checks -----------------------------------------------
if (!CLIENT_ID || !CLIENT_SECRET) {
  log("");
  log("  ✗ Missing Autodesk credentials.");
  log("");
  log("  Set APS_CLIENT_ID and APS_CLIENT_SECRET. Easiest way: create a file named");
  log(`  .env next to this script (${path.join(__dirname, ".env")}) containing:`);
  log("");
  log("      APS_CLIENT_ID=your-client-id-here");
  log("      APS_CLIENT_SECRET=your-client-secret-here");
  log("");
  log("  Get both from https://aps.autodesk.com/myapps");
  log("");
  process.exit(1);
}

// Catch the classic copy/paste mistakes that cause 403 AUTH-001.
const idIssues = [];
if (/\s/.test(CLIENT_ID)) idIssues.push("contains a space or newline");
if (CLIENT_ID !== CLIENT_ID.trim()) idIssues.push("has leading/trailing whitespace");
if (/^(your|paste|xxx|<)/i.test(CLIENT_ID)) idIssues.push("still looks like a placeholder");
if (CLIENT_ID.length < 20) idIssues.push(`is only ${CLIENT_ID.length} characters (usually ~32) — possibly truncated`);
if (idIssues.length) {
  log(`  ! Warning: APS_CLIENT_ID ${idIssues.join("; ")}. This causes 403 AUTH-001.`);
}
// Warn when both variable families are set to DIFFERENT values.
if (
  process.env.APS_CLIENT_ID &&
  process.env.FORMA_CLIENT_ID &&
  process.env.APS_CLIENT_ID !== process.env.FORMA_CLIENT_ID
) {
  log("  ! Warning: APS_CLIENT_ID and FORMA_CLIENT_ID are both set to different values.");
  log("    Using APS_CLIENT_ID. Unset FORMA_CLIENT_ID to avoid confusion.");
}

const maskedId = `${CLIENT_ID.slice(0, 6)}…${CLIENT_ID.slice(-4)}`;

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------
/** Explain APS auth failures in plain language instead of dumping raw JSON. */
function authHelp(status, text) {
  let j = null;
  try {
    j = JSON.parse(text);
  } catch {}
  const code = j?.errorCode || j?.error || "";
  const msg = j?.developerMessage || j?.error_description || "";
  if (code === "AUTH-001" || /does not have access to the api product/i.test(msg + text)) {
    return (
      `\n\n  → AUTH-001 means client_id ${maskedId} is not provisioned for this API.` +
      `\n    1. https://aps.autodesk.com/myapps → open that app → enable Data Management API,` +
      `\n       ACC/BIM 360 API and Account Admin → Save → wait ~5 minutes.` +
      `\n    2. ACC Account Admin → Settings → Custom Integrations → add the SAME client_id.` +
      `\n    3. Forma API is separately gated — request access from Autodesk.` +
      `\n    4. Delete aps-tokens.json, run: node auth.js   then restart this server.`
    );
  }
  if (/invalid_client/i.test(code + msg) || status === 401) {
    return `\n\n  → The client_id/client_secret pair was rejected. Re-copy both from https://aps.autodesk.com/myapps`;
  }
  if (/invalid_grant/i.test(code + msg)) {
    return `\n\n  → The saved sign-in expired or was already used. Run: node auth.js`;
  }
  return "";
}

async function tokenRequest(params, what) {
  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const res = await fetch(`${BASE}/authentication/v2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams(params).toString(),
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${what} failed (${res.status}): ${text.slice(0, 500)}${authHelp(res.status, text)}`);
  return JSON.parse(text);
}

let appToken = null;
let appExpiresAt = 0;
async function getAppToken() {
  if (appToken && Date.now() < appExpiresAt - 60_000) return appToken;
  const j = await tokenRequest({ grant_type: "client_credentials", scope: APP_SCOPES }, "App token request");
  appToken = j.access_token;
  appExpiresAt = Date.now() + j.expires_in * 1000;
  return appToken;
}

// Signed-in user token, saved by auth.js. Autodesk refresh tokens are single-use,
// so every refresh is written back to disk.
function readTokens() {
  try {
    return JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  } catch {
    return null;
  }
}
function writeTokens(t) {
  // Atomic write so a concurrent read never sees a half-written file.
  const tmp = `${TOKEN_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(t, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, TOKEN_FILE);
}

let refreshing = null;
async function getUserToken() {
  const t = readTokens();
  if (!t || !t.refresh_token) return null;
  if (t.access_token && Date.now() < t.expires_at - 60_000) return t.access_token;

  if (!refreshing) {
    refreshing = (async () => {
      try {
        const current = readTokens() || t;
        const j = await tokenRequest(
          { grant_type: "refresh_token", refresh_token: current.refresh_token, scope: current.scope || USER_SCOPES },
          "Sign-in refresh (run `node auth.js` again to sign in)"
        );
        const next = {
          ...current,
          access_token: j.access_token,
          refresh_token: j.refresh_token || current.refresh_token,
          scope: j.scope || current.scope || USER_SCOPES,
          expires_at: Date.now() + j.expires_in * 1000,
          client_id: CLIENT_ID,
        };
        writeTokens(next);
        return next.access_token;
      } finally {
        refreshing = null;
      }
    })();
  }
  return refreshing;
}

// ---------------------------------------------------------------------------
// HTTP helper for Autodesk Platform Services
// ---------------------------------------------------------------------------
const AUTH_HINT =
  " Hint: many Autodesk Construction Cloud endpoints need a signed-in user token (run `node auth.js`), " +
  "your app's Client ID must be added in ACC Account Admin > Custom Integrations, " +
  `and some APIs need your data region (currently APS_REGION=${REGION}).`;

// auth: "user" = require signed-in token, "app" = app-only token,
//       undefined = prefer signed-in user, fall back to app token.
async function aps(method, pathname, { query, body, auth, region } = {}) {
  if (
    typeof pathname !== "string" ||
    !pathname.startsWith("/") ||
    pathname.includes("://") ||
    pathname.includes("..")
  ) {
    throw new Error("path must start with / and be an Autodesk API path, e.g. /project/v1/hubs");
  }

  let token = null;
  let used = "app";
  if (auth !== "app") {
    token = await getUserToken();
    if (token) used = "user";
    else if (auth === "user") throw new Error("No signed-in user token found. Run `node auth.js` once to sign in.");
  }
  if (!token) token = await getAppToken();

  let q = "";
  if (query) q = query.startsWith("?") ? query : `?${query}`;

  const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = region || REGION;
  if (r) {
    headers["Region"] = r;
    headers["x-ads-region"] = r;
  }

  const res = await fetch(`${BASE}${pathname}${q}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();

  if (!res.ok) {
    const hint = res.status === 401 || res.status === 403 ? AUTH_HINT + authHelp(res.status, text) : "";
    throw new Error(`${method} ${pathname} -> HTTP ${res.status} (${used} token). ${text.slice(0, 1500)}${hint}`);
  }
  if (!text) return { status: res.status, ok: true };
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function pack(data) {
  let s = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  if (s.length > MAX_CHARS) {
    s =
      s.slice(0, MAX_CHARS) +
      `\n\n[Output truncated at ${MAX_CHARS} characters. Narrow the request: use the query parameter (for example limit=25&offset=0 or a filter).]`;
  }
  return s;
}

// ---------------------------------------------------------------------------
// Helpers for building tools
// ---------------------------------------------------------------------------
const enc = encodeURIComponent;
const stripB = (id) => String(id).replace(/^b\./, "");
const pid = (id) => enc(stripB(id)); // ACC ids: no "b." prefix
const acct = (id) => enc(stripB(id)); // account id = hub id without "b."
const need = (a, ...keys) => {
  for (const k of keys) {
    if (a[k] === undefined || a[k] === null || a[k] === "") throw new Error(`Missing required argument: ${k}`);
  }
};
// Model Derivative wants a URL-safe base64 URN. Accept a raw version URN or an encoded one.
const derivUrn = (u) => {
  const s = String(u).trim();
  return enc(s.startsWith("urn:") ? Buffer.from(s).toString("base64url") : s);
};

const S = (description) => ({ type: "string", description });
const E = (values, description) => ({ type: "string", enum: values, description });
const QUERY = S(
  "Optional raw query string without the leading ?, e.g. limit=50&offset=0 or filter[status]=open. Use it to page or filter."
);
const HUB = S('Hub id, looks like "b.xxxxxxxx-..." (from aps_list_hubs).');
const PROJ = S('Project id from aps_list_projects. Works with or without the "b." prefix.');
const PROJ_B = S('Project id WITH the "b." prefix, exactly as returned by aps_list_projects.');
const ACCT = S('Account id. This is the hub id without the "b." prefix (the "b." is removed automatically if you include it).');

const tool = (name, group, description, properties, required, run) => ({
  name,
  group,
  description,
  inputSchema: { type: "object", properties, required },
  run,
});

// ---------------------------------------------------------------------------
// Reference cheat sheet (returned by aps_api_reference)
// ---------------------------------------------------------------------------
const REFERENCE = `Autodesk Platform Services quick reference (paths come after https://developer.api.autodesk.com).
Best-effort cheat sheet. If a call returns 404, check https://aps.autodesk.com/en/docs/acc/v1/

IDS
- hubId looks like "b.<uuid>". accountId = hubId without "b.".
- Data Management (/project, /data) needs project ids WITH "b."; /construction, /cost, /bim360 endpoints need project ids WITHOUT "b." (the project id is also the container id).
- Region: set APS_REGION (US, EMEA, AUS, APAC, CAN, DEU, IND, GBR, JPN) on the server. Account Admin needs it for many calls.

HUBS / PROJECTS / DOCS
  GET /project/v1/hubs
  GET /project/v1/hubs/{hubId}/projects
  GET /project/v1/hubs/{hubId}/projects/{projectId}/topFolders
  GET /data/v1/projects/{projectId}/folders/{folderId}/contents
  GET /data/v1/projects/{projectId}/folders/{folderId}/search?filter[attributes.displayName]-contains=text
  GET /data/v1/projects/{projectId}/items/{itemId} | /versions | /tip
  GET /data/v1/projects/{projectId}/versions/{versionId}
BUILD
  Issues       GET /construction/issues/v1/projects/{pid}/issues | issue-types | issues/{id} | issues/{id}/comments
  RFIs         GET /construction/rfis/v3/projects/{pid}/rfis | rfi-types | rfis/{id}
  Submittals   GET /construction/submittals/v2/projects/{pid}/items
  Forms        GET /construction/forms/v1/projects/{pid}/forms
  Sheets       GET /construction/sheets/v1/projects/{pid}/sheets
  Assets       GET /construction/assets/v2/projects/{pid}/assets
  Locations    GET /construction/locations/v2/projects/{pid}/trees/default/nodes
MODEL COORDINATION (needs a coordination space set up in the project)
  GET /bim360/modelset/v3/containers/{pid}/modelsets
  GET /bim360/modelset/v3/containers/{pid}/modelsets/{modelSetId}
  GET /bim360/modelset/v3/containers/{pid}/modelsets/{modelSetId}/versions/latest
  GET /bim360/clash/v3/containers/{pid}/modelsets/{modelSetId}/versions/{version}/tests
  GET /bim360/clash/v3/containers/{pid}/modelsets/{modelSetId}/clashes/assigned
TAKEOFF
  GET /construction/takeoff/v1/projects/{pid}/packages
  GET /construction/takeoff/v1/projects/{pid}/packages/{packageId}/takeoff-types
  GET /construction/takeoff/v1/projects/{pid}/packages/{packageId}/takeoff-items
COST MANAGEMENT
  GET /cost/v1/containers/{pid}/budgets | contracts | main-contracts | cost-items | expenses | payments
  GET /cost/v1/containers/{pid}/change-orders/{pco|rfq|rco|oco|sco}[/{id}]
  GET /cost/v1/containers/{pid}/taxes?associationId={id}&associationType=Contract
ACCOUNT / PROJECT ADMIN
  GET /construction/admin/v1/accounts/{accountId}/projects | users | companies | business-units-structure
  GET /construction/admin/v1/projects/{pid} | users | users/{userId} | companies
REPORTS (Data Connector; needs Account Executive or project admin)
  GET /data-connector/v1/accounts/{accountId}/requests
  GET /data-connector/v1/accounts/{accountId}/jobs | jobs/{jobId} | jobs/{jobId}/data-listing | jobs/{jobId}/data/{name}
3D MODELS (Model Derivative; urn = base64url of the file version urn, aps_encode_urn does this)
  GET /modelderivative/v2/designdata/{urn}/manifest
  GET /modelderivative/v2/designdata/{urn}/metadata
  GET /modelderivative/v2/designdata/{urn}/metadata/{viewGuid} | /properties

PAGING: most list endpoints accept limit and offset (some use a cursor); pass them via the query argument.
WRITES (server needs ALLOW_WRITES=true, and the call needs confirm=true after the user approves the exact change).
Examples: POST /cost/v1/containers/{pid}/budgets | contracts | cost-items ; PATCH /cost/v1/containers/{pid}/budgets/{id} ;
POST /construction/takeoff/v1/projects/{pid}/packages ; POST /bim360/modelset/v3/containers/{pid}/modelsets ;
POST /modelderivative/v2/designdata/job. Request bodies must follow the Autodesk reference for that endpoint.`;

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------
const BUILD_LIST = {
  issues: (p) => `/construction/issues/v1/projects/${p}/issues`,
  "issue-types": (p) => `/construction/issues/v1/projects/${p}/issue-types`,
  rfis: (p) => `/construction/rfis/v3/projects/${p}/rfis`,
  "rfi-types": (p) => `/construction/rfis/v3/projects/${p}/rfi-types`,
  submittals: (p) => `/construction/submittals/v2/projects/${p}/items`,
  forms: (p) => `/construction/forms/v1/projects/${p}/forms`,
  sheets: (p) => `/construction/sheets/v1/projects/${p}/sheets`,
  assets: (p) => `/construction/assets/v2/projects/${p}/assets`,
  locations: (p) => `/construction/locations/v2/projects/${p}/trees/default/nodes`,
};
const BUILD_GET = {
  issue: (p, id) => `/construction/issues/v1/projects/${p}/issues/${id}`,
  "issue-comments": (p, id) => `/construction/issues/v1/projects/${p}/issues/${id}/comments`,
  rfi: (p, id) => `/construction/rfis/v3/projects/${p}/rfis/${id}`,
  submittal: (p, id) => `/construction/submittals/v2/projects/${p}/items/${id}`,
};
const COST_LIST = ["budgets", "contracts", "main-contracts", "cost-items", "expenses", "payments", "change-orders"];
const CO_TYPES = "pco, rfq, rco, oco or sco";

const TOOLS_ALL = [
  // ===== core =====
  tool(
    "aps_whoami",
    "core",
    "Show which Autodesk user the server is signed in as. Use this first to confirm the connection works.",
    {},
    [],
    () => aps("GET", "/userprofile/v1/users/@me", { auth: "user" })
  ),
  tool(
    "aps_auth_status",
    "core",
    "Diagnose the Autodesk connection: which client_id is loaded, whether the app-only token works, whether a signed-in user token exists and is valid. Use this FIRST when anything returns 401/403.",
    {},
    [],
    async () => {
      const t = readTokens();
      const out = {
        client_id: maskedId,
        client_id_source: process.env.APS_CLIENT_ID ? "APS_CLIENT_ID" : "FORMA_CLIENT_ID",
        env_file: dotenvResult ? `${dotenvResult.file} (${dotenvResult.count} vars loaded)` : "none found",
        region: REGION,
        writes_enabled: ALLOW_WRITES,
        token_file: TOKEN_FILE,
        user_signin: t?.refresh_token ? "found" : "MISSING — run: node auth.js",
      };
      if (t?.expires_at) {
        const mins = Math.round((t.expires_at - Date.now()) / 60000);
        out.user_token = mins > 0 ? `valid ~${mins} min` : "expired (will auto-refresh)";
      }
      if (t?.client_id && t.client_id !== CLIENT_ID) {
        out.WARNING = "aps-tokens.json was issued for a DIFFERENT client_id. Delete it and run: node auth.js";
      }
      try {
        await getAppToken();
        out.app_token = "OK";
      } catch (e) {
        out.app_token = `FAILED — ${e.message}`;
      }
      try {
        const hubs = await aps("GET", "/project/v1/hubs", { auth: "user" });
        out.hubs = (hubs.data || []).map((h) => `${h.attributes?.name} (${h.id})`);
      } catch (e) {
        out.hubs = `FAILED — ${e.message}`;
      }
      return out;
    }
  ),
  tool(
    "aps_api_reference",
    "core",
    "Return a cheat sheet of Autodesk API paths (Docs, Build, Model Coordination, Takeoff, Cost, Admin, Reports, 3D models). Read this before using aps_request.",
    {},
    [],
    async () => REFERENCE
  ),
  tool(
    "aps_encode_urn",
    "core",
    "Convert a file version URN (urn:adsk.wipprod:fs.file:vf...?version=N) into the URL-safe base64 form that Model Derivative needs. Usually not required because model_info encodes automatically.",
    { urn: S("The raw file version URN.") },
    ["urn"],
    async (a) => (need(a, "urn"), { encodedUrn: Buffer.from(String(a.urn).trim()).toString("base64url") })
  ),
  tool(
    "aps_list_hubs",
    "core",
    "List the Autodesk hubs (accounts) the signed-in user can access. Start here to find hub ids.",
    { query: QUERY },
    [],
    (a) => aps("GET", "/project/v1/hubs", { query: a.query })
  ),
  tool(
    "aps_list_projects",
    "core",
    "List projects in a hub. Project ids from here are used by every Docs, Build, Cost, Takeoff and Model Coordination tool.",
    { hubId: HUB, query: QUERY },
    ["hubId"],
    (a) => (need(a, "hubId"), aps("GET", `/project/v1/hubs/${enc(a.hubId)}/projects`, { query: a.query }))
  ),

  // ===== docs =====
  tool(
    "docs_top_folders",
    "docs",
    "List the top-level folders of a project's Docs (Project Files, Plans, etc.).",
    { hubId: HUB, projectId: PROJ_B },
    ["hubId", "projectId"],
    (a) => (need(a, "hubId", "projectId"), aps("GET", `/project/v1/hubs/${enc(a.hubId)}/projects/${enc(a.projectId)}/topFolders`))
  ),
  tool(
    "docs_folder_contents",
    "docs",
    "List the files and subfolders inside a Docs folder.",
    { projectId: PROJ_B, folderId: S("Folder id (urn:adsk.wipprod:fs.folder:...)."), query: QUERY },
    ["projectId", "folderId"],
    (a) => (need(a, "projectId", "folderId"), aps("GET", `/data/v1/projects/${enc(a.projectId)}/folders/${enc(a.folderId)}/contents`, { query: a.query }))
  ),
  tool(
    "docs_search",
    "docs",
    "Search a Docs folder (and its subfolders) for files whose name contains some text.",
    { projectId: PROJ_B, folderId: S("Folder id to search under."), text: S("Text the file name should contain.") },
    ["projectId", "folderId", "text"],
    (a) => (
      need(a, "projectId", "folderId", "text"),
      aps("GET", `/data/v1/projects/${enc(a.projectId)}/folders/${enc(a.folderId)}/search`, {
        query: `filter[attributes.displayName]-contains=${enc(a.text)}`,
      })
    )
  ),
  tool(
    "docs_get",
    "docs",
    "Get details of a Docs folder, file (item), a file's version history, its latest version (tip), or one specific version. Version ids are what model_info needs for 3D models.",
    {
      projectId: PROJ_B,
      kind: E(["folder", "item", "item_versions", "item_tip", "version"], "What to fetch."),
      id: S("The folder id, item id (urn:adsk.wipprod:dm.lineage:...) or version id (urn:adsk.wipprod:fs.file:vf...?version=N)."),
    },
    ["projectId", "kind", "id"],
    (a) => {
      need(a, "projectId", "kind", "id");
      const p = enc(a.projectId);
      const id = enc(a.id);
      const map = {
        folder: `/data/v1/projects/${p}/folders/${id}`,
        item: `/data/v1/projects/${p}/items/${id}`,
        item_versions: `/data/v1/projects/${p}/items/${id}/versions`,
        item_tip: `/data/v1/projects/${p}/items/${id}/tip`,
        version: `/data/v1/projects/${p}/versions/${id}`,
      };
      if (!map[a.kind]) throw new Error(`kind must be one of: ${Object.keys(map).join(", ")}`);
      return aps("GET", map[a.kind]);
    }
  ),

  // ===== build =====
  tool(
    "build_list",
    "build",
    "List records in an Autodesk Build project: issues, issue-types, rfis, rfi-types, submittals, forms, sheets, assets, or locations. Filter and page with query, e.g. filter[status]=open&limit=50.",
    { projectId: PROJ, resource: E(Object.keys(BUILD_LIST), "What to list."), query: QUERY },
    ["projectId", "resource"],
    (a) => {
      need(a, "projectId", "resource");
      const f = BUILD_LIST[a.resource];
      if (!f) throw new Error(`resource must be one of: ${Object.keys(BUILD_LIST).join(", ")}`);
      return aps("GET", f(pid(a.projectId)), { query: a.query });
    }
  ),
  tool(
    "build_get",
    "build",
    "Get full details of one issue, one RFI, or one submittal, or the comments on an issue.",
    {
      projectId: PROJ,
      resource: E(Object.keys(BUILD_GET), "What to fetch."),
      id: S("The issue id, RFI id or submittal item id."),
      query: QUERY,
    },
    ["projectId", "resource", "id"],
    (a) => {
      need(a, "projectId", "resource", "id");
      const f = BUILD_GET[a.resource];
      if (!f) throw new Error(`resource must be one of: ${Object.keys(BUILD_GET).join(", ")}`);
      return aps("GET", f(pid(a.projectId), enc(a.id)), { query: a.query });
    }
  ),

  // ===== model coordination =====
  tool(
    "mc_list_model_sets",
    "coordination",
    "List Model Coordination model sets (coordination spaces) in a project. Requires a coordination space to be set up in the project.",
    { projectId: PROJ, query: QUERY },
    ["projectId"],
    (a) => (need(a, "projectId"), aps("GET", `/bim360/modelset/v3/containers/${pid(a.projectId)}/modelsets`, { query: a.query }))
  ),
  tool(
    "mc_model_set_versions",
    "coordination",
    "Get versions of a model set. Use version=latest (default) for the newest version, or version=all to list every version, or a number for a specific one.",
    { projectId: PROJ, modelSetId: S("Model set id."), version: S("latest (default), all, or a version number.") },
    ["projectId", "modelSetId"],
    (a) => {
      need(a, "projectId", "modelSetId");
      const base = `/bim360/modelset/v3/containers/${pid(a.projectId)}/modelsets/${enc(a.modelSetId)}`;
      const v = String(a.version || "latest");
      if (v === "all") return aps("GET", `${base}/versions`);
      return aps("GET", `${base}/versions/${enc(v)}`);
    }
  ),
  tool(
    "mc_clash_tests",
    "coordination",
    "List clash tests that ran for a model set version (results of automated 3D clash detection).",
    { projectId: PROJ, modelSetId: S("Model set id."), version: S("Model set version number (see mc_model_set_versions).") },
    ["projectId", "modelSetId", "version"],
    (a) => (
      need(a, "projectId", "modelSetId", "version"),
      aps("GET", `/bim360/clash/v3/containers/${pid(a.projectId)}/modelsets/${enc(a.modelSetId)}/versions/${enc(a.version)}/tests`)
    )
  ),
  tool(
    "mc_assigned_clash_groups",
    "coordination",
    "List clash groups that have been assigned to people in a model set.",
    { projectId: PROJ, modelSetId: S("Model set id."), query: QUERY },
    ["projectId", "modelSetId"],
    (a) => (
      need(a, "projectId", "modelSetId"),
      aps("GET", `/bim360/clash/v3/containers/${pid(a.projectId)}/modelsets/${enc(a.modelSetId)}/clashes/assigned`, { query: a.query })
    )
  ),

  // ===== takeoff =====
  tool(
    "takeoff_list",
    "takeoff",
    "Read ACC Takeoff data: packages in a project, the takeoff types in a package, or the takeoff items (quantities) in a package.",
    {
      projectId: PROJ,
      resource: E(["packages", "types", "items"], "What to list."),
      packageId: S("Package id. Required for types and items (get it from resource=packages)."),
      query: QUERY,
    },
    ["projectId", "resource"],
    (a) => {
      need(a, "projectId", "resource");
      const base = `/construction/takeoff/v1/projects/${pid(a.projectId)}/packages`;
      if (a.resource === "packages") return aps("GET", base, { query: a.query });
      need(a, "packageId");
      if (a.resource === "types") return aps("GET", `${base}/${enc(a.packageId)}/takeoff-types`, { query: a.query });
      if (a.resource === "items") return aps("GET", `${base}/${enc(a.packageId)}/takeoff-items`, { query: a.query });
      throw new Error("resource must be packages, types or items");
    }
  ),

  // ===== cost =====
  tool(
    "cost_list",
    "cost",
    `List Cost Management records: ${COST_LIST.join(", ")}. For change-orders you must also give changeOrderType (${CO_TYPES}).`,
    {
      projectId: PROJ,
      resource: E(COST_LIST, "What to list."),
      changeOrderType: S(`Only for change-orders: ${CO_TYPES}.`),
      query: QUERY,
    },
    ["projectId", "resource"],
    (a) => {
      need(a, "projectId", "resource");
      if (!COST_LIST.includes(a.resource)) throw new Error(`resource must be one of: ${COST_LIST.join(", ")}`);
      const base = `/cost/v1/containers/${pid(a.projectId)}`;
      if (a.resource === "change-orders") {
        need(a, "changeOrderType");
        return aps("GET", `${base}/change-orders/${enc(a.changeOrderType)}`, { query: a.query });
      }
      return aps("GET", `${base}/${a.resource}`, { query: a.query });
    }
  ),
  tool(
    "cost_get",
    "cost",
    "Get one Cost Management record by id (budget, contract, main contract, cost item, expense, payment, or change order).",
    {
      projectId: PROJ,
      resource: E(COST_LIST, "What kind of record."),
      id: S("The record id."),
      changeOrderType: S(`Only for change-orders: ${CO_TYPES}.`),
      query: QUERY,
    },
    ["projectId", "resource", "id"],
    (a) => {
      need(a, "projectId", "resource", "id");
      if (!COST_LIST.includes(a.resource)) throw new Error(`resource must be one of: ${COST_LIST.join(", ")}`);
      const base = `/cost/v1/containers/${pid(a.projectId)}`;
      if (a.resource === "change-orders") {
        need(a, "changeOrderType");
        return aps("GET", `${base}/change-orders/${enc(a.changeOrderType)}/${enc(a.id)}`, { query: a.query });
      }
      return aps("GET", `${base}/${a.resource}/${enc(a.id)}`, { query: a.query });
    }
  ),

  // ===== admin =====
  tool(
    "admin_list",
    "admin",
    "Account and project administration lists. resource: account-projects, account-users, account-companies, business-units (need accountId) or project-users, project-companies (need projectId). If Autodesk answers with a region error, set APS_REGION on the server.",
    {
      resource: E(
        ["account-projects", "account-users", "account-companies", "business-units", "project-users", "project-companies"],
        "What to list."
      ),
      accountId: ACCT,
      projectId: PROJ,
      query: QUERY,
    },
    ["resource"],
    (a) => {
      need(a, "resource");
      const accountPaths = {
        "account-projects": "projects",
        "account-users": "users",
        "account-companies": "companies",
        "business-units": "business-units-structure",
      };
      const projectPaths = { "project-users": "users", "project-companies": "companies" };
      if (accountPaths[a.resource]) {
        need(a, "accountId");
        return aps("GET", `/construction/admin/v1/accounts/${acct(a.accountId)}/${accountPaths[a.resource]}`, { query: a.query });
      }
      if (projectPaths[a.resource]) {
        need(a, "projectId");
        return aps("GET", `/construction/admin/v1/projects/${pid(a.projectId)}/${projectPaths[a.resource]}`, { query: a.query });
      }
      throw new Error("Unknown resource");
    }
  ),
  tool(
    "admin_get",
    "admin",
    "Get details of one project (kind=project) or one user on a project including roles and product access (kind=project-user, needs userId).",
    {
      projectId: PROJ,
      kind: E(["project", "project-user"], "What to fetch."),
      userId: S("User id (ACC id or Autodesk id). Only for project-user."),
    },
    ["projectId", "kind"],
    (a) => {
      need(a, "projectId", "kind");
      const base = `/construction/admin/v1/projects/${pid(a.projectId)}`;
      if (a.kind === "project") return aps("GET", base);
      need(a, "userId");
      return aps("GET", `${base}/users/${enc(a.userId)}`);
    }
  ),

  // ===== reports (Data Connector) =====
  tool(
    "reports_list_requests",
    "reports",
    "List Data Connector report requests (scheduled data extracts of Issues, RFIs, Cost, Admin and more) for an account. Needs Account Executive or project admin permissions.",
    { accountId: ACCT, query: QUERY },
    ["accountId"],
    (a) => (need(a, "accountId"), aps("GET", `/data-connector/v1/accounts/${acct(a.accountId)}/requests`, { query: a.query }))
  ),
  tool(
    "reports_list_jobs",
    "reports",
    "List report jobs for an account, or the jobs of one request (give requestId), or the status of one job (give jobId).",
    { accountId: ACCT, requestId: S("Optional. Only jobs for this request."), jobId: S("Optional. Details of one job."), query: QUERY },
    ["accountId"],
    (a) => {
      need(a, "accountId");
      const base = `/data-connector/v1/accounts/${acct(a.accountId)}`;
      if (a.jobId) return aps("GET", `${base}/jobs/${enc(a.jobId)}`);
      if (a.requestId) return aps("GET", `${base}/requests/${enc(a.requestId)}/jobs`, { query: a.query });
      return aps("GET", `${base}/jobs`, { query: a.query });
    }
  ),
  tool(
    "reports_data_listing",
    "reports",
    "List the files (CSV per service, README, ZIP) inside a finished report job's data extract.",
    { accountId: ACCT, jobId: S("Job id (from reports_list_jobs).") },
    ["accountId", "jobId"],
    (a) => (need(a, "accountId", "jobId"), aps("GET", `/data-connector/v1/accounts/${acct(a.accountId)}/jobs/${enc(a.jobId)}/data-listing`))
  ),
  tool(
    "reports_get_file",
    "reports",
    "Download one file from a report job's data extract and return its text (CSV, README, etc.). Large files are truncated; use the README first to learn the columns.",
    { accountId: ACCT, jobId: S("Job id."), name: S("File name exactly as shown by reports_data_listing.") },
    ["accountId", "jobId", "name"],
    async (a) => {
      need(a, "accountId", "jobId", "name");
      const j = await aps("GET", `/data-connector/v1/accounts/${acct(a.accountId)}/jobs/${enc(a.jobId)}/data/${enc(a.name)}`);
      const url = j && typeof j === "object" ? j.signedUrl || j.signed_url || j.url : null;
      const textual = /\.(csv|txt|md|json|readme)$/i.test(a.name) || /readme/i.test(a.name);
      if (url && textual) {
        const r = await fetch(url, { signal: AbortSignal.timeout(60000) });
        if (!r.ok) throw new Error(`Download failed (HTTP ${r.status}). Signed links expire after 60 seconds; try again.`);
        return await r.text();
      }
      return j;
    }
  ),

  // ===== 3D models (Model Derivative) =====
  tool(
    "model_info",
    "models",
    "Read data about a 3D/BIM model (Revit, IFC, DWG, etc.) that has been translated: kind=manifest (translation status and derivatives), views (list of model views with viewGuid), tree (object hierarchy, needs viewGuid) or properties (object properties, needs viewGuid; add objectid=NN in query to narrow). urn is the file VERSION urn from docs_get; it is encoded automatically.",
    {
      urn: S("File version URN (urn:adsk.wipprod:fs.file:vf...?version=N) or its base64url form."),
      kind: E(["manifest", "views", "tree", "properties"], "What to fetch."),
      viewGuid: S("Required for tree and properties. Get it from kind=views."),
      query: QUERY,
    },
    ["urn", "kind"],
    (a) => {
      need(a, "urn", "kind");
      const base = `/modelderivative/v2/designdata/${derivUrn(a.urn)}`;
      if (a.kind === "manifest") return aps("GET", `${base}/manifest`);
      if (a.kind === "views") return aps("GET", `${base}/metadata`);
      need(a, "viewGuid");
      if (a.kind === "tree") return aps("GET", `${base}/metadata/${enc(a.viewGuid)}`, { query: a.query });
      if (a.kind === "properties") return aps("GET", `${base}/metadata/${enc(a.viewGuid)}/properties`, { query: a.query });
      throw new Error("kind must be manifest, views, tree or properties");
    }
  ),

  // ===== Forma site design =====
  // NOTE: the Forma API is gated. Even a correctly registered app returns 403
  // until Autodesk grants your client_id access to the Forma API product.
  tool(
    "forma_get_element",
    "forma",
    "Get a single Forma site-design element by its URN. Requires Forma API access to be granted by Autodesk for your client_id.",
    { urn: S("The element URN.") },
    ["urn"],
    (a) => (need(a, "urn"), aps("GET", `/forma/v1alpha/elements/${enc(a.urn)}`, { auth: "app" }))
  ),
  tool(
    "forma_list_generators",
    "forma",
    "List generators in a Forma site-design project. Requires Forma API access to be granted by Autodesk for your client_id.",
    { projectId: S("The Forma project id.") },
    ["projectId"],
    (a) => (need(a, "projectId"), aps("GET", `/forma/v1alpha/generators?projectId=${enc(a.projectId)}`, { auth: "app" }))
  ),

  // ===== generic access to any Autodesk API =====
  tool(
    "aps_request",
    "core",
    "Call ANY Autodesk Platform Services endpoint not covered by the other tools. GET works by default. " +
      "POST/PUT/PATCH/DELETE only work if the server enabled writes AND confirm=true; before that, tell the user exactly what will change and get their approval. " +
      "Call aps_api_reference first for paths.",
    {
      method: S("GET (default), POST, PUT, PATCH or DELETE."),
      path: S("API path starting with /, e.g. /project/v1/hubs. Do not include the host."),
      query: QUERY,
      body: S("JSON request body as a string (for POST/PUT/PATCH)."),
      auth: S("Optional: 'user' to force the signed-in user token, 'app' for the app-only token. Default prefers the user token."),
      region: S(`Optional: one of ${VALID_REGIONS.join(", ")}. Overrides the server's default data region (${REGION}) for this call.`),
      confirm: { type: "boolean", description: "Must be true for any non-GET request, only after the user approved it." },
    },
    ["path"],
    async (a) => {
      need(a, "path");
      const method = String(a.method || "GET").toUpperCase();
      if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
        throw new Error("method must be GET, POST, PUT, PATCH or DELETE");
      }
      if (method !== "GET") {
        if (!ALLOW_WRITES) {
          throw new Error("Write requests are disabled on this server. Start it with ALLOW_WRITES=true to enable POST/PUT/PATCH/DELETE.");
        }
        if (a.confirm !== true) {
          throw new Error("This changes data. Describe the exact change to the user, get their approval, then retry with confirm=true.");
        }
      }
      let body;
      if (a.body !== undefined && a.body !== "") body = typeof a.body === "string" ? JSON.parse(a.body) : a.body;
      if (a.auth && !["user", "app"].includes(a.auth)) throw new Error("auth must be 'user' or 'app'");
      // FIX: AUS (and other regions) are now accepted. The old build only allowed US/EMEA,
      // which made region:"AUS" throw even though the server default is AUS.
      if (a.region && !VALID_REGIONS.includes(String(a.region).toUpperCase())) {
        throw new Error(`region must be one of: ${VALID_REGIONS.join(", ")}`);
      }
      return aps(method, a.path, {
        query: a.query,
        body,
        auth: a.auth,
        region: a.region ? String(a.region).toUpperCase() : undefined,
      });
    }
  ),
];

const TOOLS = GROUP_FILTER
  ? TOOLS_ALL.filter((t) => t.group === "core" || GROUP_FILTER.has(t.group))
  : TOOLS_ALL;
const TOOL_MAP = new Map(TOOLS.map((t) => [t.name, t]));

// ---------------------------------------------------------------------------
// MCP server
// ---------------------------------------------------------------------------
function createServer() {
  const server = new Server({ name: "forma-mcp", version: "0.4.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const t = TOOL_MAP.get(name);
    try {
      if (!t) throw new Error(`Unknown tool: ${name}`);
      const data = await t.run(args || {});
      return { content: [{ type: "text", text: pack(data) }] };
    } catch (err) {
      return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Transport selection
//   node server.js                -> stdio (VS Code / GitHub Copilot)
//   TRANSPORT=http node server.js -> HTTP at /mcp (Copilot Studio via ngrok or hosting)
// ---------------------------------------------------------------------------
const mode = process.env.TRANSPORT || "stdio";
log(
  `forma-mcp v0.4.0 | transport=${mode} | tools=${TOOLS.length} | client_id=${maskedId} | ` +
    `env=${dotenvResult ? "loaded .env" : "process env only"} | writes=${ALLOW_WRITES ? "ENABLED" : "off"} | ` +
    `region=${REGION} | user sign-in=${readTokens()?.refresh_token ? "found" : "NOT FOUND (run node auth.js)"}`
);

if (mode === "http") {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

  const PORT = process.env.PORT || 3000;
  const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;

  app.get("/health", (_req, res) => res.json({ ok: true, tools: TOOLS.length }));
  app.get("/mcp", (_req, res) =>
    res.status(405).send("This is an MCP endpoint. Connect with an MCP client (POST requests only).")
  );

  app.post("/mcp", async (req, res) => {
    if (AUTH_TOKEN) {
      const header = req.headers["authorization"] || "";
      if (header !== `Bearer ${AUTH_TOKEN}`) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }
    }
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  app.listen(PORT, () => {
    log(`forma-mcp HTTP server listening on port ${PORT} (endpoint: /mcp, health: /health)`);
  });
} else {
  const server = createServer();
  await server.connect(new StdioServerTransport());
}
