const DASHBOARD_PASSWORD = "CHANGE_ME_TO_YOUR_OWN_PASSWORD";

// Default number of configs to take from each group per rotation round (can be changed in the UI)
const DEFAULT_ROTATION_CHUNK = 3;

// Initial configurations if database is empty
const defaultGroups = {
  "Germany_Server": {
    mode: "configs",
    configs: [
      "vless://example-de-1@1.1.1.1:443?type=ws"
    ],
    subUrls: [],
    cachedSubConfigs: []
  }
};

// Any "scheme://" at the start of a line begins a NEW entry (this is what keeps configs from being glued together)
const SCHEME_LINE_RE = /^[a-z][a-z0-9+.\-]*:\/\//i;

// Protocols that are treated as proxy configs
const KNOWN_PROTOCOLS = new Set([
  'vless', 'vmess', 'trojan', 'ss', 'ssr',
  'hysteria2', 'hy2', 'hysteria', 'tuic',
  'wireguard', 'wg', 'socks', 'socks5', 'anytls', 'juicity'
]);

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

/* ------------------------------------------------------------------ */
/* Auth helpers                                                        */
/* ------------------------------------------------------------------ */

async function getAuthToken() {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('vpn-hub:' + DASHBOARD_PASSWORD));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(header, name) {
  const parts = String(header || '').split(';');
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx === -1) continue;
    if (p.slice(0, idx).trim() === name) return p.slice(idx + 1).trim();
  }
  return '';
}

function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ------------------------------------------------------------------ */
/* Request handler                                                     */
/* ------------------------------------------------------------------ */

async function handleRequest(request) {
  const url = new URL(request.url);
  const subToken = await envFetchOrCreateSubToken();
  const isProtectedSubMatch =
    url.pathname === `/sub/${subToken}` ||
    url.pathname === `/sub-${subToken}` ||
    (url.pathname === '/sub' && url.searchParams.get('key') === subToken) ||
    url.searchParams.get('raw') === subToken;

  // 1. ONLY ALLOW THE VPN APP TO FETCH CONFIGS WITH THE SECRET 6-DIGIT SUBSCRIPTION CODE
  if (isProtectedSubMatch) {
    let serverGroups = await envFetchGroups();
    let rotationChunk = await envFetchRotationChunk();

    // Optional query override e.g. /sub/123456?chunk=5
    if (url.searchParams.has('chunk')) {
      const qChunk = parseInt(url.searchParams.get('chunk'), 10);
      if (Number.isFinite(qChunk) && qChunk >= 1) {
        rotationChunk = qChunk;
      }
    }

    // Resolve each group's active configs (direct configs OR live-fetched subscription URLs)
    const groupNames = Object.keys(serverGroups);
    const cleaned = {};
    let kvCacheUpdated = false;

    await Promise.all(groupNames.map(async (g) => {
      const entry = normalizeGroupEntry(serverGroups[g]);
      if (entry.mode === 'sub') {
        if (entry.subUrls.length > 0) {
          const fetchResult = await fetchAndDecodeSubUrls(entry.subUrls);
          if (fetchResult.configs.length > 0) {
            cleaned[g] = fetchResult.configs;
            if (JSON.stringify(entry.cachedSubConfigs) !== JSON.stringify(fetchResult.configs)) {
              entry.cachedSubConfigs = fetchResult.configs;
              serverGroups[g] = entry;
              kvCacheUpdated = true;
            }
          } else {
            // Fallback to cached configs if remote subscription server is temporarily unreachable
            cleaned[g] = Array.isArray(entry.cachedSubConfigs) ? entry.cachedSubConfigs.filter(c => typeof c === 'string' && c.trim() !== '') : [];
          }
        } else {
          cleaned[g] = [];
        }
      } else {
        // Direct configs mode (also resolves any http/https subscription URL if pasted directly)
        const resolvedDirect = [];
        for (const line of entry.configs) {
          const trimmed = String(line || '').trim();
          if (!trimmed) continue;
          if (isHttpUrl(trimmed)) {
            const subRes = await fetchAndDecodeSubUrls([trimmed]);
            subRes.configs.forEach(c => resolvedDirect.push(c));
          } else {
            resolvedDirect.push(trimmed);
          }
        }
        cleaned[g] = resolvedDirect;
      }
    }));

    if (kvCacheUpdated) {
      try {
        await VPN_DB.put("server_groups", JSON.stringify(serverGroups));
      } catch (e) {}
    }

    // Round-robin: take rotationChunk configs from group 1, then group 2, ...
    // then loop back for the next rotationChunk from each, until all are used.
    const allConfigs = [];
    let offset = 0;
    while (true) {
      let addedAny = false;
      for (const group of groupNames) {
        const list = cleaned[group] || [];
        const slice = list.slice(offset, offset + rotationChunk);
        if (slice.length === 0) continue;
        addedAny = true;
        const cleanGroupName = group.replace(/_/g, ' ');
        slice.forEach(config => {
          allConfigs.push(renameConfigWithIP(config, cleanGroupName));
        });
      }
      if (!addedAny) break;
      offset += rotationChunk;
    }

    const subscriptionContent = allConfigs.join('\n');
    // Use ?format=plain if you ever want to inspect unencoded output in browser
    const outputBody = url.searchParams.get('format') === 'plain'
      ? subscriptionContent
      : btoa(unescape(encodeURIComponent(subscriptionContent)));

    return new Response(outputBody, {
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Access-Control-Allow-Origin': '*',
        'Profile-Title': btoa(unescape(encodeURIComponent('VPN Subscription Hub'))),
        'Profile-Update-Interval': '12'
      },
    });
  }

  // Block bare /sub or wrong /sub/... tokens so scanners cannot guess or scrape the link
  if (url.pathname === '/sub' || url.pathname.startsWith('/sub/') || url.pathname.startsWith('/sub-')) {
    return new Response('404 Not Found', {
      status: 404,
      headers: { 'content-type': 'text/plain; charset=utf-8' }
    });
  }

  // 2. CHECK LOGIN COOKIE FOR WEB DASHBOARD ACCESS
  const authToken = await getAuthToken();
  const isLoggedIn = safeEqual(getCookie(request.headers.get('Cookie'), 'auth_token'), authToken);

  // Handle Login Request Verification
  if (request.method === 'POST' && url.pathname === '/login') {
    try {
      const data = await request.json();
      if (typeof data.password === 'string' && safeEqual(data.password, DASHBOARD_PASSWORD)) {
        return new Response(JSON.stringify({ success: true }), {
          headers: {
            'content-type': 'application/json',
            'Set-Cookie': `auth_token=${authToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000` // 30 Days
          }
        });
      }
      return new Response(JSON.stringify({ success: false, error: "Incorrect Password" }), { status: 403, headers: { 'content-type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  // If not logged in, force show the Login Page layout
  if (!isLoggedIn) {
    return new Response(getLoginPageHTML(), {
      headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  }

  // 3. SECURE ENDPOINTS (Only active if logged in via cookie verification)
  if (request.method === 'POST' && url.pathname === '/fetch-sub') {
    try {
      const body = await request.json();
      const rawUrls = Array.isArray(body.urls) ? body.urls : (typeof body.url === 'string' ? [body.url] : []);
      const validUrls = rawUrls.map(u => String(u || '').trim()).filter(u => isHttpUrl(u));
      if (validUrls.length === 0) {
        return new Response(JSON.stringify({
          success: false,
          error: "Please enter at least one valid http:// or https:// subscription link.",
          configs: [],
          count: 0
        }), { status: 400, headers: { 'content-type': 'application/json' } });
      }
      const result = await fetchAndDecodeSubUrls(validUrls);
      return new Response(JSON.stringify({
        success: result.configs.length > 0 || result.errors.length === 0,
        configs: result.configs,
        count: result.configs.length,
        errors: result.errors
      }), { headers: { 'content-type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message, configs: [], count: 0 }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  if (request.method === 'POST' && url.pathname === '/save') {
    try {
      const data = await request.json();
      if (data && data.groups && typeof data.groups === 'object') {
        const normalizedGroups = {};
        const groupKeys = Object.keys(data.groups);
        await Promise.all(groupKeys.map(async (k) => {
          const entry = normalizeGroupEntry(data.groups[k]);
          if (entry.mode === 'sub' && entry.subUrls.length > 0) {
            const res = await fetchAndDecodeSubUrls(entry.subUrls);
            if (res.configs.length > 0) {
              entry.cachedSubConfigs = res.configs;
            }
          }
          normalizedGroups[k] = entry;
        }));
        // Keep the order the user arranged in the UI
        const orderedGroups = {};
        groupKeys.forEach(k => { orderedGroups[k] = normalizedGroups[k]; });
        await VPN_DB.put("server_groups", JSON.stringify(orderedGroups));
      }
      if (data && data.rotationChunk !== undefined) {
        const parsedChunk = Math.max(1, parseInt(data.rotationChunk, 10) || DEFAULT_ROTATION_CHUNK);
        await VPN_DB.put("rotation_chunk", String(parsedChunk));
      }
      if (data && typeof data.subToken === 'string' && /^\d{6}$/.test(data.subToken)) {
        await VPN_DB.put("sub_token", data.subToken);
      }
      const latestGroups = await envFetchGroups();
      return new Response(JSON.stringify({ success: true, groups: latestGroups }), { headers: { 'content-type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  // Regenerate a new random 6-digit subscription token on demand
  if (request.method === 'POST' && url.pathname === '/regenerate-token') {
    try {
      const newToken = generateSixDigitCode();
      await VPN_DB.put("sub_token", newToken);
      return new Response(JSON.stringify({ success: true, subToken: newToken }), {
        headers: { 'content-type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ success: false, error: e.message }), { status: 500, headers: { 'content-type': 'application/json' } });
    }
  }

  // If logged in, safely render Graphic Interface Panel
  let serverGroups = await envFetchGroups();
  let rotationChunk = await envFetchRotationChunk();
  return new Response(getAdminPanelHTML(url.origin, serverGroups, rotationChunk, subToken), {
    headers: { 'content-type': 'text/html; charset=utf-8' }
  });
}

/* ------------------------------------------------------------------ */
/* Parsing helpers                                                     */
/* ------------------------------------------------------------------ */

function isHttpUrl(str) {
  const s = String(str || '').trim().toLowerCase();
  return s.startsWith('https://') || s.startsWith('http://');
}

function getScheme(str) {
  const m = String(str || '').trim().match(/^([a-z][a-z0-9+.\-]*):\/\//i);
  return m ? m[1].toLowerCase() : '';
}

function isKnownProtocolLine(str) {
  return KNOWN_PROTOCOLS.has(getScheme(str));
}

// Splits text into entries. A line that starts with ANY "scheme://" is always a new entry,
// so an unrecognised scheme can never be glued onto the previous config.
// Only lines that look like a wrapped continuation (no scheme, no whitespace) are stitched.
function splitNonEmptyLines(text) {
  const rawLines = String(text || '')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean);

  const stitched = [];
  for (const line of rawLines) {
    if (SCHEME_LINE_RE.test(line)) {
      stitched.push(line);
    } else if (
      stitched.length > 0 &&
      !/\s/.test(line) &&
      !line.startsWith('//') &&
      !line.startsWith(';') &&
      !line.startsWith('#')
    ) {
      // Stitch wrapped continuation lines (common with long IPv6 config URLs)
      stitched[stitched.length - 1] += line;
    }
  }
  return stitched;
}

function safeBase64Decode(b64) {
  const compact = String(b64 || '').trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (compact.length % 4)) % 4;
  const padded = compact + '='.repeat(padLen);
  try {
    return decodeURIComponent(escape(atob(padded)));
  } catch (e) {
    return atob(padded);
  }
}

function decodeSubscriptionPayload(rawBody) {
  const trimmed = String(rawBody || '').trim();
  if (!trimmed) return [];

  const directLines = splitNonEmptyLines(trimmed).filter(l => isKnownProtocolLine(l));
  if (directLines.length > 0) {
    return directLines;
  }

  try {
    const decoded = safeBase64Decode(trimmed);
    const decodedLines = splitNonEmptyLines(decoded).filter(l => isKnownProtocolLine(l));
    if (decodedLines.length > 0) {
      return decodedLines;
    }
  } catch (e) {}

  return directLines;
}

async function fetchAndDecodeSubUrls(urls) {
  const errors = [];
  const perUrlConfigs = await Promise.all((urls || []).map(async (targetUrl) => {
    const cleanUrl = String(targetUrl || '').trim();
    if (!isHttpUrl(cleanUrl)) return [];
    try {
      const res = await fetch(cleanUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'v2rayNG/1.8.19',
          'Accept': '*/*'
        }
      });
      if (!res.ok) {
        errors.push(`${cleanUrl}: HTTP ${res.status}`);
        return [];
      }
      const text = await res.text();
      const decoded = decodeSubscriptionPayload(text);
      if (decoded.length === 0) {
        errors.push(`${cleanUrl}: No valid configs found`);
        return [];
      }
      return decoded;
    } catch (err) {
      errors.push(`${cleanUrl}: ${err && err.message ? err.message : 'Fetch error'}`);
      return [];
    }
  }));
  const allConfigs = [];
  perUrlConfigs.forEach(list => {
    list.forEach(c => allConfigs.push(c));
  });
  return { configs: allConfigs, errors };
}

function normalizeGroupEntry(rawEntry) {
  if (Array.isArray(rawEntry)) {
    const cleaned = splitNonEmptyLines(rawEntry.join('\n'));
    const subUrls = cleaned.filter(c => isHttpUrl(c));
    const configs = cleaned.filter(c => !isHttpUrl(c));
    const mode = (subUrls.length > 0 && configs.length === 0) ? 'sub' : 'configs';
    return {
      mode,
      configs,
      subUrls,
      cachedSubConfigs: []
    };
  }
  if (rawEntry && typeof rawEntry === 'object') {
    const mode = rawEntry.mode === 'sub' ? 'sub' : 'configs';
    const configs = Array.isArray(rawEntry.configs)
      ? splitNonEmptyLines(rawEntry.configs.join('\n')).filter(c => !isHttpUrl(c))
      : [];
    const subUrls = Array.isArray(rawEntry.subUrls)
      ? rawEntry.subUrls.map(c => String(c || '').trim()).filter(c => isHttpUrl(c))
      : [];
    const cachedSubConfigs = Array.isArray(rawEntry.cachedSubConfigs)
      ? splitNonEmptyLines(rawEntry.cachedSubConfigs.join('\n')).filter(c => !isHttpUrl(c))
      : [];
    return { mode, configs, subUrls, cachedSubConfigs };
  }
  return { mode: 'configs', configs: [], subUrls: [], cachedSubConfigs: [] };
}

function normalizeAllGroups(rawGroups) {
  const source = (rawGroups && typeof rawGroups === 'object' && !Array.isArray(rawGroups) && Object.keys(rawGroups).length > 0)
    ? rawGroups
    : defaultGroups;
  const out = {};
  Object.keys(source).forEach(k => {
    out[k] = normalizeGroupEntry(source[k]);
  });
  return out;
}

function generateSixDigitCode() {
  try {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return String(100000 + (arr[0] % 900000));
  } catch (e) {
    return String(Math.floor(100000 + Math.random() * 900000));
  }
}

async function envFetchOrCreateSubToken() {
  try {
    const existing = await VPN_DB.get("sub_token");
    if (existing && /^\d{6}$/.test(existing.trim())) {
      return existing.trim();
    }
    const generated = generateSixDigitCode();
    await VPN_DB.put("sub_token", generated);
    return generated;
  } catch (e) {
    return "482915";
  }
}

/* ------------------------------------------------------------------ */
/* Host / IPv6 handling                                                */
/* ------------------------------------------------------------------ */

function isValidIPv6(s) {
  if (!/^[0-9a-fA-F:]+$/.test(s) || s.indexOf(':::') !== -1) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  const toGroups = h => (h === '' ? [] : h.split(':'));
  const all = halves.flatMap(toGroups);
  if (all.some(g => g.length < 1 || g.length > 4)) return false;
  return halves.length === 2 ? all.length <= 7 : all.length === 8;
}

// Splits "host:port" for IPv4, domains, bracketed IPv6 and UNBRACKETED IPv6.
// Returns { host, port } where port may be ''.
function splitHostPort(hostPort) {
  const hp = String(hostPort || '').trim();

  const bracket = hp.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracket) return { host: bracket[1], port: bracket[2] || '' };

  const colonCount = (hp.match(/:/g) || []).length;
  if (colonCount <= 1) {
    const m = hp.match(/^([^:/?#]+)(?::(\d+))?$/);
    return m ? { host: m[1], port: m[2] || '' } : { host: hp, port: '' };
  }

  // 2+ colons => unbracketed IPv6
  const idx = hp.lastIndexOf(':');
  const candidateHost = hp.slice(0, idx);
  const candidatePort = hp.slice(idx + 1);
  if (/^\d{1,5}$/.test(candidatePort) && Number(candidatePort) <= 65535 && isValidIPv6(candidateHost)) {
    return { host: candidateHost, port: candidatePort };
  }
  if (isValidIPv6(hp)) return { host: hp, port: '' };
  return { host: hp, port: '' };
}

// Parses out the host, normalises unbracketed IPv6 so VPN clients don't drop it,
// and injects the custom group name as the config remark.
function renameConfigWithIP(config, groupName) {
  try {
    const rawConfig = String(config || '').trim();
    const scheme = getScheme(rawConfig);

    if (scheme === 'vmess') {
      const hashIdx = rawConfig.indexOf('#');
      const b64Body = (hashIdx !== -1 ? rawConfig.slice(8, hashIdx) : rawConfig.slice(8)).trim();
      const decoded = safeBase64Decode(b64Body);
      const configObj = JSON.parse(decoded);
      const rawHost = String(configObj.add || configObj.host || "Unknown_IP").trim();
      const ipAddress = rawHost.replace(/^\[|\]$/g, '');
      configObj.ps = `${groupName} - ${ipAddress}`;
      return `vmess://${btoa(unescape(encodeURIComponent(JSON.stringify(configObj))))}`;
    }

    if (scheme && KNOWN_PROTOCOLS.has(scheme)) {
      const hashIndex = rawConfig.indexOf('#');
      let basePart = hashIndex !== -1 ? rawConfig.substring(0, hashIndex) : rawConfig;
      let ipAddress = "Unknown_IP";

      const schemeEnd = basePart.indexOf('://') + 3;
      const qIndex = basePart.indexOf('?', schemeEnd);
      const pathIndex = basePart.indexOf('/', schemeEnd);
      let authorityEnd = basePart.length;
      if (qIndex !== -1 && qIndex < authorityEnd) authorityEnd = qIndex;
      if (pathIndex !== -1 && pathIndex < authorityEnd) authorityEnd = pathIndex;

      const authorityPart = basePart.slice(0, authorityEnd);
      const restPart = basePart.slice(authorityEnd);
      const atIndex = authorityPart.lastIndexOf('@');

      if (atIndex !== -1) {
        const prefix = authorityPart.slice(0, atIndex + 1);
        const hostPort = authorityPart.slice(atIndex + 1);
        const parsed = splitHostPort(hostPort);
        if (parsed.host) {
          ipAddress = parsed.host;
          const isV6 = parsed.host.indexOf(':') !== -1;
          const hostOut = isV6 ? `[${parsed.host}]` : parsed.host;
          basePart = `${prefix}${hostOut}${parsed.port ? ':' + parsed.port : ''}${restPart}`;
        }
      } else if (scheme === 'ss') {
        // Legacy ss:// with the whole authority base64-encoded
        const body = authorityPart.slice(5);
        const decoded = safeBase64Decode(body);
        const atInDecoded = decoded.lastIndexOf('@');
        if (atInDecoded !== -1) {
          const parsed = splitHostPort(decoded.slice(atInDecoded + 1));
          if (parsed.host) ipAddress = parsed.host;
        }
      }

      return `${basePart}#${encodeURIComponent(`${groupName} - ${ipAddress}`)}`;
    }
  } catch (err) {}
  return config;
}

async function envFetchGroups() {
  try {
    const kvData = await VPN_DB.get("server_groups");
    if (kvData) {
      const parsed = JSON.parse(kvData);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length > 0) {
        return normalizeAllGroups(parsed);
      }
    }
  } catch (e) {}
  return normalizeAllGroups(defaultGroups);
}

async function envFetchRotationChunk() {
  try {
    const kvChunk = await VPN_DB.get("rotation_chunk");
    if (kvChunk) {
      const n = parseInt(kvChunk, 10);
      if (Number.isFinite(n) && n >= 1) return n;
    }
  } catch (e) {}
  return DEFAULT_ROTATION_CHUNK;
}

/* ------------------------------------------------------------------ */
/* LOGIN SCREEN                                                        */
/* ------------------------------------------------------------------ */

function getLoginPageHTML() {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <title>Sign in · Subscription Hub</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
            background:
                radial-gradient(900px 500px at 15% -10%, rgba(99,102,241,0.22), transparent 60%),
                radial-gradient(800px 500px at 100% 110%, rgba(14,165,233,0.18), transparent 60%),
                #0b0c10;
            color: #e5e7eb;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; padding: 20px;
        }
        .card {
            width: 100%; max-width: 380px; padding: 34px 30px 30px;
            background: rgba(22,23,29,0.82);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            backdrop-filter: blur(14px);
            box-shadow: 0 24px 60px rgba(0,0,0,0.45);
            text-align: center;
        }
        .logo {
            width: 54px; height: 54px; margin: 0 auto 18px; border-radius: 16px;
            display: grid; place-items: center; font-size: 26px;
            background: linear-gradient(135deg, #6366f1, #0ea5e9);
            box-shadow: 0 10px 30px rgba(99,102,241,0.4);
        }
        h2 { margin: 0 0 6px; font-size: 21px; color: #fff; letter-spacing: -0.2px; }
        p { margin: 0 0 22px; font-size: 13px; color: #8b93a7; }
        input {
            width: 100%; padding: 13px 14px; margin-bottom: 12px;
            background: #0d0e13; border: 1px solid #272a36; color: #fff;
            border-radius: 11px; font-size: 14px; text-align: center;
            transition: border-color .15s, box-shadow .15s;
        }
        input:focus { outline: none; border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99,102,241,0.18); }
        button {
            width: 100%; padding: 13px; border: none; border-radius: 11px; cursor: pointer;
            font-size: 14px; font-weight: 600; color: #fff;
            background: linear-gradient(135deg, #6366f1, #3b82f6);
            transition: transform .1s, filter .15s;
        }
        button:hover { filter: brightness(1.1); }
        button:active { transform: translateY(1px); }
        button:disabled { opacity: .6; cursor: wait; }
        .err { min-height: 18px; margin-top: 12px; font-size: 12.5px; color: #fca5a5; }
        .shake { animation: shake .35s; }
        @keyframes shake { 25% { transform: translateX(-6px);} 75% { transform: translateX(6px);} }
    </style>
</head>
<body>
    <div class="card" id="card">
        <div class="logo">🔐</div>
        <h2>Subscription Hub</h2>
        <p>Enter your dashboard password to continue</p>
        <input type="password" id="passInput" placeholder="Password" autocomplete="current-password" autofocus>
        <button id="loginBtn" onclick="login()">Sign in</button>
        <div class="err" id="err"></div>
    </div>
    <script>
        const input = document.getElementById('passInput');
        input.addEventListener('keydown', function (e) { if (e.key === 'Enter') login(); });
        async function login() {
            const btn = document.getElementById('loginBtn');
            const err = document.getElementById('err');
            err.textContent = '';
            btn.disabled = true;
            try {
                const res = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: input.value })
                });
                if (res.ok) {
                    window.location.reload();
                    return;
                }
                err.textContent = 'Incorrect password. Please try again.';
                const card = document.getElementById('card');
                card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
                input.select();
            } catch (e) {
                err.textContent = 'Network error. Please try again.';
            } finally {
                btn.disabled = false;
            }
        }
    </script>
</body>
</html>
  `;
}

/* ------------------------------------------------------------------ */
/* MAIN DASHBOARD                                                      */
/* ------------------------------------------------------------------ */

function getAdminPanelHTML(baseUrl, serverGroups, rotationChunk, subToken) {
  const safeGroupsJson = JSON.stringify(normalizeAllGroups(serverGroups)).replace(/</g, '\\u003c');
  const safeChunk = Number(rotationChunk) >= 1 ? Number(rotationChunk) : DEFAULT_ROTATION_CHUNK;
  const safeSubToken = String(subToken || '482915').replace(/[^0-9]/g, '').slice(0, 6) || '482915';

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <title>VPN Subscription Hub</title>
    <style>
        :root {
            --bg: #0b0c10;
            --surface: #14151b;
            --surface-2: #1a1c24;
            --surface-3: #21232d;
            --line: #272a36;
            --line-soft: rgba(255,255,255,0.06);
            --text: #e5e7eb;
            --muted: #8b93a7;
            --muted-2: #656c80;
            --accent: #6366f1;
            --accent-2: #3b82f6;
            --accent-soft: rgba(99,102,241,0.14);
            --green: #10b981;
            --green-soft: rgba(16,185,129,0.14);
            --amber: #f59e0b;
            --red: #ef4444;
            --red-soft: rgba(239,68,68,0.13);
            --radius: 16px;
            --mono: ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace;
        }
        * { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
            background:
                radial-gradient(1000px 520px at 10% -8%, rgba(99,102,241,0.16), transparent 60%),
                radial-gradient(900px 520px at 100% 0%, rgba(14,165,233,0.10), transparent 60%),
                var(--bg);
            background-attachment: fixed;
            color: var(--text);
            margin: 0;
            padding: 28px 20px 130px;
            display: flex;
            justify-content: center;
            -webkit-font-smoothing: antialiased;
        }
        .container { width: 100%; max-width: 880px; }

        /* ---------- Header ---------- */
        header {
            display: flex; justify-content: space-between; align-items: center;
            gap: 14px; flex-wrap: wrap; margin-bottom: 22px;
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .brand-logo {
            width: 44px; height: 44px; border-radius: 13px; display: grid; place-items: center;
            font-size: 22px; background: linear-gradient(135deg, var(--accent), #0ea5e9);
            box-shadow: 0 8px 24px rgba(99,102,241,0.35);
        }
        h1 { margin: 0; font-size: 22px; color: #fff; letter-spacing: -0.3px; }
        .brand-sub { font-size: 12.5px; color: var(--muted); margin-top: 2px; }

        /* ---------- Buttons ---------- */
        .btn {
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            color: #fff; border: none; padding: 9px 16px; border-radius: 10px;
            cursor: pointer; font-weight: 600; font-size: 13px; font-family: inherit;
            transition: filter .15s, transform .1s, background .15s;
            white-space: nowrap;
        }
        .btn:hover { filter: brightness(1.12); }
        .btn:active { transform: translateY(1px); }
        .btn:disabled { opacity: .55; cursor: not-allowed; filter: none; }
        .btn-ghost {
            background: var(--surface-2); border: 1px solid var(--line); color: #cbd5e1;
            padding: 7px 12px; font-size: 12px; font-weight: 600;
        }
        .btn-ghost:hover { background: var(--surface-3); color: #fff; filter: none; }
        .btn-danger-ghost {
            background: var(--red-soft); border: 1px solid rgba(239,68,68,0.3); color: #fca5a5;
            padding: 7px 12px; font-size: 12px; font-weight: 600;
        }
        .btn-danger-ghost:hover { background: rgba(239,68,68,0.22); color: #fecaca; filter: none; }
        .icon-btn {
            background: var(--surface-2); border: 1px solid var(--line); color: #cbd5e1;
            width: 30px; height: 30px; border-radius: 8px; cursor: pointer; font-size: 14px;
            display: inline-flex; align-items: center; justify-content: center; padding: 0;
            transition: background .15s;
        }
        .icon-btn:hover { background: var(--surface-3); color: #fff; }
        .icon-btn:disabled { opacity: .3; cursor: default; }

        /* ---------- Stats ---------- */
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
        .stat {
            background: var(--surface); border: 1px solid var(--line-soft); border-radius: 14px;
            padding: 14px 16px;
        }
        .stat-label { font-size: 11.5px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted-2); font-weight: 600; }
        .stat-value { font-size: 26px; font-weight: 700; color: #fff; margin-top: 4px; letter-spacing: -0.5px; }
        .stat-value small { font-size: 12px; font-weight: 500; color: var(--muted); letter-spacing: 0; margin-left: 4px; }

        /* ---------- Generic card ---------- */
        .card {
            background: var(--surface); border: 1px solid var(--line-soft);
            border-radius: var(--radius); padding: 16px 18px; margin-bottom: 16px;
        }
        .card-title { font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
        .card-desc { font-size: 12px; color: var(--muted); margin-top: 3px; line-height: 1.5; }

        /* ---------- Subscription link ---------- */
        .sub-card { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; }
        .sub-card-main { min-width: 0; flex: 1; }
        .sub-url-row {
            margin-top: 8px; display: flex; align-items: center; gap: 8px;
            background: #0d0e13; border: 1px solid var(--line); border-radius: 10px; padding: 9px 12px;
        }
        .sub-url-row code { color: #7dd3fc; font-family: var(--mono); font-size: 13px; word-break: break-all; flex: 1; }
        .code-badge {
            background: var(--green-soft); border: 1px solid rgba(16,185,129,.35); color: #6ee7b7;
            font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; font-family: var(--mono);
        }
        .sub-card-actions { display: flex; gap: 8px; flex-wrap: wrap; }

        /* ---------- Divide preference ---------- */
        .divide-top { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; }
        .segmented { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
        .chunk-preset-btn {
            background: var(--surface-2); border: 1px solid var(--line); color: #cbd5e1;
            min-width: 36px; padding: 6px 11px; border-radius: 9px; font-size: 12.5px; font-weight: 700;
            cursor: pointer; transition: all .15s; font-family: inherit;
        }
        .chunk-preset-btn:hover { background: var(--surface-3); color: #fff; }
        .chunk-preset-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; box-shadow: 0 4px 14px rgba(99,102,241,.35); }
        .chunk-custom-wrap {
            display: flex; align-items: center; gap: 6px; background: #0d0e13;
            border: 1px solid var(--line); border-radius: 9px; padding: 3px 9px;
        }
        .chunk-custom-wrap span { font-size: 11px; color: var(--muted); }
        .chunk-custom-input {
            width: 46px; background: transparent; border: none; color: #fff; font-size: 13px;
            font-weight: 700; text-align: center; padding: 4px 0; font-family: inherit;
        }
        .chunk-custom-input:focus { outline: none; }

        /* Rotation preview */
        .preview-toggle {
            margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--line);
            display: flex; justify-content: space-between; align-items: center; gap: 10px;
            cursor: pointer; user-select: none;
        }
        .preview-toggle .card-title { font-size: 12.5px; color: #cbd5e1; }
        .chev { display: inline-block; transition: transform .18s; color: var(--muted); font-size: 12px; }
        .preview-open .chev { transform: rotate(90deg); }
        .preview-body { display: none; margin-top: 10px; }
        .preview-open .preview-body { display: block; }
        .preview-legend { font-size: 11.5px; color: var(--muted); margin-bottom: 8px; line-height: 1.5; }
        .batches { display: flex; flex-wrap: wrap; gap: 6px; }
        .batch-pill {
            display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600;
            padding: 4px 9px; border-radius: 999px; color: #e2e8f0;
            border: 1px solid transparent;
        }
        .batch-pill b { font-family: var(--mono); font-weight: 700; }
        .batch-pill.partial { border-style: dashed; border-color: rgba(251,191,36,.7); }
        .batch-sep { color: var(--muted-2); font-size: 11px; align-self: center; }
        .batch-more { font-size: 11.5px; color: var(--muted); align-self: center; }

        .hint { font-size: 12px; color: var(--muted); margin: 4px 2px 12px; }

        /* ---------- Groups ---------- */
        .server-group {
            position: relative;
            background: var(--surface); border: 1px solid var(--line-soft);
            border-radius: var(--radius); padding: 16px 18px 14px 22px;
            transition: border-color .15s, box-shadow .15s;
        }
        .server-group::before {
            content: ''; position: absolute; left: 0; top: 14px; bottom: 14px; width: 4px;
            border-radius: 0 4px 4px 0; background: var(--gc, var(--accent));
        }
        .server-group:hover { border-color: rgba(255,255,255,0.12); }
        .server-group.dragging { opacity: .35; }
        .server-group.collapsed .group-body { display: none; }
        .server-group.collapsed .group-header { margin-bottom: 0; }

        .drop-zone {
            height: 18px; border-radius: 8px; border: 2px dashed transparent;
            display: flex; align-items: center; justify-content: center;
            transition: background-color .1s, border-color .1s;
        }
        body.is-dragging .drop-zone { border-color: #30333f; }
        body.is-dragging .drop-zone.hover { border-color: var(--accent); border-style: solid; background: rgba(99,102,241,.22); }
        .drop-zone::after { content: ''; font-size: 11px; letter-spacing: .4px; color: transparent; }
        body.is-dragging .drop-zone.hover::after { content: 'Drop here'; color: #c7d2fe; font-weight: 700; }

        .group-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }
        .header-left { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 220px; }
        .header-right { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
        .drag-handle { color: var(--muted-2); font-size: 18px; user-select: none; cursor: grab; padding: 2px 5px; border-radius: 6px; }
        .drag-handle:hover { color: #cbd5e1; background: var(--surface-2); }
        .drag-handle:active { cursor: grabbing; }
        .collapse-btn { background: none; border: none; color: var(--muted); cursor: pointer; padding: 4px; font-size: 12px; border-radius: 6px; }
        .collapse-btn:hover { background: var(--surface-2); color: #fff; }
        .server-group:not(.collapsed) .collapse-btn .chev { transform: rotate(90deg); }
        .group-title {
            background: transparent; border: none; color: #fff; font-size: 17px; font-weight: 700;
            border-bottom: 1px dashed transparent; padding: 3px 2px; flex: 1; min-width: 0; font-family: inherit;
            letter-spacing: -0.2px;
        }
        .group-title:hover { border-bottom-color: #3a3e4c; }
        .group-title:focus { outline: none; border-bottom-color: var(--accent); }

        .config-count-badge {
            background: var(--accent-soft); border: 1px solid rgba(99,102,241,.3); color: #c7d2fe;
            font-size: 11.5px; font-weight: 700; padding: 3px 10px; border-radius: 999px; white-space: nowrap;
        }
        .config-count-badge.empty { background: var(--red-soft); border-color: rgba(239,68,68,.3); color: #fca5a5; }
        .config-count-badge.sub-mode { background: var(--green-soft); border-color: rgba(16,185,129,.35); color: #6ee7b7; }

        .chips { display: flex; flex-wrap: wrap; gap: 5px; margin: 0 0 10px; min-height: 0; }
        .chips:empty { display: none; }
        .chip {
            font-family: var(--mono); font-size: 10.5px; font-weight: 700; text-transform: uppercase;
            letter-spacing: .4px; padding: 2px 7px; border-radius: 6px;
            background: var(--surface-3); color: #aab2c5; border: 1px solid var(--line);
        }
        .chip.v6 { background: rgba(14,165,233,.14); border-color: rgba(14,165,233,.35); color: #7dd3fc; }

        .mode-bar { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; flex-wrap: wrap; }
        .mode-switch-group { display: inline-flex; background: #0d0e13; border: 1px solid var(--line); border-radius: 10px; padding: 3px; gap: 3px; }
        .mode-btn {
            background: transparent; border: none; color: var(--muted); font-size: 12px; font-weight: 700;
            padding: 6px 12px; border-radius: 7px; cursor: pointer; transition: all .15s; font-family: inherit;
        }
        .mode-btn:hover { color: #fff; }
        .mode-btn.active { background: var(--accent); color: #fff; }
        .mode-btn.active.sub-active { background: #059669; }
        .sub-actions-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .sub-status-text { font-size: 11.5px; color: var(--muted); }
        .sub-status-text.ok { color: #6ee7b7; }
        .sub-status-text.err { color: #fca5a5; }

        textarea {
            width: 100%; height: 130px; background: #0d0e13; border: 1px solid var(--line);
            border-radius: 11px; color: #cbd5e1; padding: 11px 12px; font-family: var(--mono);
            font-size: 12.5px; line-height: 1.55; resize: vertical; transition: border-color .15s, box-shadow .15s;
        }
        textarea.sub-textarea { height: 84px; border-color: rgba(16,185,129,.35); }
        textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 4px rgba(99,102,241,.14); }
        textarea.sub-textarea:focus { border-color: #10b981; box-shadow: 0 0 0 4px rgba(16,185,129,.14); }
        body.is-dragging textarea, body.is-dragging input, body.is-dragging .floating-save-bar { pointer-events: none; }

        .group-footer {
            margin-top: 9px; display: flex; flex-wrap: wrap; align-items: center;
            justify-content: space-between; gap: 8px; font-size: 11.5px; color: var(--muted-2);
        }
        .group-footer code { color: var(--muted); font-family: var(--mono); font-size: 11px; }

        .empty-groups-state {
            background: var(--surface); border: 1px dashed #353846; border-radius: var(--radius);
            padding: 44px 20px; text-align: center; color: var(--muted);
        }

        /* ---------- Save bar ---------- */
        .floating-save-bar {
            position: fixed; bottom: 0; left: 0; right: 0; z-index: 40;
            background: rgba(11,12,16,.82); backdrop-filter: blur(14px);
            border-top: 1px solid var(--line); padding: 12px 20px; display: flex; justify-content: center;
        }
        .floating-save-inner { width: 100%; max-width: 880px; display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
        .save-status { font-size: 12.5px; color: var(--muted); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .save-status .sep { opacity: .5; }
        .dirty-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 4px rgba(16,185,129,.15); display: inline-block; }
        .dirty-dot.dirty { background: var(--amber); box-shadow: 0 0 0 4px rgba(245,158,11,.18); }
        .floating-actions { display: flex; align-items: center; gap: 10px; }
        kbd { font-family: var(--mono); font-size: 10.5px; background: var(--surface-3); border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 5px; padding: 1px 5px; color: #aab2c5; }

        /* ---------- Toasts ---------- */
        .toasts { position: fixed; top: 18px; right: 18px; z-index: 100; display: flex; flex-direction: column; gap: 8px; max-width: calc(100vw - 36px); }
        .toast {
            background: var(--surface-2); border: 1px solid var(--line); border-left: 4px solid var(--accent);
            color: #e5e7eb; padding: 11px 15px; border-radius: 10px; font-size: 13px; font-weight: 500;
            box-shadow: 0 12px 30px rgba(0,0,0,.45); animation: toastIn .22s ease-out;
        }
        .toast.ok { border-left-color: var(--green); }
        .toast.err { border-left-color: var(--red); }
        .toast.out { opacity: 0; transform: translateX(14px); transition: all .22s; }
        @keyframes toastIn { from { opacity: 0; transform: translateX(14px); } to { opacity: 1; transform: none; } }

        @media (max-width: 620px) {
            body { padding: 18px 12px 150px; }
            .stats { grid-template-columns: repeat(3, 1fr); gap: 8px; }
            .stat { padding: 11px 12px; }
            .stat-value { font-size: 21px; }
            .server-group { padding: 14px 14px 12px 18px; }
            kbd, .kbd-hint { display: none; }
        }