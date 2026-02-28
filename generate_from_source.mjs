#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const SOURCE_FILE = process.env.SOURCE_FILE || 'source';
const OUTPUT_DIR = process.env.OUTPUT_DIR || 'sub';
const README_FILE = process.env.README_FILE || 'README.md';
const RAW_BASE_URL = process.env.RAW_BASE_URL || (() => {
  const repo = process.env.GITHUB_REPOSITORY;
  const refName = process.env.GITHUB_REF_NAME || (process.env.GITHUB_REF || '').replace('refs/heads/', '');
  if (repo && refName) return `https://raw.githubusercontent.com/${repo}/refs/heads/${refName}`;
  return '';
})();
const GEO_FLAG_ENABLED = (process.env.ENABLE_GEO_FLAG ?? '1') !== '0';
const GEO_FLAG_TIMEOUT_MS = Number(process.env.GEO_FLAG_TIMEOUT_MS || '1200');
const GEO_FLAG_CONCURRENCY = Number(process.env.GEO_FLAG_CONCURRENCY || '8');
const GEO_FLAG_RETRY = Number(process.env.GEO_FLAG_RETRY || '2');
const GEO_CACHE_FILE = process.env.GEO_CACHE_FILE || '.cache/geoip-cache.json';
const GEO_CACHE_TTL_HOURS = Number(process.env.GEO_CACHE_TTL_HOURS || '168');
const GEO_CACHE_MAX_ITEMS = Number(process.env.GEO_CACHE_MAX_ITEMS || '20000');

const PROTOCOL_ALIASES = new Map([
  ['hysteria2', 'hy2'],
  ['hysteria', 'hysteria'],
  ['wireguard', 'wg'],
  ['socks5', 'socks'],
]);

const AMNEZIA_DEFAULT_FIELDS = { s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4 };
const AMNEZIA_PROFILE_PRESETS = new Map([
  ['optimal-balanced-daily-use', { jc: 4, jmin: 64, jmax: 120 }],
  ['weak-net-low-bandwidth', { jc: 6, jmin: 64, jmax: 80 }],
  ['aggressive-pattern', { jc: 8, jmin: 64, jmax: 150 }],
  ['fast-low-handshake-overhead', { jc: 2, jmin: 64, jmax: 70 }],
  ['proton-minimal-compatibility', { jc: 4, jmin: 40, jmax: 70 }],
  ['bpb-legacy-balanced', { jc: 5, jmin: 50, jmax: 100 }],
  ['hamedp71-compatibility', { jc: 4, jmin: 40, jmax: 250 }],
  ['rus-micro-micro-noise', { jc: 3, jmin: 10, jmax: 30 }],
  ['rus-flood-heavy-flood', { jc: 10, jmin: 30, jmax: 60 }],
  ['stalinium-strategy-maximum', { jc: 31, jmin: 20, jmax: 40 }],
  ['high-entropy-obfuscation', { jc: 33, jmin: 132, jmax: 1200 }],
  ['heavy-traffic-simulation', { jc: 50, jmin: 5, jmax: 1500 }],
  ['metacubex-fixed-window', { jc: 5, jmin: 500, jmax: 501 }],
  ['amnezia-official-default', { jc: 8, jmin: 50, jmax: 1000 }],
  ['gaming-ultra-low-overhead', { jc: 3, jmin: 64, jmax: 80 }],
]);
const AMNEZIA_ALL_PROFILES = [...AMNEZIA_PROFILE_PRESETS.keys()];

function normalizeBase64(v) {
  if (!v) return null;
  v = v.replace(/[\r\n\t\s]/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = v.length % 4;
  if (pad === 2) v += '==';
  else if (pad === 3) v += '=';
  else if (pad === 1) return null;
  try {
    return Buffer.from(v, 'base64').toString('utf8');
  } catch { return null; }
}

function decodeSub(text) {
  if (text.includes('://')) return text;
  return normalizeBase64(text) ?? text;
}

function safeDecode(str) {
  try { return decodeURIComponent(str); } catch { return str; }
}

function getDisplayType(type) {
  return PROTOCOL_ALIASES.get(type) || type.toLowerCase();
}

function toRawGithubUrl(input) {
  try {
    const u = new URL(input);
    if (u.hostname !== 'github.com') return input;
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length < 5 || parts[2] !== 'blob') return input;
    const [owner, repo, _blob, branch, ...rest] = parts;
    return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${rest.join('/')}`;
  } catch {
    return input;
  }
}

function parseProxy(line) {
  try {
    const prefix = line.substring(0, 16).toLowerCase();
    if (prefix.startsWith('vless://')) return parseVless(line);
    if (prefix.startsWith('vmess://')) return parseVmess(line);
    if (prefix.startsWith('trojan://')) return parseTrojan(line);
    if (prefix.startsWith('anytls://')) return parseAnyTls(line);
    if (prefix.startsWith('ss://')) return parseSS(line);
    if (prefix.startsWith('ssr://')) return parseSSR(line);
    if (prefix.startsWith('hy2://') || prefix.startsWith('hysteria2://')) return parseHysteria2(line);
    if (prefix.startsWith('hysteria://')) return parseHysteria(line);
    if (prefix.startsWith('wg://') || prefix.startsWith('wireguard://')) return parseWireguard(line);
    if (prefix.startsWith('tuic://')) return parseTuic(line);
    if (prefix.startsWith('http://') || prefix.startsWith('https://')) return parseHttp(line);
    if (prefix.startsWith('socks://') || prefix.startsWith('socks5://')) return parseSocks(line);
    if (prefix.startsWith('snell://')) return parseSnell(line);
    if (prefix.startsWith('ssh://')) return parseSSH(line);
  } catch {}
  return null;
}

function parseVless(link) {
  const url = new URL(link.replace(/^vless:\/\//i, 'http://'));
  const security = url.searchParams.get('security') || '';
  const p = {
    name: safeDecode(url.hash.substring(1) || url.hostname), type: 'vless', server: url.hostname,
    port: Number(url.port), uuid: url.username || '', udp: true, tls: ['tls', 'reality'].includes(security),
    network: url.searchParams.get('type') || 'tcp'
  };
  const sni = url.searchParams.get('sni'); if (sni) p.servername = sni;
  return p;
}

function parseVmess(link) {
  const fixed = normalizeBase64(link.replace(/^vmess:\/\//i, '')); if (!fixed) return null;
  const j = JSON.parse(fixed);
  return { name: j.ps || j.add, type: 'vmess', server: j.add, port: Number(j.port), uuid: j.id || '', alterId: Number(j.aid) || 0, cipher: j.scy || 'auto', udp: true };
}

function parseTrojan(link) {
  const url = new URL(link.replace(/^trojan:\/\//i, 'http://'));
  return { name: safeDecode(url.hash.substring(1) || url.hostname), type: 'trojan', server: url.hostname, port: Number(url.port), password: safeDecode(url.username) || '', udp: true, tls: true };
}

function parseAnyTls(link) {
  const url = new URL(link.replace(/^anytls:\/\//i, 'http://'));
  return { name: safeDecode(url.hash.substring(1) || url.hostname), type: 'anytls', server: url.hostname, port: Number(url.port), password: safeDecode(url.username || url.password) || '' };
}

function parseSS(link) {
  const raw = link.replace(/^ss:\/\//i, '');
  const [base, tag] = raw.split('#');
  let method, password, server, port;
  if (base.includes('@')) {
    const [authRaw, hostRaw] = base.split('@');
    const auth = normalizeBase64(authRaw) || authRaw;
    [method, password] = auth.split(':');
    [server, port] = hostRaw.split(':');
  } else {
    const decoded = normalizeBase64(base); if (!decoded) return null;
    const [auth, host] = decoded.split('@'); if (!auth || !host) return null;
    [method, password] = auth.split(':'); [server, port] = host.split(':');
  }
  return { name: safeDecode(tag || server), type: 'ss', server, port: Number(port), cipher: method, password: safeDecode(password || '') };
}

function parseSSR(link) {
  const decoded = normalizeBase64(link.replace(/^ssr:\/\//i, '')); if (!decoded) return null;
  const [main, query] = decoded.split('/?');
  const [server, port, protocol, method, obfs, b64pass] = main.split(':');
  const p = { name: 'SSR', type: 'ssr', server, port: Number(port), protocol, cipher: method, obfs, password: normalizeBase64(b64pass) || b64pass || '' };
  if (query) {
    const params = new URLSearchParams(query);
    const remarks = params.get('remarks'); if (remarks) p.name = safeDecode(normalizeBase64(remarks) || remarks);
  }
  return p;
}

function parseHysteria2(link) {
  const url = new URL(link.replace(/^(hy2|hysteria2):\/\//i, 'http://'));
  return { name: safeDecode(url.hash.substring(1) || url.hostname), type: 'hysteria2', server: url.hostname, port: Number(url.port), password: safeDecode(url.username) || '' };
}

function parseHysteria(link) {
  const url = new URL(link.replace(/^hysteria:\/\//i, 'http://'));
  return { name: safeDecode(url.hash.substring(1) || url.hostname), type: 'hysteria', server: url.hostname, port: Number(url.port), auth_str: url.searchParams.get('auth') || '' };
}

function parseWireguard(link) {
  const url = new URL(link.replace(/^(wg|wireguard):\/\//i, 'http://'));
  const p = {
    name: safeDecode(url.hash.substring(1) || url.hostname), type: 'wireguard', server: url.hostname,
    port: Number(url.port) || 51820, ip: (url.searchParams.get('ip') || '10.0.0.1').split(',')[0].trim(),
    'private-key': safeDecode(url.username || url.searchParams.get('privateKey') || url.searchParams.get('private-key') || ''),
    'public-key': safeDecode(url.searchParams.get('public-key') || 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo='),
    'allowed-ips': ['0.0.0.0/0'], udp: true
  };
  const profile = url.searchParams.get('profile') || url.searchParams.get('amnezia') || url.searchParams.get('awg_profile');
  if (profile) p.amneziaProfile = profile;
  return p;
}

function parseTuic(link) {
  const url = new URL(link.replace(/^tuic:\/\//i, 'http://'));
  return { name: safeDecode(url.hash.substring(1) || url.hostname), type: 'tuic', server: url.hostname, port: Number(url.port), uuid: safeDecode(url.username) || '', password: safeDecode(url.password) || '' };
}

function parseHttp(link) {
  const u = new URL(link);
  const isHttps = link.toLowerCase().startsWith('https://');
  return { name: safeDecode(u.hash.substring(1) || u.hostname), type: 'http', server: u.hostname, port: Number(u.port) || (isHttps ? 443 : 80), tls: isHttps, username: safeDecode(u.username) || '', password: safeDecode(u.password) || '' };
}

function parseSocks(link) {
  const u = new URL(link.replace(/^(socks|socks5):\/\//i, 'http://'));
  return { name: safeDecode(u.hash.substring(1) || u.hostname), type: 'socks5', server: u.hostname, port: Number(u.port) || 1080, username: safeDecode(u.username) || '', password: safeDecode(u.password) || '' };
}

function parseSnell(link) {
  const u = new URL(link.replace(/^snell:\/\//i, 'http://'));
  return { name: safeDecode(u.hash.substring(1) || u.hostname), type: 'snell', server: u.hostname, port: Number(u.port), psk: safeDecode(u.username || u.searchParams.get('psk')) || '', version: u.searchParams.get('version') || '2' };
}

function parseSSH(link) {
  const u = new URL(link.replace(/^ssh:\/\//i, 'http://'));
  return { name: safeDecode(u.hash.substring(1) || u.hostname), type: 'ssh', server: u.hostname, port: Number(u.port) || 22, user: safeDecode(u.username) || '', password: safeDecode(u.password) || '' };
}

function valid(p) {
  if (!p.server || !p.port || Number.isNaN(p.port) || p.port < 1 || p.port > 65535) return false;
  switch (p.type) {
    case 'vmess': case 'vless': return Boolean(p.uuid);
    case 'trojan': case 'hysteria2': return Boolean(p.password);
    case 'wireguard': return Boolean(p['private-key']);
    case 'hysteria': return Boolean(p.auth_str);
    case 'tuic': return Boolean(p.uuid && p.password);
    case 'snell': return Boolean(p.psk);
    case 'ssh': return Boolean(p.user && p.password);
    default: return true;
  }
}

function parseSource(text) {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const groups = new Map();
  let active = null;
  for (const line of lines) {
    if (line === '🔚') break;
    const urlMatch = line.match(/^(\d+)-(.+)$/);
    if (urlMatch) {
      const gid = urlMatch[1];
      const url = toRawGithubUrl(urlMatch[2].trim());
      if (!groups.has(gid)) groups.set(gid, { id: gid, urls: [], settings: {}, protocolOrder: [] });
      active = groups.get(gid);
      active.urls.push(url);
      continue;
    }
    if (!active) continue;
    const idx = line.indexOf(':');
    if (idx < 1) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    active.settings[key] = value;
    if (!['name', 'All', 'Amnezia'].includes(key)) active.protocolOrder.push(key.toLowerCase());
  }
  return [...groups.values()];
}

function parseLimit(value) {
  if (!value || value === '♾️' || value.toLowerCase() === 'infinity') return Infinity;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : Infinity;
}

function sanitizeName(v) {
  return v.replace(/\.[a-zA-Z0-9]+$/, '').replace(/[^\w@%+.-]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
}

function normalizeProfileName(value) {
  return sanitizeName(String(value || '').toLowerCase()).replace(/_+/g, '-');
}

function getAmneziaPreset(profileName) {
  const normalized = normalizeProfileName(profileName);
  const fromMap = AMNEZIA_PROFILE_PRESETS.get(normalized);
  if (fromMap) return { ...fromMap, ...AMNEZIA_DEFAULT_FIELDS };

  const fallbackKey = [...AMNEZIA_PROFILE_PRESETS.keys()].find((k) =>
    k.replace(/-/g, '').includes(normalized.replace(/-/g, '')) || normalized.replace(/-/g, '').includes(k.replace(/-/g, ''))
  );
  const fallbackPreset = fallbackKey ? AMNEZIA_PROFILE_PRESETS.get(fallbackKey) : null;
  return { ...(fallbackPreset || { jc: 4, jmin: 40, jmax: 100 }), ...AMNEZIA_DEFAULT_FIELDS };
}

function deriveName(urls, explicitName) {
  if (explicitName) return sanitizeName(explicitName);
  const metas = urls.map((u) => {
    const x = new URL(u);
    const h = x.hostname;
    if (h === 'raw.githubusercontent.com') {
      const p = x.pathname.split('/').filter(Boolean);
      const owner = p[0], repo = p[1], rest = p.slice(4);
      return { owner, repo, path: rest };
    }
    return { owner: x.hostname.replace(/\./g, '-'), repo: '', path: x.pathname.split('/').filter(Boolean) };
  });
  const first = metas[0];
  const stems = metas.map((m) => sanitizeName((m.path.at(-1) || 'output')));
  let suffix = stems[0] || 'mix';
  if (stems.length > 1) {
    const parts = stems.map((s) => s.split(/[_-]+/));
    let common = '';
    for (let i = 0; i < Math.min(...parts.map((p) => p.length)); i++) {
      const token = parts[0][i];
      if (parts.every((p) => p[i] === token)) common = token; else break;
    }
    suffix = common || sanitizeName(first.path.at(-2) || 'mix');
    suffix += '-mix';
  }
  return sanitizeName([first.owner, first.repo, suffix].filter(Boolean).join('-'));
}


function countryCodeToFlag(countryCode) {
  if (!countryCode || !/^[A-Za-z]{2}$/.test(countryCode)) return '';
  const code = countryCode.toUpperCase();
  return String.fromCodePoint(...[...code].map((c) => 127397 + c.charCodeAt(0)));
}

async function geoLookup(server) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GEO_FLAG_TIMEOUT_MS);
  try {
    const url = `https://ipwho.is/${encodeURIComponent(server)}`;
    const res = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'mihomo-converter-geo/1.0' } });
    if (!res.ok) return '';
    const data = await res.json();
    if (!data || data.success === false) return '';
    const code = String(data.country_code || '').toUpperCase();
    return countryCodeToFlag(code);
  } catch {
    return '';
  } finally {
    clearTimeout(timer);
  }
}

async function loadGeoCache() {
  const now = Date.now();
  const ttlMs = Math.max(1, GEO_CACHE_TTL_HOURS) * 3600 * 1000;
  try {
    const raw = await fs.readFile(GEO_CACHE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    const entries = Array.isArray(parsed.entries) ? parsed.entries : [];
    const map = new Map();
    for (const row of entries) {
      if (!row || typeof row.server !== 'string') continue;
      const ts = Number(row.ts || 0);
      if (now - ts > ttlMs) continue;
      map.set(row.server, { flag: String(row.flag || ''), ts });
    }
    return map;
  } catch {
    return new Map();
  }
}

async function saveGeoCache(cacheMap) {
  const now = Date.now();
  const items = [...cacheMap.entries()]
    .map(([server, value]) => ({ server, flag: String(value.flag || ''), ts: Number(value.ts || now) }))
    .sort((a, b) => b.ts - a.ts)
    .slice(0, Math.max(100, GEO_CACHE_MAX_ITEMS));

  const payload = { version: 1, updatedAt: now, entries: items };
  await fs.mkdir(path.dirname(GEO_CACHE_FILE), { recursive: true });
  await fs.writeFile(GEO_CACHE_FILE, JSON.stringify(payload), 'utf8');
}

async function resolveFlagsForServers(servers, geoCache) {
  const unique = [...new Set(servers.filter(Boolean))];
  const flags = new Map();
  if (!GEO_FLAG_ENABLED || unique.length === 0) return flags;

  const pending = [];
  for (const server of unique) {
    const cached = geoCache.get(server);
    if (cached) {
      flags.set(server, cached.flag || '');
    } else {
      pending.push(server);
    }
  }

  if (pending.length === 0) return flags;

  let idx = 0;
  const workers = Array.from({ length: Math.max(1, GEO_FLAG_CONCURRENCY) }, async () => {
    while (idx < pending.length) {
      const current = pending[idx++];
      let flag = '';
      for (let attempt = 0; attempt <= GEO_FLAG_RETRY; attempt++) {
        flag = await geoLookup(current);
        if (flag) break;
        if (attempt < GEO_FLAG_RETRY) await sleep(150 + Math.floor(Math.random() * 150));
      }
      flags.set(current, flag);
      geoCache.set(current, { flag, ts: Date.now() });
    }
  });

  await Promise.all(workers);
  return flags;
}

async function withGroupPrefixedNames(proxies, groupId, geoCache) {
  const prefix = `${groupId}-`;
  const flagsByServer = await resolveFlagsForServers(proxies.map((p) => p.server), geoCache);

  for (let i = 0; i < proxies.length; i++) {
    const p = proxies[i];
    const sourceName = String(p.name || p.server || p.type || 'proxy').trim();
    const baseName = sourceName.startsWith(prefix) ? sourceName.slice(prefix.length) : sourceName;
    const flag = flagsByServer.get(p.server) || '';
    p.name = flag ? `${i + 1} ${flag} ${baseName}` : `${i + 1} ${baseName}`;
  }
  return proxies;
}


function buildFullConfig(proxies) {
  const proxyBlock = proxies.length
    ? proxies.map((p) => `  - ${JSON.stringify(p)}`).join('\n')
    : '  []';
  const proxyNames = proxies.length
    ? proxies.map((p) => `      - "${p.name}"`).join('\n')
    : '      - DIRECT';

  return `global-client-fingerprint: chrome
port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7894
allow-lan: true
tcp-concurrent: true
enable-process: true
find-process-mode: always
ipv6: true
log-level: debug
geo-auto-update: true
geo-update-interval: 168
secret: ''
bind-address: '*'
unified-delay: false
disable-keep-alive: false
keep-alive-idle: 30
keep-alive-interval: 30
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  ipv6: true
  respect-rules: false
  prefer-h3: true
  cache-algorithm: arc
  use-system-hosts: true
  use-host: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  fake-ip-filter-mode: blacklist
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.localdomain'
    - '*.invalid'
    - '*.localhost'
    - '*.test'
    - '*.local'
    - '*.home.arpa'
    - 'time.*.com'
    - 'ntp.*.com'
    - '*.ir'
 
  default-nameserver: 
    - 8.8.8.8 
    - 8.8.4.4 
    - 1.0.0.1 
    - 1.1.1.1 
    - 9.9.9.9 
    - 9.9.9.11 
    - 9.9.9.10 
    - 94.140.14.15 
    - 94.140.15.15 
    - 223.5.5.5 
    - 77.88.8.8
  nameserver:
    - 'https://sky.rethinkdns.com/1:-J8AGH8C7_2-___f3_vZ3f_z-f9KagBI'
    - 'tls://1-7cpqagd7alx73px777p5766z3x77h6p7jjvaasa.max.rethinkdns.com'
  direct-nameserver:
    - '78.157.42.100'
    - '78.157.42.101' 
  proxy-server-nameserver: 
    - '2606:4700:4700::1111' 
    - '2606:4700:4700::1001' 
    - '2001:4860:4860::8888' 
    - '2001:4860:4860::8844' 
    - '1.1.1.1' 
    - '8.8.8.8' 
    - '8.8.4.4' 
    - '9.9.9.9' 
    - '223.5.5.5' 
    - '77.88.8.8' 
    - '2400:3200::1' 
    - '2a02:6b8::feed:0ff' 
    - '2620:fe::fe' 

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    HTTP:
      ports: [80, 8080, 8880, 2052, 2082, 2086, 2095]
    TLS:
      ports: [443, 8443, 2053, 2083, 2087, 2096]

tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-detect-interface: true
  auto-redir: true
  dns-hijack:
    - "any:53"
    - "tcp://any:53"

rule-providers:
  local_ips:
    type: http
    behavior: ipcidr
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/local-ips.yaml
    interval: 86400
    path: ./ruleset/local_ips.yaml
  category_ir:
    type: http
    behavior: domain
    url: https://raw.githubusercontent.com/10ium/V2rayDomains2Clash/generated/category-ir.yaml
    interval: 86400
    path: ./ruleset/category_ir.yaml
  iran:
    type: http
    behavior: classical
    url: https://raw.githubusercontent.com/10ium/clash_rules/main/iran.yaml
    interval: 86400
    path: ./ruleset/iran.yaml
  ir:
    type: http
    format: yaml
    behavior: domain
    url: "https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ir.yaml"
    path: ./ruleset/ir.yaml
    interval: 86400
  apps:
    type: http
    format: yaml
    behavior: classical
    url: "https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/apps.yaml"
    path: ./ruleset/apps.yaml
    interval: 86400
  ircidr:
    type: http
    format: yaml
    behavior: ipcidr
    url: "https://github.com/chocolate4u/Iran-clash-rules/releases/latest/download/ircidr.yaml"
    path: ./ruleset/ircidr.yaml
    interval: 86400
  irasn:
    type: http
    format: yaml
    behavior: classical
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/irasn.yaml"
    path: ./ruleset/irasn.yaml
    interval: 86400
  arvancloud:
    type: http
    format: yaml
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/arvancloud.yaml"
    path: ./ruleset/arvancloud.yaml
    interval: 86400
  derakcloud:
    type: http
    format: yaml
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/derakcloud.yaml"
    path: ./ruleset/derakcloud.yaml
    interval: 86400
  iranserver:
    type: http
    format: yaml
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/iranserver.yaml"
    path: ./ruleset/iranserver.yaml
    interval: 86400
  parspack:
    type: http
    format: yaml
    behavior: ipcidr
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/parspack.yaml"
    path: ./ruleset/parspack.yaml
    interval: 86400
proxies:
${proxyBlock}
proxy-groups:
  - name: "نوع انتخاب پروکسی 🔀"
    icon: https://www.svgrepo.com/show/412721/choose.svg
    type: select
    proxies:
      - "خودکار (بهترین پینگ) 🤖"
      - "دستی 🤏🏻"
      - "بدون فیلترشکن 🛡️"
      - "قطع اینترنت ⛔"
  - name: "دستی 🤏🏻"
    type: select
    icon: https://www.svgrepo.com/show/372331/cursor-hand-click.svg
    proxies:
${proxyNames}
  - name: "خودکار (بهترین پینگ) 🤖"
    type: url-test
    icon: https://www.svgrepo.com/show/7876/speedometer.svg
    url: https://api.v2fly.org/checkConnection.svgz
    interval: 300
    tolerance: 50
    lazy: true
    proxies:
${proxyNames}
  - name: سایتای ایرانی 🇮🇷
    type: select
    icon: https://upload.wikimedia.org/wikipedia/commons/3/36/Flag_of_Iran_%28civil%29.svg
    proxies:
      - "بدون فیلترشکن 🛡️"
      - "نوع انتخاب پروکسی 🔀"
      - "خودکار (بهترین پینگ) 🤖"
      - "دستی 🤏🏻"
      - "اجازه ندادن 🚫"
  - name: تلگرام 💬
    type: select
    icon: https://www.svgrepo.com/show/354443/telegram.svg
    proxies:
      - "نوع انتخاب پروکسی 🔀"
      - "بدون فیلترشکن 🛡️"
      - "خودکار (بهترین پینگ) 🤖"
      - "دستی 🤏🏻"
      - "اجازه ندادن 🚫"
  - name: "بدون فیلترشکن 🛡️"
    type: select
    icon: https://www.svgrepo.com/show/6318/connection.svg
    proxies:
      - DIRECT
    hidden: true
  - name: "قطع اینترنت ⛔"
    type: select
    icon: https://www.svgrepo.com/show/305372/wifi-off.svg
    proxies:
      - REJECT
    hidden: true
  - name: "اجازه ندادن 🚫"
    type: select
    icon: https://www.svgrepo.com/show/444307/gui-ban.svg
    proxies:
      - REJECT
    hidden: true

rules:
  - RULE-SET,local_ips,بدون فیلترشکن 🛡️
  - PROCESS-NAME,Telegram.exe,تلگرام 💬
  - PROCESS-NAME,org.telegram.messenger,تلگرام 💬
  - PROCESS-NAME,org.telegram.messenger.web,تلگرام 💬
  - IP-CIDR,10.10.34.0/24,نوع انتخاب پروکسی 🔀
  - RULE-SET,apps,سایتای ایرانی 🇮🇷
  - RULE-SET,iran,سایتای ایرانی 🇮🇷
  - RULE-SET,arvancloud,سایتای ایرانی 🇮🇷
  - RULE-SET,derakcloud,سایتای ایرانی 🇮🇷
  - RULE-SET,iranserver,سایتای ایرانی 🇮🇷
  - RULE-SET,parspack,سایتای ایرانی 🇮🇷
  - RULE-SET,irasn,سایتای ایرانی 🇮🇷
  - RULE-SET,ircidr,سایتای ایرانی 🇮🇷
  - RULE-SET,ir,سایتای ایرانی 🇮🇷
  - RULE-SET,category_ir,سایتای ایرانی 🇮🇷
  - MATCH,نوع انتخاب پروکسی 🔀

ntp:
  enable: true
  server: "time.apple.com"
  port: 123
  interval: 30
`;
}

async function fetchProxies(url) {
  const res = await fetch(url, { headers: { 'User-Agent': 'mihomo-converter-script/1.0' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const raw = await res.text();
  const decoded = decodeSub(raw);
  const proxies = [];
  for (const lineRaw of decoded.split(/\r?\n/)) {
    const line = lineRaw.trim();
    if (!line || line.startsWith('#')) continue;
    const p = parseProxy(line);
    if (p && valid(p)) proxies.push(p);
  }
  return proxies;
}

function applyLimits(allProxies, settings, protocolOrder) {
  const totalLimit = parseLimit(settings.All);
  const protocolKeys = protocolOrder.filter((v, i, a) => a.indexOf(v) === i);
  const hasProtocolRules = protocolKeys.length > 0;

  const limits = new Map();
  for (const proto of protocolKeys) limits.set(proto, parseLimit(settings[proto]));

  const buckets = new Map();
  for (const p of allProxies) {
    const t = getDisplayType(p.type);
    if (hasProtocolRules && !limits.has(t)) continue;
    if (hasProtocolRules && limits.get(t) === 0) continue;
    if (!buckets.has(t)) buckets.set(t, []);
    buckets.get(t).push(p);
  }

  const orderedTypes = hasProtocolRules ? protocolKeys : [...buckets.keys()];
  const picked = [];
  for (const type of orderedTypes) {
    if (!buckets.has(type)) continue;
    const cap = hasProtocolRules ? limits.get(type) : Infinity;
    for (const p of buckets.get(type)) {
      if (picked.length >= totalLimit) return picked;
      const sameCount = picked.filter((x) => getDisplayType(x.type) === type).length;
      if (sameCount >= cap) continue;
      picked.push(p);
    }
  }
  return picked.slice(0, totalLimit);
}

function applyAmneziaVariants(baseName, proxies, amneziaValue) {
  if (!amneziaValue) return [{ fileName: `${baseName}.yaml`, proxies }];

  const requested = amneziaValue.toLowerCase() === 'all'
    ? AMNEZIA_ALL_PROFILES
    : amneziaValue.split('-').map((s) => normalizeProfileName(s.trim())).filter(Boolean);

  if (!requested.length) return [{ fileName: `${baseName}.yaml`, proxies }];

  return requested.map((profile) => {
    const amneziaPreset = getAmneziaPreset(profile);
    const variantProxies = proxies.map((p) => {
      if (p.type !== 'wireguard') return { ...p };
      return { ...p, 'amnezia-wg-option': amneziaPreset };
    });
    return { fileName: `${baseName}-amnezia-${sanitizeName(profile)}.yaml`, proxies: variantProxies };
  });
}

function buildReadme(entries) {
  const lines = ['# Generated Clash Subscriptions', ''];
  for (const e of entries) {
    lines.push(`- [${e.fileName}](${e.rawUrl})`);
  }
  lines.push('');
  return lines.join('\n');
}

async function main() {
  const source = await fs.readFile(SOURCE_FILE, 'utf8');
  const groups = parseSource(source);
  await fs.mkdir(OUTPUT_DIR, { recursive: true });

  const readmeEntries = [];
  const geoCache = await loadGeoCache();

  for (const group of groups) {
    const uniq = new Map();
    for (const url of group.urls) {
      try {
        const proxies = await fetchProxies(url);
        for (const p of proxies) {
          const key = `${p.type}|${p.server}|${p.port}|${p.uuid || p.password || p.auth_str || p['private-key'] || p.psk || p.user || ''}`;
          if (!uniq.has(key)) uniq.set(key, p);
        }
      } catch (e) {
        console.warn(`[WARN] ${url} -> ${e.message}`);
      }
    }

    const outputName = deriveName(group.urls, group.settings.name);
    const limited = await withGroupPrefixedNames(applyLimits([...uniq.values()], group.settings, group.protocolOrder), group.id, geoCache);
    const variants = applyAmneziaVariants(outputName, limited, group.settings.Amnezia);

    const existingFiles = await fs.readdir(OUTPUT_DIR).catch(() => []);
    const keepFiles = new Set(variants.map((v) => v.fileName));
    for (const fileName of existingFiles) {
      if (!fileName.endsWith('.yaml')) continue;
      if (fileName === `${outputName}.yaml` || fileName.startsWith(`${outputName}-amnezia-`)) {
        if (!keepFiles.has(fileName)) {
          await fs.rm(path.join(OUTPUT_DIR, fileName), { force: true });
        }
      }
    }

    for (const variant of variants) {
      const filePath = path.join(OUTPUT_DIR, variant.fileName);
      await fs.writeFile(filePath, buildFullConfig(variant.proxies), 'utf8');
      const rawUrl = RAW_BASE_URL
        ? `${RAW_BASE_URL.replace(/\/$/, '')}/${OUTPUT_DIR}/${variant.fileName}`
        : `${OUTPUT_DIR}/${variant.fileName}`;
      readmeEntries.push({ fileName: variant.fileName, rawUrl });
      console.log(`[OK] ${variant.fileName} (${variant.proxies.length} proxies)`);
    }
  }

  await fs.writeFile(README_FILE, buildReadme(readmeEntries), 'utf8');
  if (GEO_FLAG_ENABLED) await saveGeoCache(geoCache);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
