#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';

const SOURCE_FILE = process.env.SOURCE_FILE || 'source';
const OUTPUT_DIR = process.env.OUTPUT_DIR || 'sub';
const README_FILE = process.env.README_FILE || 'README.md';
const RAW_BASE_URL = process.env.RAW_BASE_URL || '';

const PROTOCOL_ALIASES = new Map([
  ['hysteria2', 'hy2'],
  ['hysteria', 'hysteria'],
  ['wireguard', 'wg'],
  ['socks5', 'socks'],
]);

const AMNEZIA_PRESET = { jc: 4, jmin: 40, jmax: 100, s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4 };

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
mode: rule
log-level: info
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  ipv6: true
  enhanced-mode: fake-ip
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
proxies:
${proxyBlock}
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "Auto"
      - "DIRECT"
  - name: "Auto"
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
${proxyNames}
rules:
  - GEOIP,IR,DIRECT
  - MATCH,Proxy
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

function withNames(proxies) {
  const counters = new Map();
  for (const p of proxies) {
    const t = getDisplayType(p.type);
    counters.set(t, (counters.get(t) || 0) + 1);
    p.name = `${t} ${counters.get(t)}`;
  }
  return proxies;
}

function applyAmneziaVariants(baseName, proxies, amneziaValue) {
  if (!amneziaValue) return [{ fileName: `${baseName}.yaml`, proxies }];
  const wireguards = proxies.filter((p) => p.type === 'wireguard');
  if (!wireguards.length) return [{ fileName: `${baseName}.yaml`, proxies }];

  const profiles = [...new Set(wireguards.map((p) => p.amneziaProfile || 'default'))];
  const wanted = amneziaValue.toLowerCase() === 'all'
    ? profiles
    : amneziaValue.split('-').map((s) => s.trim()).filter(Boolean);

  if (!wanted.length) return [{ fileName: `${baseName}.yaml`, proxies }];

  return wanted.map((profile) => {
    const variantProxies = proxies
      .filter((p) => p.type !== 'wireguard' || (p.amneziaProfile || 'default') === profile)
      .map((p) => (p.type === 'wireguard' ? { ...p, 'amnezia-wg-option': AMNEZIA_PRESET } : { ...p }));
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
    const limited = withNames(applyLimits([...uniq.values()], group.settings, group.protocolOrder));
    const variants = applyAmneziaVariants(outputName, limited, group.settings.Amnezia);

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
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
