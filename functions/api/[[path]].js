// Cloudflare Pages Function: /api/ip, /api/dns, /api/whois, /api/status
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

const DOMAIN = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/i;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;
function safeUrl(raw) {
  let u;
  try { u = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw); } catch { return null; }
  const h = u.hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return null;
  if (/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(h)) return null;
  if (h === '[::1]' || /^\[(fc|fd|fe80)/.test(h)) return null;
  return u;
}

const DNS_TYPES = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, SOA: 6, TXT: 16, CAA: 257, DS: 43, DNSKEY: 48, HTTPS: 65 };
async function dns(q, type, res) {
  const base = res === 'google' ? 'https://dns.google/resolve' : 'https://cloudflare-dns.com/dns-query';
  const list = type === 'ALL' ? Object.keys(DNS_TYPES) : DNS_TYPES[type] ? [type] : null;
  if (!list) return [{ error: 'Unknown record type' }, 400];
  const rows = await Promise.all(list.map(async t => {
    try {
      const r = await fetch(`${base}?name=${encodeURIComponent(q)}&type=${DNS_TYPES[t]}`, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(6000) });
      const d = await r.json();
      return [t, { rcode: d.Status, records: (d.Answer || []).filter(x => x.type === DNS_TYPES[t]).map(x => ({ data: x.data, ttl: x.TTL })) }];
    } catch { return [t, { rcode: -1, records: [] }]; }
  }));
  return [{ domain: q, resolver: res === 'google' ? 'google' : 'cloudflare', results: Object.fromEntries(rows) }, 200];
}
const RDAP_FALLBACK = { hk: 'https://rdap.hkirc.hk/' };
const flat = es => (es || []).flatMap(e => [e, ...flat(e.entities)]);
function vcard(e) {
  const v = e.vcardArray?.[1] || [], f = k => v.find(x => x[0] === k)?.[3], adr = v.find(x => x[0] === 'adr');
  const org = f('org');
  return { roles: e.roles, name: f('fn'), org: Array.isArray(org) ? org.join(' ') : org, email: f('email'), phone: f('tel'),
    country: Array.isArray(adr?.[3]) ? adr[3][6] : adr?.[1]?.cc, ianaId: (e.publicIds || []).find(x => /iana/i.test(x.type))?.identifier };
}
async function rdapGet(urls) {
  let last = 'no response';
  for (const u of urls) {
    try {
      const r = await fetch(u, { headers: { accept: 'application/rdap+json, application/json', 'user-agent': 'NetTools/1.0 (RDAP client)' }, redirect: 'follow', signal: AbortSignal.timeout(8000) });
      if (r.ok) return [await r.json(), null, r.url];
      last = r.status;
    } catch (e) { last = e.name === 'TimeoutError' ? 'timeout' : 'network error'; }
  }
  return [null, last, null];
}
async function domainUrls(name) {
  const urls = [], tld = name.split('.').pop();
  try {
    const r = await fetch('https://data.iana.org/rdap/dns.json', { cf: { cacheTtl: 86400, cacheEverything: true } });
    const b = await r.json();
    const svc = b.services.find(x => x[0].includes(tld));
    const base = svc && (svc[1].find(x => x.startsWith('https')) || svc[1][0]);
    if (base) urls.push(base.replace(/\/?$/, '/') + 'domain/' + name);
  } catch {}
  if (RDAP_FALLBACK[tld]) urls.push(RDAP_FALLBACK[tld] + 'domain/' + name);
  urls.push(`https://rdap.org/domain/${name}`);
  return [...new Set(urls)];
}
async function tcpWhois(server, query) {
  const { connect } = await import('cloudflare:sockets');
  const sock = connect({ hostname: server, port: 43 });
  const w = sock.writable.getWriter();
  await w.write(new TextEncoder().encode(query + '\r\n'));
  w.releaseLock();
  const rd = sock.readable.getReader(), dec = new TextDecoder(), t0 = Date.now();
  let out = '';
  while (Date.now() - t0 < 8000 && out.length < 30000) {
    const { value, done } = await Promise.race([rd.read(), new Promise(res => setTimeout(() => res({ done: true }), 8000))]);
    if (done) break;
    out += dec.decode(value, { stream: true });
  }
  try { await sock.close(); } catch {}
  return out;
}
async function whoisText(name) {
  try {
    const tld = name.split('.').pop();
    let server = { hk: 'whois.hkirc.hk' }[tld];
    if (!server) { const t = await tcpWhois('whois.iana.org', tld); server = /^(?:refer|whois):\s*(\S+)/im.exec(t)?.[1]; }
    if (!server) return null;
    const raw = (await tcpWhois(server, name)).replace(/\r/g, '').trim();
    if (!raw || /no match|not found|no data found|object does not exist/i.test(raw.slice(0, 400))) return null;
    const pick = re => re.exec(raw)?.[1]?.trim();
    return { source: 'whois-tcp', kind: 'domain', domain: name, server, registrar: pick(/^\s*registrar(?: name)?:\s*(.+)$/im), status: pick(/^\s*domain status:\s*(.+)$/im),
      registered: pick(/(?:creation|commencement|registered|registration) date:\s*(.+)$/im), expires: pick(/expir\w* date:\s*(.+)$/im),
      nameservers: [...raw.matchAll(/^\s*name server(?: \d+)?:\s*(\S+)/gim)].map(m => m[1]), raw: raw.slice(0, 6000) };
  } catch { return null; }
}
async function whois(q) {
  q = q.replace(/^https?:\/\//, '').replace(/[\/?#].*$/, '');
  const isIp = IPV4.test(q) || (q.includes(':') && IPV6.test(q));
  if (!isIp && !DOMAIN.test(q)) return [{ error: 'Enter a valid domain or IP' }, 400];
  let d, err, used;
  if (isIp) {
    [d, err, used] = await rdapGet([`https://rdap.arin.net/registry/ip/${q}`, `https://rdap.org/ip/${q}`]);
  } else {
    const labels = q.split('.');
    for (let i = 0; i < Math.min(3, labels.length - 1); i++) {
      [d, err, used] = await rdapGet(await domainUrls(labels.slice(i).join('.')));
      if (d) break;
    }
    if (!d) {
      for (const name of [...new Set([q, labels.slice(-3).join('.'), labels.slice(-2).join('.')])]) {
        const t = await whoisText(name);
        if (t) return [t, 200];
      }
    }
  }
  if (!d) return [{ error: `No RDAP or WHOIS data found (RDAP upstream: ${err})` }, 404];
  const ev = Object.fromEntries((d.events || []).map(e => [e.eventAction, e.eventDate]));
  const contacts = flat(d.entities).map(vcard).filter(c => c.name || c.org || c.email || c.phone).slice(0, 10);
  const raw = JSON.stringify(d, null, 2).slice(0, 12000);
  if (isIp) {
    return [{ kind: 'ip', source: 'rdap', rdap_url: used, handle: d.handle, name: d.name, type: d.type, country: d.country,
      range: `${d.startAddress} - ${d.endAddress}`, cidr: (d.cidr0_cidrs || []).map(c => `${c.v4prefix || c.v6prefix}/${c.length}`),
      parent_handle: d.parentHandle, status: d.status, registered: ev.registration, last_changed: ev['last changed'],
      remarks: (d.remarks || []).map(r => (r.description || []).join(' ')).filter(Boolean).slice(0, 4), contacts, raw }, 200];
  }
  const regE = flat(d.entities).find(e => (e.roles || []).includes('registrar')), rv = regE && vcard(regE), exp = ev.expiration;
  return [{ kind: 'domain', source: 'rdap', rdap_url: used, domain: d.ldhName || q, handle: d.handle, registrar: rv?.name || rv?.org, registrar_iana_id: rv?.ianaId,
    status: d.status, registered: ev.registration, expires: exp, last_changed: ev['last changed'], rdap_updated: ev['last update of RDAP database'],
    days_to_expiry: exp ? Math.floor((Date.parse(exp) - Date.now()) / 864e5) : undefined,
    age_years: ev.registration ? +((Date.now() - Date.parse(ev.registration)) / 31557600000).toFixed(1) : undefined,
    nameservers: (d.nameservers || []).map(n => n.ldhName), secure_dns: d.secureDNS?.delegationSigned, whois_server: d.port43, contacts, raw }, 200];
}

async function status(raw) {
  const u = safeUrl(raw);
  if (!u) return [{ error: 'Invalid or blocked URL' }, 400];
  const t0 = Date.now();
  try {
    const r = await fetch(u.href, { redirect: 'follow', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'NetTools-StatusCheck/1.0' } });
    return [{ url: raw, ok: r.ok, status: r.status, statusText: r.statusText, ms: Date.now() - t0, finalUrl: r.url, server: r.headers.get('server') }, 200];
  } catch (e) {
    return [{ url: raw, ok: false, error: e.name === 'TimeoutError' ? 'Timed out (8s)' : 'Unreachable', ms: Date.now() - t0 }, 200];
  }
}

async function subs(q) {
  const names = new Set([q]);
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(q)}&output=json&exclude=expired`, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) throw 0;
    for (const c of await r.json()) for (const n of String(c.name_value).split('\n')) names.add(n);
  } catch {
    try {
      const r = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(q)}&include_subdomains=true&expand=dns_names`, { signal: AbortSignal.timeout(10000) });
      if (r.ok) for (const c of await r.json()) for (const n of c.dns_names || []) names.add(n);
    } catch {}
  }
  const all = [...new Set([...names].map(n => n.toLowerCase().replace(/^\*\./, ''))
    .filter(n => DOMAIN.test(n) && (n === q || n.endsWith('.' + q))))].sort();
  const list = [q, ...all.filter(n => n !== q)].slice(0, 30); // free plan allows ~50 subrequests
  const hosts = await Promise.all(list.map(async host => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
        { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
      return { host, ips: ((await r.json()).Answer || []).filter(a => a.type === 1).map(a => a.data) };
    } catch { return { host, ips: [] }; }
  }));
  let mx = [];
  try {
    const dq = (n, t) => fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
      { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) }).then(r => r.json());
    const rows = ((await dq(q, 'MX')).Answer || []).filter(a => a.type === 15)
      .map(a => { const [pref, h] = a.data.split(' '); return { pref: +pref, host: (h || '').replace(/\.$/, '').toLowerCase() }; })
      .filter(m => DOMAIN.test(m.host)).slice(0, 6);
    mx = await Promise.all(rows.map(async m => {
      try { return { ...m, ips: ((await dq(m.host, 'A')).Answer || []).filter(a => a.type === 1).map(a => a.data) }; }
      catch { return { ...m, ips: [] }; }
    }));
  } catch {}
  return { domain: q, total: all.length, shown: list.length, hosts, mx };
}

async function ipinfo(ip) {
  try {
    const r = await fetch(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [{ error: `IP lookup failed (${r.status})` }, 502];
    const d = await r.json();
    if (d.error) return [{ error: String(d.error) }, 502];
    const a = d.asn || {}, c = d.company || {}, l = d.location || {};
    const pen = { is_abuser: 40, is_tor: 30, is_vpn: 20, is_proxy: 20, is_datacenter: 10 };
    const score = Math.max(0, 100 - Object.entries(pen).reduce((t, [k, v]) => t + (d[k] ? v : 0), 0));
    return [{
      ip: d.ip || ip, score, asn: a.asn ? 'AS' + a.asn : undefined, org: a.org || c.name, route: a.route,
      network_type: a.type || c.type, country: l.country, country_code: l.country_code, city: l.city, timezone: l.timezone,
      datacenter: !!d.is_datacenter, vpn: !!d.is_vpn, proxy: !!d.is_proxy, tor: !!d.is_tor, abuser: !!d.is_abuser, crawler: !!d.is_crawler,
      abuse_score: c.abuser_score,
    }, 200];
  } catch { return [{ error: 'IP lookup unavailable' }, 502]; }
}

async function ping(target) {
  if (!(DOMAIN.test(target) || IPV4.test(target)) || /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(target))
    return [{ error: 'Enter a valid public domain or IPv4' }, 400];
  const r = await fetch('https://api.globalping.io/v1/measurements', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'ping', target, limit: 10, locations: [{ magic: 'world' }] }),
  });
  if (!r.ok) return [{ error: `Globalping error (${r.status})` }, 502];
  const { id } = await r.json();
  for (let i = 0; i < 8; i++) {
    await new Promise(res => setTimeout(res, 1000));
    const m = await (await fetch(`https://api.globalping.io/v1/measurements/${id}`)).json();
    if (m.status === 'finished') {
      return [{ target, probes: (m.results || []).map(x => ({
        city: x.probe?.city, country: x.probe?.country, network: x.probe?.network,
        status: x.result?.status, avg: x.result?.stats?.avg, min: x.result?.stats?.min, loss: x.result?.stats?.loss,
      })) }, 200];
    }
  }
  return [{ error: 'Timed out waiting for probes' }, 504];
}

const RES = { Cloudflare: 'https://cloudflare-dns.com/dns-query', Google: 'https://dns.google/dns-query', Quad9: 'https://dns.quad9.net/dns-query', OpenDNS: 'https://doh.opendns.com/dns-query' };
const b64u = u => btoa(String.fromCharCode(...u)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function packQ(name, t) {
  const o = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  for (const l of name.split('.')) o.push(l.length, ...new TextEncoder().encode(l));
  o.push(0, t >> 8, t & 255, 0, 1);
  return Uint8Array.from(o);
}
function parseDns(buf) {
  const v = new DataView(buf), u = new Uint8Array(buf), dec = new TextDecoder();
  const name = p => {
    const out = []; let end = p, jumped = false;
    for (let n = 0; n < 60; n++) {
      const l = u[p];
      if (l === 0) { if (!jumped) end = p + 1; break; }
      if ((l & 0xc0) === 0xc0) { if (!jumped) end = p + 2; p = ((l & 0x3f) << 8) | u[p + 1]; jumped = true; continue; }
      out.push(dec.decode(u.slice(p + 1, p + 1 + l))); p += l + 1;
    }
    return [out.join('.'), end];
  };
  const qd = v.getUint16(4), an = v.getUint16(6);
  let p = 12;
  for (let i = 0; i < qd; i++) p = name(p)[1] + 4;
  const answers = [];
  for (let i = 0; i < an; i++) {
    p = name(p)[1];
    const t = v.getUint16(p), len = v.getUint16(p + 8); p += 10;
    let d = '';
    if (t === 1) d = [...u.slice(p, p + 4)].join('.');
    else if (t === 28) { const g = []; for (let k = 0; k < 16; k += 2) g.push(v.getUint16(p + k).toString(16)); d = g.join(':'); }
    else if (t === 5 || t === 2) d = name(p)[0];
    else if (t === 15) d = v.getUint16(p) + ' ' + name(p + 2)[0];
    else if (t === 16) { let q = p; while (q < p + len) { d += dec.decode(u.slice(q + 1, q + 1 + u[q])); q += u[q] + 1; } }
    answers.push({ type: t, data: d }); p += len;
  }
  return { rcode: v.getUint8(3) & 15, answers };
}
async function prop(q, type) {
  const t = { A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CNAME: 5 }[type];
  if (!t) return [{ error: 'Type must be A, AAAA, MX, NS, TXT or CNAME' }, 400];
  const dns = b64u(packQ(q, t));
  const results = await Promise.all(Object.entries(RES).map(async ([resolver, base]) => {
    const t0 = Date.now();
    try {
      const r = await fetch(`${base}?dns=${dns}`, { headers: { accept: 'application/dns-message' }, signal: AbortSignal.timeout(6000) });
      if (!r.ok) throw 0;
      const d = parseDns(await r.arrayBuffer());
      return { resolver, ms: Date.now() - t0, rcode: d.rcode, answers: d.answers.filter(a => a.type === t).map(a => a.data) };
    } catch { return { resolver, error: 'No response' }; }
  }));
  return [{ domain: q, type, results }, 200];
}
const ALG = { 5: 'RSASHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256', 10: 'RSASHA512', 13: 'ECDSAP256SHA256', 14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448' };
const DIGEST = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };
const b64b = x => Uint8Array.from(atob(x), c => c.charCodeAt(0));
const keyTag = (flags, alg, pub) => { let ac = 0; [flags >> 8, flags & 255, 3, alg, ...pub].forEach((x, i) => { ac += i & 1 ? x : x << 8; }); ac += (ac >> 16) & 0xffff; return ac & 0xffff; };
const nameWire = n => { const o = []; for (const l of n.replace(/\.$/, '').toLowerCase().split('.')) if (l) o.push(l.length, ...new TextEncoder().encode(l)); o.push(0); return Uint8Array.from(o); };
const keyBits = (alg, pub) => [5, 7, 8, 10].includes(alg) ? (pub.length - (pub[0] === 0 ? 3 : 1) - (pub[0] === 0 ? (pub[1] << 8) | pub[2] : pub[0])) * 8 : { 13: 256, 14: 384, 15: 256, 16: 456 }[alg];
const dnsTime = x => `${x.slice(0, 4)}-${x.slice(4, 6)}-${x.slice(6, 8)}T${x.slice(8, 10)}:${x.slice(10, 12)}:${x.slice(12, 14)}Z`;
async function zoneInfo(zone, g) {
  const root = zone === '.';
  const [dsR, keyR] = await Promise.all([root ? null : g(zone, 'DS'), g(zone, 'DNSKEY')]);
  const keys = (keyR.Answer || []).filter(r => r.type === 48).map(r => {
    const [f, , a, ...k] = r.data.split(' '), flags = +f, alg = +a, pub = b64b(k.join(''));
    return { flags, role: flags & 1 ? 'KSK' : 'ZSK', alg, algorithm: ALG[alg] || String(alg), key_tag: keyTag(flags, alg, pub), key_bits: keyBits(alg, pub), pub };
  });
  const ds = [];
  for (const r of (dsR?.Answer || []).filter(x => x.type === 43)) {
    const [t, a, dt, ...dg] = r.data.split(' '), digest = dg.join('').toUpperCase(), key = keys.find(k => k.key_tag === +t && k.alg === +a);
    let ok = null;
    if (key && DIGEST[+dt]) {
      const buf = Uint8Array.from([...nameWire(zone), key.flags >> 8, key.flags & 255, 3, key.alg, ...key.pub]);
      ok = [...new Uint8Array(await crypto.subtle.digest(DIGEST[+dt], buf))].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase() === digest;
    }
    ds.push({ key_tag: +t, alg: +a, algorithm: ALG[+a] || String(a), digest_type: DIGEST[+dt] || String(dt), digest, key_found: !!key, digest_ok: ok });
  }
  return { zone, is_root: root, signed: keys.length > 0, keys: keys.map(({ pub, ...k }) => k), ds };
}
async function dnssec(q) {
  const g = (name, type, cd) => fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}&do=1${cd ? '&cd=1' : ''}`, { signal: AbortSignal.timeout(6000) }).then(r => r.json());
  const [root, top, dom, a, acd] = await Promise.all([zoneInfo('.', g), zoneInfo(q.split('.').pop(), g), zoneInfo(q, g), g(q, 'A'), g(q, 'A', 1)]);
  const rrsigs = (a.Answer || []).filter(r => r.type === 46).slice(0, 4).map(r => {
    const p = r.data.split(' '), exp = dnsTime(p[4]);
    return { covers: p[0], algorithm: ALG[+p[1]] || p[1], key_tag: +p[6], signer: p[7], inception: dnsTime(p[5]), expires: exp, days_left: Math.floor((Date.parse(exp) - Date.now()) / 864e5) };
  });
  const status = !dom.ds.length ? 'unsigned' : (a.Status === 2 && acd.Status === 0) ? 'bogus' : a.AD ? 'valid' : 'unknown';
  return { domain: q, status, validated_by_resolver: !!a.AD, resolver_status: a.Status, zones: [root, top, dom], rrsigs };
}

async function asnPrefixes(q) {
  const m = /^(?:as)?(\d{1,10})$/i.exec(q);
  if (!m) return [{ error: 'Enter an ASN like AS13335' }, 400];
  const rs = k => fetch(`https://stat.ripe.net/data/${k}/data.json?resource=AS${m[1]}`, { signal: AbortSignal.timeout(10000) }).then(r => r.json()).then(j => j.data || {}).catch(() => ({}));
  const [pf, ov] = await Promise.all([rs('announced-prefixes'), rs('as-overview')]);
  const all = (pf.prefixes || []).map(x => x.prefix);
  const v4 = all.filter(x => !x.includes(':')), v6 = all.filter(x => x.includes(':'));
  if (!all.length) return [{ error: 'No announced prefixes found for this ASN' }, 404];
  return [{ asn: 'AS' + m[1], holder: ov.holder, v4_count: v4.length, v6_count: v6.length, v4: v4.slice(0, 300), v6: v6.slice(0, 300) }, 200];
}
async function bgp(q) {
  if (!/^[0-9a-f.:]+(\/\d{1,3})?$/i.test(q)) return [{ error: 'Enter an IP or prefix, like 1.1.1.0/24' }, 400];
  const rs = k => fetch(`https://stat.ripe.net/data/${k}/data.json?resource=${encodeURIComponent(q)}`, { signal: AbortSignal.timeout(10000) }).then(r => r.json()).then(j => j.data || {}).catch(() => ({}));
  const [st, lg] = await Promise.all([rs('routing-status'), rs('looking-glass')]);
  const vis = st.visibility || {};
  const paths = [];
  for (const rrc of lg.rrcs || []) { const x = (rrc.peers || [])[0]; if (x) paths.push({ location: rrc.location || rrc.rrc, origin: x.asn_origin, path: x.as_path, prefix: x.prefix }); }
  return [{ resource: q, origins: (st.origins || []).map(o => 'AS' + o.origin), first_seen: st.first_seen?.time, last_seen: st.last_seen?.time,
    v4_peers_seeing: vis.v4 ? `${vis.v4.ris_peers_seeing} of ${vis.v4.total_ris_peers}` : undefined,
    v6_peers_seeing: vis.v6 ? `${vis.v6.ris_peers_seeing} of ${vis.v6.total_ris_peers}` : undefined, paths: paths.slice(0, 14) }, 200];
}
const dn = x => Object.fromEntries([...String(x || '').matchAll(/(\w+)=((?:[^,\\]|\\.)+)/g)].map(m => [m[1], m[2].replace(/\\(.)/g, '$1').trim()]));
const covers = (sans, q) => sans.some(x => x === q || (x.startsWith('*.') && q.endsWith(x.slice(1)) && q.split('.').length === x.split('.').length));
async function liveHttps(q) {
  if (!safeUrl('https://' + q)) return { https_ok: false, error: 'Blocked host' };
  const t0 = Date.now();
  try {
    const r = await fetch(`https://${q}/`, { redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'NetTools-TLSCheck/1.0' } });
    let redir = null;
    try { const h = await fetch(`http://${q}/`, { redirect: 'manual', signal: AbortSignal.timeout(6000) }); redir = h.status >= 300 && h.status < 400 && /^https:/i.test(h.headers.get('location') || ''); } catch {}
    return { https_ok: true, status: r.status, ms: Date.now() - t0, hsts: r.headers.get('strict-transport-security'), http_redirects_to_https: redir, server: r.headers.get('server') };
  } catch { return { https_ok: false, error: 'HTTPS connection failed: the certificate may be invalid or expired, or the site is down' }; }
}
async function ssl(q) {
  const [r, live] = await Promise.all([fetch(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json&exclude=expired`, { signal: AbortSignal.timeout(15000) }).catch(() => null), liveHttps(q)]);
  let rows = [];
  try { if (r?.ok) rows = await r.json(); } catch {}
  const seen = new Set();
  rows = rows.filter(x => !seen.has(x.serial_number) && seen.add(x.serial_number));
  if (!rows.length && !live.https_ok) return [{ error: 'No active certificate in the certificate logs, and no HTTPS response from the site' }, 404];
  rows.sort((a, b) => (b.not_before || '').localeCompare(a.not_before || ''));
  const c = rows[0], sans = c ? [...new Set(String(c.name_value).split('\n'))] : [];
  const nb = c && Date.parse(c.not_before + 'Z'), na = c && Date.parse(c.not_after + 'Z'), iss = c ? dn(c.issuer_name) : {};
  return [{ domain: q, live, total_active: rows.length,
    current: c ? { id: c.id, subject_cn: c.common_name, issuer: { CN: iss.CN, O: iss.O, C: iss.C }, not_before: c.not_before, not_after: c.not_after,
      validity_days: Math.round((na - nb) / 864e5), days_left: Math.floor((na - Date.now()) / 864e5), serial: c.serial_number,
      sans: sans.slice(0, 60), san_count: sans.length, wildcard: sans.some(x => x.startsWith('*.')), covers_domain: covers(sans, q) } : null,
    history: rows.slice(0, 10).map(x => ({ id: x.id, not_before: x.not_before, not_after: x.not_after, issuer: dn(x.issuer_name).CN || x.issuer_name })) }, 200];
}
async function oui(q) {
  const hex = q.replace(/[:\-.\s]/g, '').toUpperCase();
  if (!/^[0-9A-F]{6,12}$/.test(hex)) return [{ error: 'Enter a MAC address like 00:1A:2B:3C:4D:5E' }, 400];
  const pre = hex.slice(0, 6).match(/../g).join(':');
  const r = await fetch(`https://api.macvendors.com/${pre}`, { signal: AbortSignal.timeout(6000) });
  if (r.status === 404) return [{ error: 'Vendor not found (it may be a private or randomized MAC)' }, 404];
  if (!r.ok) return [{ error: `Lookup limit reached or unavailable (${r.status}). Try again in a few seconds` }, 502];
  return [{ oui: pre, vendor: (await r.text()).trim() }, 200];
}
async function mtr(q) {
  if (!(DOMAIN.test(q) || IPV4.test(q)) || /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(q))
    return [{ error: 'Enter a valid public domain or IPv4' }, 400];
  const r = await fetch('https://api.globalping.io/v1/measurements', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'mtr', target: q, limit: 3, locations: [{ magic: 'world' }] }),
  });
  if (!r.ok) return [{ error: `Globalping error (${r.status})` }, 502];
  const { id } = await r.json();
  for (let i = 0; i < 20; i++) {
    await new Promise(res => setTimeout(res, 1500));
    const m = await (await fetch(`https://api.globalping.io/v1/measurements/${id}`)).json();
    if (m.status !== 'finished') continue;
    return [{ target: q, probes: (m.results || []).map(x => ({
      city: x.probe?.city, country: x.probe?.country, network: x.probe?.network, status: x.result?.status,
      hops: (x.result?.hops || []).map((h, n) => ({ hop: n + 1, host: h.resolvedHostname || h.resolvedAddress || '???', asn: Array.isArray(h.asn) ? h.asn[0] : h.asn,
        loss: h.stats?.loss, sent: h.stats?.total, last: h.timings?.length ? h.timings[h.timings.length - 1].rtt : null,
        avg: h.stats?.avg, best: h.stats?.min, worst: h.stats?.max, stdev: h.stats?.stDev })) })) }, 200];
  }
  return [{ error: 'Timed out waiting for the probes (MTR can take 20 seconds or more). Try again' }, 504];
}

async function intel(q, t) {
  const get = u => fetch(u, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
  if (t === 'ip') {
    const r = await get(`https://internetdb.shodan.io/${encodeURIComponent(q)}`);
    if (r.status === 404) return [{ found: false }, 200];
    if (!r.ok) return [{ error: `Shodan InternetDB error (${r.status})` }, 502];
    const d = await r.json();
    return [{ found: true, ports: d.ports, hostnames: d.hostnames, cpes: d.cpes, tags: d.tags, vulns: d.vulns }, 200];
  }
  if (t === 'hash') {
    const r = await get(`https://hashlookup.circl.lu/lookup/${{ 32: 'md5', 40: 'sha1', 64: 'sha256' }[q.length]}/${q}`);
    if (r.status === 404) return [{ found: false }, 200];
    if (!r.ok) return [{ error: `CIRCL hashlookup error (${r.status})` }, 502];
    const d = await r.json();
    return [{ found: true, name: d.FileName, size: d.FileSize, trust: d['hashlookup:trust'], source: d.source }, 200];
  }
  const r = await get(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent('domain:' + q)}&size=10`);
  if (!r.ok) return [{ error: `urlscan.io error (${r.status})` }, 502];
  const d = await r.json();
  return [{ total: d.total, scans: (d.results || []).map(x => ({ time: x.task?.time, url: x.page?.url || x.task?.url, ip: x.page?.ip, country: x.page?.country, status: x.page?.status, id: x._id })) }, 200];
}
async function cve(id) {
  if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) return [{ error: 'Enter a CVE ID like CVE-2021-44228' }, 400];
  const j = u => fetch(u, { signal: AbortSignal.timeout(9000) }).then(r => r.ok ? r.json() : null).catch(() => null);
  const [n, e] = await Promise.all([j(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`), j(`https://api.first.org/data/v1/epss?cve=${id}`)]);
  const c = n?.vulnerabilities?.[0]?.cve;
  if (!c) return [{ error: 'CVE not found (or the NVD service is busy, try again)' }, 404];
  const m = (c.metrics?.cvssMetricV31 || c.metrics?.cvssMetricV40 || c.metrics?.cvssMetricV30 || [])[0]?.cvssData || {};
  const ep = e?.data?.[0];
  return [{ id, published: c.published, modified: c.lastModified, description: (c.descriptions || []).find(x => x.lang === 'en')?.value,
    cvss: m.baseScore, severity: m.baseSeverity, vector: m.vectorString, epss: ep ? +ep.epss : undefined, epss_percentile: ep ? +ep.percentile : undefined,
    kev: c.cisaExploitAdd ? { added: c.cisaExploitAdd, due: c.cisaActionDue } : undefined,
    references: (c.references || []).map(x => x.url).filter(x => /^https?:\/\//.test(x)).slice(0, 6) }, 200];
}
async function mailsec(q, sel) {
  const txt = async n => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=TXT`, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) });
      return ((await r.json()).Answer || []).filter(a => a.type === 16).map(a => a.data.replace(/^"|"$/g, '').replace(/" "/g, ''));
    } catch { return []; }
  };
  const [root, dm, dk] = await Promise.all([txt(q), txt('_dmarc.' + q), sel ? txt(`${sel}._domainkey.${q}`) : []]);
  const spf = root.find(x => /^v=spf1/i.test(x)), dmarc = dm.find(x => /^v=DMARC1/i.test(x));
  const all = spf && /(?:^|\s)([+\-~?]?)all\b/i.exec(spf);
  const tag = (x, k) => new RegExp(`(?:^|;)\\s*${k}=([^;]+)`, 'i').exec(x || '')?.[1]?.trim();
  return { domain: q, spf: spf || null, spf_all: all ? (all[1] || '+') + 'all' : null, dmarc: dmarc || null,
    dmarc_policy: tag(dmarc, 'p'), dmarc_subdomain_policy: tag(dmarc, 'sp'), dmarc_pct: tag(dmarc, 'pct'), dmarc_rua: tag(dmarc, 'rua'),
    dkim_selector: sel || null, dkim: sel ? (dk[0] || null) : undefined };
}
async function headers(raw) {
  const u = safeUrl(raw);
  if (!u) return [{ error: 'Invalid or blocked URL' }, 400];
  try {
    const r = await fetch(u.href, { redirect: 'follow', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'NetTools-HeaderCheck/1.0' } });
    const names = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
    return [{ url: r.url, status: r.status, server: r.headers.get('server'), powered_by: r.headers.get('x-powered-by'),
      checks: Object.fromEntries(names.map(n => [n, r.headers.get(n)])),
      cookies: (r.headers.getSetCookie?.() || []).map(c => ({ name: c.split('=')[0], secure: /;\s*secure/i.test(c), httponly: /;\s*httponly/i.test(c), samesite: /;\s*samesite=/i.test(c) })) }, 200];
  } catch { return [{ error: 'Could not reach the site' }, 502]; }
}

const vtKey = env => env?.VT_API_KEY || env?.VIRUSTOTAL_API_KEY || env?.VT_KEY;
async function vt(q, env) {
  if (!/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(q)) return [{ error: 'Enter an MD5, SHA-1 or SHA-256 hash' }, 400];
  if (!vtKey(env)) return [{ error: 'VirusTotal is not set up on this site yet' }, 503];
  const r = await fetch(`https://www.virustotal.com/api/v3/files/${q}`, {
    headers: { 'x-apikey': vtKey(env), accept: 'application/json' }, signal: AbortSignal.timeout(10000),
    cf: { cacheTtl: 3600, cacheEverything: true },
  });
  if (r.status === 404) return [{ found: false }, 200];
  if (r.status === 429) return [{ error: 'VirusTotal free limit reached (4 per minute, 500 per day). Try again soon' }, 429];
  if (r.status === 401 || r.status === 403) return [{ error: 'VirusTotal rejected the API key' }, 502];
  if (!r.ok) return [{ error: `VirusTotal error (${r.status})` }, 502];
  const a = (await r.json()).data?.attributes || {}, st = a.last_analysis_stats || {};
  const day = t => t ? new Date(t * 1000).toISOString().slice(0, 10) : undefined;
  const total = (st.malicious || 0) + (st.suspicious || 0) + (st.harmless || 0) + (st.undetected || 0);
  return [{ found: true, malicious: st.malicious || 0, suspicious: st.suspicious || 0, total, name: a.meaningful_name, type: a.type_description,
    size: a.size, threat_label: a.popular_threat_classification?.suggested_threat_label, first_seen: day(a.first_submission_date),
    last_analysis: day(a.last_analysis_date), tags: (a.tags || []).slice(0, 8) }, 200];
}

async function vtx(q, t, env) {
  if (!vtKey(env)) return [{ error: 'VirusTotal is not set up on this site yet' }, 503];
  const r = await fetch(`https://www.virustotal.com/api/v3/${{ domain: 'domains', ip: 'ip_addresses', hash: 'files' }[t]}/${encodeURIComponent(q)}`, {
    headers: { 'x-apikey': vtKey(env), accept: 'application/json' }, signal: AbortSignal.timeout(10000), cf: { cacheTtl: 3600, cacheEverything: true } });
  if (r.status === 404) return [{ found: false, type: t }, 200];
  if (r.status === 429) return [{ error: 'VirusTotal free limit reached (4 per minute, 500 per day). Try again soon' }, 429];
  if (r.status === 401 || r.status === 403) return [{ error: 'VirusTotal rejected the API key' }, 502];
  if (!r.ok) return [{ error: `VirusTotal error (${r.status})` }, 502];
  const a = (await r.json()).data?.attributes || {}, st = a.last_analysis_stats || {};
  const day = x => x ? new Date(x * 1000).toISOString().slice(0, 10) : undefined;
  const c = a.last_https_certificate;
  const out = { found: true, type: t, malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, undetected: st.undetected || 0,
    total: (st.malicious || 0) + (st.suspicious || 0) + (st.harmless || 0) + (st.undetected || 0), reputation: a.reputation, last_analysis: day(a.last_analysis_date), tags: (a.tags || []).slice(0, 12),
    categories: [...new Set(Object.values(a.categories || {}))].slice(0, 12),
    flagged: Object.entries(a.last_analysis_results || {}).filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious').map(([engine, v]) => ({ engine, category: v.category, result: v.result })).slice(0, 40),
    cert: c ? { issuer: c.issuer?.O || c.issuer?.CN, subject: c.subject?.CN, valid_from: c.validity?.not_before, valid_to: c.validity?.not_after, sans: (c.extensions?.subject_alternative_name || []).slice(0, 20), sha256: c.thumbprint_sha256 } : undefined };
  if (t === 'domain') Object.assign(out, { registrar: a.registrar, created: day(a.creation_date), whois_updated: day(a.whois_date), whois: (a.whois || '').slice(0, 3000),
    dns: (a.last_dns_records || []).slice(0, 30).map(x => ({ type: x.type, value: x.value, ttl: x.ttl })), ranks: Object.entries(a.popularity_ranks || {}).map(([source, v]) => ({ source, rank: v.rank })).slice(0, 8) });
  if (t === 'ip') Object.assign(out, { asn: a.asn, owner: a.as_owner, country: a.country, network: a.network, rir: a.regional_internet_registry });
  if (t === 'hash') Object.assign(out, { name: a.meaningful_name, file_type: a.type_description, size: a.size, threat_label: a.popular_threat_classification?.suggested_threat_label, first_seen: day(a.first_submission_date), sha256: a.sha256, sha1: a.sha1, md5: a.md5 });
  return [out, 200];
}
async function rawHeaders(raw) {
  let url = /^https?:\/\//i.test(raw) ? raw : 'http://' + raw;
  const hops = [];
  for (let i = 0; i < 6; i++) {
    const u = safeUrl(url);
    if (!u) { if (!hops.length) return [{ error: 'Invalid or blocked URL' }, 400]; hops.push({ url, error: 'Redirect to a blocked or invalid address was not followed' }); break; }
    const t0 = Date.now();
    let r;
    try { r = await fetch(u.href, { redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'NetTools-HeaderView/1.0', accept: '*/*' } }); }
    catch { hops.push({ url: u.href, error: 'Could not connect to this address' }); break; }
    const sc = r.headers.getSetCookie?.() || [];
    hops.push({ url: u.href, status: r.status, statusText: r.statusText, ms: Date.now() - t0,
      headers: [...r.headers.entries()].filter(([k]) => k !== 'set-cookie').concat(sc.map(v => ['set-cookie', v])).map(([k, v]) => [k, String(v).slice(0, 600)]) });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { try { url = new URL(loc, u.href).href; } catch { break; } } else break;
  }
  return [{ hops }, 200];
}

export async function onRequestGet({ request, params, env }) {
  const url = new URL(request.url);
  const route = [].concat(params.path || [])[0];
  const q = (url.searchParams.get('q') || url.searchParams.get('url') || '').trim().toLowerCase().replace(/\.$/, '');

  if (route === 'ip') {
    const c = request.cf || {};
    return json({
      ip: request.headers.get('CF-Connecting-IP'), country: c.country, region: c.region, city: c.city,
      postal: c.postalCode, timezone: c.timezone, latitude: c.latitude, longitude: c.longitude,
      asn: c.asn, org: c.asOrganization, datacenter: c.colo, http: c.httpProtocol, tls: c.tlsVersion,
    });
  }
  if (route === 'dns') {
    if (!DOMAIN.test(q)) return json({ error: 'Enter a valid domain' }, 400);
    const [d, st] = await dns(q, (url.searchParams.get('t') || 'ALL').toUpperCase(), (url.searchParams.get('r') || 'cloudflare').toLowerCase());
    return json(d, st);
  }
  if (route === 'whois') { const [d, s] = await whois(q); return json(d, s); }
  if (route === 'status') {
    const raw = (url.searchParams.get('url') || '').trim();
    const [d, s] = await status(raw); return json(d, s);
  }
  if (route === 'subs') {
    if (!DOMAIN.test(q)) return json({ error: 'Enter a valid domain' }, 400);
    return json(await subs(q));
  }
  if (route === 'ipinfo') {
    const ip = q || request.headers.get('CF-Connecting-IP') || '';
    if (!(IPV4.test(ip) || (ip.includes(':') && IPV6.test(ip)))) return json({ error: 'Enter a valid IP address' }, 400);
    const [d, st] = await ipinfo(ip); return json(d, st);
  }
  if (route === 'ping') { const [d, st] = await ping(q); return json(d, st); }
  if (route === 'prop') { const [d, st] = await prop(q, (url.searchParams.get('t') || 'A').toUpperCase()); return json(d, st); }
  if (route === 'dnssec') {
    if (!DOMAIN.test(q)) return json({ error: 'Enter a valid domain' }, 400);
    return json(await dnssec(q));
  }
  if (route === 'asn') { const [d, st] = await asnPrefixes(q); return json(d, st); }
  if (route === 'bgp') { const [d, st] = await bgp(q); return json(d, st); }
  if (route === 'ssl') {
    if (!DOMAIN.test(q)) return json({ error: 'Enter a valid domain' }, 400);
    const [d, st] = await ssl(q); return json(d, st);
  }
  if (route === 'oui') { const [d, st] = await oui(q); return json(d, st); }
  if (route === 'mtr') { const [d, st] = await mtr(q); return json(d, st); }
  if (route === 'intel') {
    const t = url.searchParams.get('t');
    const ok = t === 'ip' ? (IPV4.test(q) || (q.includes(':') && IPV6.test(q))) : t === 'hash' ? /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(q) : t === 'domain' ? DOMAIN.test(q) : false;
    if (!ok) return json({ error: 'Invalid indicator' }, 400);
    const [d, st] = await intel(q, t); return json(d, st);
  }
  if (route === 'cve') { const [d, st] = await cve(q.toUpperCase()); return json(d, st); }
  if (route === 'mailsec') {
    if (!DOMAIN.test(q)) return json({ error: 'Enter a valid domain' }, 400);
    const sel = (url.searchParams.get('sel') || '').toLowerCase();
    if (sel && !/^[a-z0-9._-]{1,63}$/.test(sel)) return json({ error: 'Invalid DKIM selector' }, 400);
    return json(await mailsec(q, sel));
  }
  if (route === 'headers') { const [d, st] = await headers((url.searchParams.get('url') || '').trim()); return json(d, st); }
  if (route === 'health') return json({ ok: true, virustotal_key_found: !!vtKey(env) });
  if (route === 'vt') {
    const sfs = request.headers.get('sec-fetch-site');
    if (sfs && sfs !== 'same-origin') return json({ error: 'Not allowed' }, 403);
    const [d, st] = await vt(q, env); return json(d, st);
  }
  if (route === 'vtx') {
    const sfs = request.headers.get('sec-fetch-site');
    if (sfs && sfs !== 'same-origin') return json({ error: 'Not allowed' }, 403);
    const t = url.searchParams.get('t');
    const ok = t === 'domain' ? DOMAIN.test(q) : t === 'ip' ? (IPV4.test(q) || (q.includes(':') && IPV6.test(q))) : t === 'hash' ? /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(q) : false;
    if (!ok) return json({ error: 'Enter a domain, IP address or file hash' }, 400);
    const [d, st] = await vtx(q, t, env); return json(d, st);
  }
  if (route === 'hdrs') { const [d, st] = await rawHeaders((url.searchParams.get('url') || '').trim()); return json(d, st); }
  return json({ error: 'Not found' }, 404);
}
