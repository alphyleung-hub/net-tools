// Cloudflare Pages Function: /api/ip, /api/dns, /api/whois, /api/status
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

const DOMAIN = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/i;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;
const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };

function safeUrl(raw) {
  let u;
  try { u = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw); } catch { return null; }
  const h = u.hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return null;
  if (/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(h)) return null;
  if (h === '[::1]' || /^\[(fc|fd|fe80)/.test(h)) return null;
  return u;
}

async function dns(q) {
  const rows = await Promise.all(Object.entries(TYPES).map(async ([t, num]) => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(q)}&type=${t}`,
        { headers: { accept: 'application/dns-json' } });
      const d = await r.json();
      return [t, (d.Answer || []).filter(a => a.type === num).map(a => ({ data: a.data, ttl: a.TTL }))];
    } catch { return [t, []]; }
  }));
  return Object.fromEntries(rows);
}

async function rdapGet(urls) {
  let last = 'no response';
  for (const u of urls) {
    try {
      const r = await fetch(u, {
        headers: { accept: 'application/rdap+json, application/json' },
        redirect: 'follow', signal: AbortSignal.timeout(8000),
      });
      if (r.ok) return [await r.json(), null];
      last = r.status;
    } catch (e) { last = e.name === 'TimeoutError' ? 'timeout' : 'network error'; }
  }
  return [null, last];
}

async function domainUrls(name) {
  const urls = [];
  try {
    const r = await fetch('https://data.iana.org/rdap/dns.json', { cf: { cacheTtl: 86400, cacheEverything: true } });
    const b = await r.json();
    const svc = b.services.find(s => s[0].includes(name.split('.').pop()));
    const base = svc && (svc[1].find(x => x.startsWith('https')) || svc[1][0]);
    if (base) urls.push(base.replace(/\/?$/, '/') + 'domain/' + name);
  } catch {}
  urls.push(`https://rdap.org/domain/${name}`);
  return urls;
}

async function whois(q) {
  const isIp = IPV4.test(q) || (q.includes(':') && IPV6.test(q));
  if (!isIp && !DOMAIN.test(q)) return [{ error: 'Enter a valid domain or IP' }, 400];
  let d, err;
  if (isIp) {
    [d, err] = await rdapGet([`https://rdap.arin.net/registry/ip/${q}`, `https://rdap.org/ip/${q}`]);
  } else {
    // try the name, then its parent domains (e.g. www.example.com -> example.com)
    const labels = q.split('.');
    for (let i = 0; i < Math.min(3, labels.length - 1); i++) {
      [d, err] = await rdapGet(await domainUrls(labels.slice(i).join('.')));
      if (d) break;
    }
  }
  if (!d) return [{ error: `No RDAP data (upstream: ${err})` }, 404];
  const ev = Object.fromEntries((d.events || []).map(e => [e.eventAction, e.eventDate]));
  if (isIp) {
    return [{
      handle: d.handle, name: d.name, type: d.type, country: d.country,
      range: `${d.startAddress} - ${d.endAddress}`,
      cidr: (d.cidr0_cidrs || []).map(c => `${c.v4prefix || c.v6prefix}/${c.length}`),
      registered: ev.registration, updated: ev['last changed'],
    }, 200];
  }
  const reg = (d.entities || []).find(e => (e.roles || []).includes('registrar'));
  const registrar = reg?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3];
  return [{
    domain: d.ldhName, registrar, status: d.status,
    registered: ev.registration, expires: ev.expiration, updated: ev['last changed'],
    nameservers: (d.nameservers || []).map(n => n.ldhName),
  }, 200];
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
  return { domain: q, total: all.length, shown: list.length, hosts };
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

export async function onRequestGet({ request, params }) {
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
    return json(await dns(q));
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
  return json({ error: 'Not found' }, 404);
}
