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

async function whois(q) {
  const isIp = IPV4.test(q) || (q.includes(':') && IPV6.test(q));
  if (!isIp && !DOMAIN.test(q)) return [{ error: 'Enter a valid domain or IP' }, 400];
  const r = await fetch(`https://rdap.org/${isIp ? 'ip' : 'domain'}/${encodeURIComponent(q)}`,
    { headers: { accept: 'application/rdap+json' }, redirect: 'follow' });
  if (!r.ok) return [{ error: 'No RDAP data for this query' }, 404];
  const d = await r.json();
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
  return json({ error: 'Not found' }, 404);
}
