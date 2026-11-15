<div align="center">

# 🌐 Net Tools

**A free, open-source network and security toolbox that runs on Cloudflare's free plan.**
IP lookup · DNS · domain mapping · BGP · subnet calculators · threat-intel triage — 42 tools in one simple page.

![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)
![No build step](https://img.shields.io/badge/build-none-brightgreen)
![Vanilla JS](https://img.shields.io/badge/JavaScript-vanilla-F7DF1E?logo=javascript&logoColor=black)
![Free to host](https://img.shields.io/badge/hosting-free-blue)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

**[Live demo](https://net-tools.alphyleung.workers.dev)** · [Features](#-features) · [Deploy your own](#-deploy-your-own-free) · [API](#-api) · [Contributing](#-contributing)

</div>

---

## Why Net Tools?

Network engineers, SOC analysts and curious people often juggle a dozen websites for simple jobs: "what is my IP?", "who owns this domain?", "is this hash known?", "what is the subnet mask?". **Net Tools puts them in one clean, friendly page**, explains each result in plain words, and tells you exactly **where every tool gets its data**.

- 🆓 **Free to host.** Runs on Cloudflare Workers' free plan. No servers, no database, no build step.
- 🔒 **Privacy first.** Many tools run 100% in your browser and send nothing anywhere.
- 🧭 **Beginner friendly.** Every tool has a short, easy explanation and one-click examples.
- 🧩 **Simple code.** One HTML file and one API file. Easy to read, fork and extend.
- 🌗 **Light, dark and auto themes**, works on phones.

## ✨ Features

42 tools in seven categories. 🔒 = runs entirely in your browser (nothing is sent anywhere).

### 🏠 Connection
| Tool | What it does | Data from |
|---|---|---|
| **My IP** | Your public IP, location, ASN and Cloudflare trace. Hide-IP button for screenshots | Cloudflare |
| **Claude Check** | Region support, IP quality, reachability of claude.ai, WebRTC leak and device info | ipapi.is, Anthropic supported-regions list, your browser |
| **IP Score** | 0-100 trust estimate with VPN / proxy / Tor / datacenter / abuse flags | ipapi.is |
| **Split Test** | Do different websites see different IPs from you? | 10 public IP-echo sites |
| **WebRTC** | Is your browser leaking your real IP? | your browser + STUN |

### 🌍 Domain & DNS
| Tool | What it does | Data from |
|---|---|---|
| **Domain Map** | Sub-sites, server IPs, hosting networks, colored relationship graph, **Excel export** | crt.sh, Cloudflare DNS, ipapi.is |
| **DNS** | All record types (A, AAAA, CNAME, MX, NS, SOA, TXT, CAA, DS, DNSKEY, HTTPS) from Cloudflare or Google, each explained in plain words | Cloudflare / Google DoH |
| **Whois** | Registrar, status locks, dates, age, name servers, contacts (domains, including .com.hk) or owner (IPs) | RDAP, WHOIS fallback |
| **Propagation** | Ask Cloudflare, Google, Quad9 and OpenDNS at once | DNS over HTTPS |
| **DNSSEC** | Chain of trust root → TLD → domain, DS / DNSKEY / RRSIG details, independent DS check | Google Public DNS |
| **SSL/TLS** | Certificate details, expiry, issuance history, live HTTPS / HSTS check | crt.sh + live check |

### 📡 Network
| Tool | What it does | Data from |
|---|---|---|
| **Ping** | Latency from 10 locations worldwide | Globalping.io |
| **Status** | Is a website up, and how fast? (up to 10 at once) | this site's Worker |
| **Server Headers** | Raw HTTP response headers, hop by hop through redirects | this site's Worker |
| **MTR** | Hop-by-hop route from 3 worldwide probes, color-coded loss and delay | Globalping.io |
| **ASN Prefixes** | Every IPv4 / IPv6 prefix a network announces | RIPEstat |
| **BGP Route** | Route visibility, origin AS and sample AS paths | RIPEstat (RIS collectors) |

### ✉️ Email
| Tool | What it does | Data from |
|---|---|---|
| **Email Health** | One report with a grade: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, reverse DNS and blocklists, with fixes | Cloudflare DNS, public blocklists |
| **MX Lookup** | Mail servers, IPv4/IPv6, reverse DNS, provider detection | Cloudflare DNS |
| **DMARC Check** | Policy, every tag explained, report authorisation and how to strengthen it | Cloudflare DNS |
| **SPF/DKIM** | Quick SPF, DKIM and DMARC check | Cloudflare DNS |
| **Header Analyzer** 🔒 | Route, delays, TLS and SPF/DKIM/DMARC results of a pasted email header | browser |

### ☁️ Cloud
| Tool | What it does | Data from |
|---|---|---|
| **Cloud Health** | Status board for Microsoft 365, Azure, AWS, Google Cloud, Cloudflare, GitHub and Claude with clickable core-service tiles | provider RSS / Atom feeds and Statuspage APIs |

### 🛡️ Security
| Tool | What it does | Data from |
|---|---|---|
| **Investigate** | Paste an IP, domain, URL or hash. Get findings, pivot links and a **triage report** (copy / download) | Shodan InternetDB (IPs), urlscan.io (domains), CIRCL + VirusTotal (hashes) |
| **VirusTotal** | Domain, IP or hash: detections, categories, DNS, certificate, WHOIS (needs `VT_API_KEY`) | VirusTotal API |
| **NVD Dashboard** | New CVEs by severity, CISA KEV count, newest critical CVEs, keyword search | NIST NVD API |
| **Patch Check** 🔒 | Verify KBs, minimum versions or CVE fixes against pasted endpoint inventories | browser + NVD |
| **Watchlist** ⭐🔒 | Save indicators in your browser, re-check with one click, export CSV | local storage |
| **Email Security** | SPF, DKIM and DMARC with plain-language grades | Cloudflare DNS |
| **Security Headers** | HSTS, CSP, X-Frame-Options and more, plus cookie flags | this site's Worker |
| **CVE Lookup** | CVSS, EPSS exploit probability and CISA KEV flag | NVD, FIRST |
| **Decoder** 🔒 | Base64, URL, Hex, gzip, PowerShell UTF-16, ROT13, defang/refang (CyberChef-lite) | browser |
| **IOC Extractor** 🔒 | Pull IPs, domains, URLs, emails, hashes and CVEs out of any text | browser |
| **Hash** 🔒 | SHA-1 / 256 / 384 / 512 of text | browser |
| **JWT Decoder** 🔒 | Read header, payload and expiry (signature not verified) | browser |
| **Password Check** | Has this password appeared in a breach? Only 5 hash characters leave your browser | Have I Been Pwned |

### 🧮 Tools
| Tool | What it does | Data from |
|---|---|---|
| **Subnet Calc** 🔒 | IPv4 and IPv6: network, broadcast, usable hosts, masks | browser |
| **Range to CIDR** 🔒 | `192.168.1.0 - 192.168.1.255` → `192.168.1.0/24` | browser |
| **Transfer Time** 🔒 | "How long to move 50 GB over 500 Mbps?" with overhead | browser |
| **MAC Lookup** | Vendor of a MAC address, flags random private MACs | macvendors.com |
| **Config Generator** 🔒 | Cisco IOS VLAN, MikroTik address-list, Linux nftables | browser |
| **History** 🔒 | Every check with its time, exportable as CSV or JSON | local storage |
| **More Tools** | Links to Check-Host (terminal, ping, HTTP, TCP, DNS), VirtualBytes, DNSChecker, VirusTotal | external sites |

## 🧰 Everyday conveniences

- **Export any result** as JSON or CSV, with a time stamp (⬇ buttons above every result).
- **History**: every check is logged with its time (tool: History), exportable as CSV or JSON.
- **Watchlist for every tool**: press ☆ Watch on any result and re-check it later.
- **Recent inputs**: the last 20 IPs and domains appear as chips under "Try:", each with a × to remove it.
- **✨ Ask Gemini**: every tool has a button that copies a short question about the tool and opens Gemini, so you can learn what it is for (your inputs are not included).
- **Paste anything**: full URLs such as `https://www.example.com/page` are accepted; the domain is extracted automatically.
- **Results stay put** when you switch tools, and the browser Back / Forward buttons move between tools.
- Recent inputs, history and the watchlist live in your browser only.

## 🔐 Privacy

- 🔒 tools never send what you type anywhere.
- Other tools send your input to **this site's Worker**, which asks the third-party service listed above. Nothing is stored by the Worker.
- The **Watchlist** lives in your browser's local storage only.
- The **Password Check** uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent.
- Never paste secrets, private files or internal data into tools that call third-party services.

## 🧱 How it works

```
 Browser ── index.html (vanilla JS, no framework, no build)
    │
    ├── 🔒 browser-only tools (calculators, decoder, hash, JWT, IOC, watchlist)
    │
    └── /api/*  ──►  Cloudflare Worker  ──►  free public APIs
                      (src/index.js +        (DNS over HTTPS, RDAP, RIPEstat,
                       functions/api)         crt.sh, Shodan InternetDB, ...)
```

```
net-tools/
├── public/index.html            UI (all tools, one file)
├── src/index.js                 Worker entry: routes /api/* and serves the page
├── functions/api/[[path]].js    API handlers
├── wrangler.jsonc               Cloudflare config
└── README.md
```

## 🚀 Deploy your own (free)

You need a free [Cloudflare account](https://dash.cloudflare.com/sign-up) and a GitHub account.

**Option A: from GitHub (recommended)**
1. Fork or clone this repository.
2. In the Cloudflare dashboard: **Workers & Pages → Create → Import a repository**, pick your repo.
3. Leave the build command empty and keep the deploy command `npx wrangler deploy`.
4. Click **Deploy**. Every push to GitHub redeploys automatically.

**Option B: from your computer**
```bash
git clone https://github.com/YOUR-USERNAME/net-tools.git
cd net-tools
npx wrangler dev        # run locally at http://localhost:8787
npx wrangler deploy     # publish to Cloudflare
```

> Some tools (My IP, Cloudflare trace) show full data only on the deployed site, because they read Cloudflare's request data.

### Optional: VirusTotal hash lookups

Investigate can show VirusTotal results for file hashes. Add your free API key as a **secret** (never commit it to Git):

- Dashboard: **Workers & Pages → your Worker → Settings → Runtime → Variables and secrets** (the section called **Runtime variables and secrets**, on the **Production** tab) **→ Add variable** → type *Secret*, name `VT_API_KEY`. Do **not** use the separate *Build* section called "Variables and secrets": that one is only for build commands and the Worker cannot read it
- or CLI: `npx wrangler secret put VT_API_KEY`

Open `/api/health` on your site to check: it should show `virustotal_key_found: true`. Without the secret, everything else still works. Free VirusTotal limits: 4 requests/minute, 500/day.

### Optional: NVD API key

NVD works without a key (5 requests per 30 seconds, results cached 15 minutes). A free key from nvd.nist.gov raises the limit and adds medium and low counts to the dashboard. Add it as a **Secret** named `NVD_API_KEY`, the same way as `VT_API_KEY`.

## 🔌 API

All endpoints are `GET /api/<name>` and return JSON.

| Endpoint | Parameters | Purpose |
|---|---|---|
| `ip` | - | Your IP, location, ASN (from Cloudflare) |
| `ipinfo` | `q` (IP, optional) | IP type, risk flags and score |
| `dns` | `q`, `t` (`ALL` or one type), `r` (`cloudflare` or `google`) | DNS records |
| `prop` | `q`, `t` (A, AAAA, MX, NS, TXT, CNAME) | Multi-resolver propagation check |
| `dnssec` | `q` | DNSSEC status |
| `whois` | `q` (domain or IP) | RDAP data |
| `subs` | `q` (domain) | Sub-sites, IPs and MX records |
| `ssl` | `q` | Newest certificate in CT logs |
| `status` | `url` | Is the site up? |
| `headers` | `url` | Security header check |
| `ping` | `q` | Global ping |
| `mtr` | `q` | MTR route |
| `asn` | `q` (e.g. `AS13335`) | Announced prefixes |
| `bgp` | `q` (IP or prefix) | BGP visibility |
| `oui` | `q` (MAC) | MAC vendor |
| `intel` | `q`, `t` (`ip`, `domain`, `hash`) | Shodan InternetDB / urlscan.io / CIRCL |
| `vt` | `q` (hash) | VirusTotal file lookup (needs `VT_API_KEY`) |
| `mx` | `q` | MX lookup with IPs and reverse DNS |
| `mailhealth` | `q`, `sel` (DKIM selector, optional) | Full email health data |
| `dmarc` | `q` | DMARC record analysis |
| `cloud` | `p` (`m365`, `azure`, `aws`, `gcp`, `cloudflare`, `github`, `claude`) | Provider status |
| `nvd` | `k` (keyword, optional) | NVD dashboard or search |
| `vtx` | `q`, `t` (`domain`, `ip`, `hash`) | VirusTotal details (needs `VT_API_KEY`) |
| `hdrs` | `url` | Raw response headers and redirect chain |
| `health` | - | Shows whether optional features (VirusTotal key) are configured |
| `cve` | `q` | CVE details, EPSS, KEV |
| `mailsec` | `q`, `sel` (DKIM selector, optional) | SPF / DKIM / DMARC |

## ⚠️ Limits and known limitations

- Built on **free public APIs**. They have rate limits and can be slow or unavailable. Tools show the reason when a lookup fails.
- Cloudflare's free plan allows about **50 outgoing requests per call**, so Domain Map checks at most 30 hostnames.
- **SSL/TLS** shows the newest certificate from public logs, not necessarily the one a server is serving right now. Supported TLS versions cannot be probed from the free plan.
- **Claude Check** compares the IP's country with a copy of Anthropic's published supported-regions list. The list changes, so see the [official policy](https://www.anthropic.com/legal/supported-regions). The IP score is a simple estimate, not an official rating.
- **IP Score** is a heuristic based on public data, not a reputation guarantee.

## 🛡️ Responsible use

- Net Tools is **passive**: it reads public data. It does **not** scan ports or probe targets, and that is intentional.
- The status and header checkers block private and local addresses.
- Only investigate systems and data you are allowed to look into.
- If you make your instance public, add rate limiting (for example Cloudflare Rate Limiting rules) to protect free API quotas.

## 🗺️ Roadmap

- [ ] World map and services chart in Domain Map
- [ ] Chinese / English language switch
- [ ] VirusTotal lookups for IPs and domains
- [ ] Saved report history
- [ ] Rate limiting and caching layer
- [ ] More config generator templates (Juniper, FortiGate, iptables)

Have an idea? [Open an issue](../../issues).

## 🤝 Contributing

Contributions are welcome.

1. Fork the repo and create a branch.
2. Each tool is one entry in the `T` object in `public/index.html` (title, easy explanation, `run()` function). Server-side lookups go in `functions/api/[[path]].js`.
3. Keep tools simple, explain results in plain words, and add the data source to the `SRC` list.
4. Test with `npx wrangler dev`, then open a pull request.

Please do not add features that scan or attack third-party systems.

## 🙏 Acknowledgements

Inspired by [ip.net.coffee](https://ip.net.coffee/) and [DNSdumpster](https://dnsdumpster.com/). Powered by free public services: Cloudflare, ipapi.is, Shodan InternetDB, urlscan.io, CIRCL hashlookup, VirusTotal, RIPEstat, Globalping, crt.sh, RDAP, Have I Been Pwned, NVD, FIRST EPSS and macvendors.com. Excel export uses [SheetJS](https://sheetjs.com/).

## 📄 License

[MIT](LICENSE). This project is not affiliated with, or endorsed by, any of the services listed above, including Anthropic, Cloudflare and VirusTotal.
