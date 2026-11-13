# Net Tools (free, Cloudflare Workers)

Features: Domain map (subdomains + graph), IP score, global ping, split-tunnel test, My IP + geo/ASN, Cloudflare trace, DNS records (DoH), Whois/RDAP, service status, WebRTC leak test.

Layout:
- public/index.html            UI (static asset)
- src/index.js                 Worker entry, routes /api/* to the API
- functions/api/[[path]].js    API handlers (shared code)
- wrangler.jsonc               Worker + assets config

Run locally:  npx wrangler dev
Deploy:       npx wrangler deploy
(or push to GitHub; Cloudflare Workers Builds runs `npx wrangler deploy`)

Notes: the IP and trace tabs show full data only on the deployed site (they use Cloudflare request data).
For testing only: add rate limiting before sharing the URL publicly.
