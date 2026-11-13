# Net Tools (free, Cloudflare Pages)

Features: My IP + geo/ASN, Cloudflare trace, DNS records (DoH), Whois/RDAP, service status, WebRTC leak test.

Layout: `public/index.html` (UI) and `functions/api/[[path]].js` (API).

Run locally:  npx wrangler pages dev public
Deploy:       npx wrangler pages deploy public
Or push to GitHub and connect the repo in Cloudflare Pages (build command: none, output directory: public).

Notes: the IP and trace tabs show full data only on the deployed site (they use Cloudflare's request data).
For testing only: add rate limiting before sharing the URL publicly.
