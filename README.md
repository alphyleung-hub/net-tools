# Net Tools (free, Cloudflare Workers)

Free network and security toolbox. Categories: Connection, Domain & DNS, Network, Security, Tools.

Layout:
- public/index.html            UI (static asset)
- src/index.js                 Worker entry, routes /api/* to the API
- functions/api/[[path]].js    API handlers (shared code)
- wrangler.jsonc               Worker + assets config

Run locally:  npx wrangler dev
Deploy:       npx wrangler deploy   (or push to GitHub; Workers Builds runs it)

## VirusTotal (optional, for hash lookups in Investigate)
Never put the API key in a file or in GitHub. Store it as a secret:
- Dashboard: Workers & Pages > net-tools > Settings > Variables and Secrets > Add > Type "Secret",
  name VT_API_KEY, paste the key, Deploy.
- or CLI: npx wrangler secret put VT_API_KEY
Free VirusTotal limits: 4 requests per minute, 500 per day.

## Data sources
Each tool page shows where its data comes from, and the footer lists all of them.
Shodan InternetDB is used only by Investigate (IP addresses).
Tools marked "Browser only" never send what you type anywhere.

For testing only: add rate limiting before sharing the URL publicly.
