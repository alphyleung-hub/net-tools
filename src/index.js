// Cloudflare Workers entry: routes /api/* to the API handlers, everything else is served from public/
import { onRequestGet } from '../functions/api/[[path]].js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const route = url.pathname.split('/')[2];
      return onRequestGet({ request, params: { path: [route] } });
    }
    return env.ASSETS.fetch(request);
  },
};
