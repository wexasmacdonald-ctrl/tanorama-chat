## Overview
- **Stack**: Vercel serverless (`@vercel/node`) with static assets in `public/`.
- **Routes**:
  - `/chat` → branded chat widget served by `api/chat-page.js`.
  - `/api/chat` → OpenAI proxy with validation, CORS, JWT verification, and in-memory rate limiting.
  - `/api/health` → uptime probe.
- **Client behavior**: `/chat` renders a Tanorama-branded assistant that keeps session history in memory, posts to `/api/chat`, and never stores data in cookies or localStorage.

```
.
├── api
│   ├── chat.js          # POST proxy to OpenAI with rate limiting + auth + logging
│   ├── chat-page.js     # Serves the iframe widget with CSP headers
│   └── health.js        # GET health check
├── public
│   └── chat.html        # Static Tanorama chat widget UI
└── vercel.json          # Build + route configuration
```

## Deploying to Vercel
1. **Create project**: `vercel projects add tanorama-chat` (or via dashboard). Framework preset: `Other`.
2. **Import repo**: Connect GitHub or upload manually. Ensure `public/chat.html` is included.
3. **Configure builds**: Vercel picks up `vercel.json` automatically; no further setup needed.
4. **Set environment variables** (Settings → Environment Variables):
   - `OPENAI_API_KEY` – secret key for OpenAI.
   - `JWT_SECRET` – HS256 secret for short-lived tokens if you enable Authorization.
   - `ALLOW_ORIGINS` – comma-separated origins allowed to call `/api/chat` and embed `/chat`, e.g.  
     `https://your-project.vercel.app,https://tanorama.ca,https://www.tanorama.ca`
5. **Redeploy** to apply env vars.
6. **Verify health**: `curl https://<project>.vercel.app/api/health` → expect `{ "ok": true, "time": "<ISO>" }`.

## Headers, CORS, and CSP
- `/api/chat` responds only when `Origin` matches `ALLOW_ORIGINS`. The response includes:
  - `Access-Control-Allow-Origin: <matching origin>`  
  - `Access-Control-Allow-Headers: Content-Type, Authorization, X-Chat-Site`  
  - `Vary: Origin`
- `/chat` returns `Content-Security-Policy: frame-ancestors 'self' <ALLOW_ORIGINS...>` so the widget can be embedded in Wix and other allowed domains. Do **not** add `X-Frame-Options`.
- Body size is capped at 64 KB; larger payloads get a 400 with the friendly message.

## Testing Checklist
1. **Health check**: `curl` `/api/health`.
2. **Load widget**: Open `https://<project>.vercel.app/chat?siteId=tanorama&title=Tanorama%20Assistant&accent=%23e11d48&welcome=Hi!` in a desktop and mobile viewport.
3. **Send a message**: Confirm POST `/api/chat` succeeds and response includes `reply`.
4. **CORS headers**: Inspect the network tab for `/api/chat`; ensure `Access-Control-Allow-Origin` matches the page origin and `Vary: Origin` is present.
5. **Content-Security-Policy**: View response headers on `/chat`; confirm `frame-ancestors` lists your Vercel domain + client domains.
6. **Rate limiting**: Rapid-fire messages (>6 in 30 seconds or >60 in 10 minutes) should yield HTTP 429 with Retry-After and the message “We’re getting a lot of messages. Try again in a moment.”
7. **Error handling**: Trigger 400 (send >1,500 chars), 401 (use an expired/invalid JWT), and upstream failure (temporarily unset `OPENAI_API_KEY`) to confirm friendly messages.
8. **Logs**: Use Vercel logs to confirm entries contain timestamp, siteId, duration, and token usage—no PII is recorded.

## Wix Embedding
### Preferred: Wix Lightbox (iframe)
1. Create a Wix Lightbox.
2. Add an **HTML iframe** element with:
   ```html
   <iframe
     src="https://<project>.vercel.app/chat?siteId=tanorama&title=Tanorama%20Assistant&accent=%23e11d48&welcome=Hi!"
     style="width:100%;height:100%;border:0;border-radius:18px;"
     allow="clipboard-read; clipboard-write"
     title="Tanorama Assistant"
   ></iframe>
   ```
3. Configure the launcher button in Wix to open the Lightbox.
4. Exclude unwanted pages (Corporate Giveaway Form, Corporate Landing Page, Wedding Landing Page) via Wix page settings.

### Alternative: Wix Custom Code snippet
Add this under **Settings → Custom Code** (body end), adjusting the dimensions as needed:
```html
<div id="tanorama-chat-container" style="position:fixed;bottom:24px;right:24px;z-index:9999;">
  <iframe
    src="https://<project>.vercel.app/chat?siteId=tanorama&title=Tanorama%20Assistant&accent=%23e11d48"
    style="width:380px;height:520px;border:0;border-radius:18px;box-shadow:0 18px 44px rgba(225,29,72,0.24);"
    allow="clipboard-read; clipboard-write"
    title="Tanorama Assistant"
  ></iframe>
</div>
```

### Close actions
- The widget posts `window.parent.postMessage({ source: "macautomation-chat", type: "close", reason: "<string>" }, "*")`.
- Reasons: `"close-button"`, `"escape-key"`, `"user"` (generic). Handle this inside Wix to hide the Lightbox or remove the iframe.

## Token & Session Handling
- Pass optional Authorization header (`Bearer <JWT>`) from Wix if you issue short-lived tokens. Tokens are HS256-signed via `JWT_SECRET`.
- `siteId` is read from the query string or `X-Chat-Site` header. Missing/unknown IDs return HTTP 403.
- `sessionId` can be supplied by the embedder; otherwise the widget generates a UUID per load.
- No cookies or localStorage; the chat history lives in-memory inside the iframe and resets on reload.

## Adding a New Site Prompt
1. Open `api/chat.js`.
2. Extend the `SITE_PROMPTS` map with a new key:
   ```js
   const SITE_PROMPTS = {
     ...,
     "new-site-id": "You are the ...", // custom prompt
   };
   ```
3. Embed the widget with `?siteId=new-site-id&title=Your%20Title&accent=%23rrggbb`.
4. Optionally add the domain to `ALLOW_ORIGINS`.

## Post-Deployment Monitoring
- Enable Vercel Analytics or external uptime monitoring to poll `/api/health`.
- Review Vercel function logs periodically for rate-limit spikes or upstream failures.
- When rotating keys, update Vercel env vars and redeploy; the widget consumes new values immediately due to no caching.
