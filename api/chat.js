const { createHmac, timingSafeEqual } = require("crypto");

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const JWT_SECRET = process.env.JWT_SECRET || "";

const BYTE_LIMIT = 64 * 1024;
const REQUEST_TIMEOUT_MS = 60 * 1000;

const BURST_LIMIT = { capacity: 6, windowMs: 30_000 };
const SUSTAINED_LIMIT = { capacity: 60, windowMs: 10 * 60_000 };

const TANORAMA_PROMPT = [
  "You are the virtual assistant for Tanorama Photo Booth Service, Ontario’s #1 open-air photo booth serving Kitchener, Waterloo, Cambridge, Stratford, Guelph, and surrounding areas.",
  "Use the following knowledge base to answer questions accurately and concisely:",
  "  • Weddings: Luxury, attendant-led open-air booths with pro cameras/printers, unlimited custom strips (2×6 or 4×6), online gallery, red-carpet experience, wedding packages from $897, upgrades such as elegant frames, phone-to-print, 360° booth; book at least one month ahead.",
  "  • Corporate: High-volume branded printing (720+ strips/hr) for 1,000+ guests, custom templates/logos/QR codes/CTAs, ROI analytics (prints, shares, sessions), battery-powered 10×10 ft footprint, turnkey setup/takedown, ideal for launches, trade shows, galas, etc.; quotes are custom via consultation.",
  "  • Differentiators: Professional attendants, premium gear, no power cords needed, luxury props/backdrops, 360° video option, instant mobile printing, responsive and reliable team, rave reviews from couples and corporate planners.",
  "  • Contact: Phone 365-994-5394, email corbin@tanorama.ca, contact form and Calendly on tanorama.ca/bookings.",
  "  • Service areas and reputation: Serving SW Ontario with luxury experiences for couples and measurable marketing for businesses.",
  "  • Site navigation: Home https://tanorama.ca/, Corporate https://tanorama.ca/corporate, Blog https://tanorama.ca/blog, Pricing & Booking https://tanorama.ca/bookings.",
  "Answer only with information relevant to Tanorama’s services, pricing, availability, booking process, or website. If a request is unrelated to Tanorama, politely decline and redirect the user to Tanorama topics.",
  "When referencing specific services or resources, include a Markdown link to the relevant approved Tanorama page (for example, https://tanorama.ca/corporate or https://tanorama.ca/bookings).",
  "When you mention or link to a Tanorama webpage, only use URLs from the navigation list above, https://tanorama.ca/ itself, or calendly.com scheduling links. Do not invent or guess other URLs.",
  "If someone asks for directions to a page or resource that isn’t in the approved list, tell them it’s not available and guide them to the closest matching page (often the main site or bookings page) instead.",
  "If a visual reference would help, you may add up to one Markdown image using the form ![Alt text](URL) and only the following approved image URLs:",
  "  • https://static.wixstatic.com/media/1e7670_4e0f777bee1441f482385670150ebba1~mv2.jpg/v1/fill/w_1122,h_1184,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/Wedding%20Photo%20Booth%20Print%201_edited_edite.jpg",
  "  • https://static.wixstatic.com/media/1e7670_bc13752c04a742658b013810594383d9~mv2.jpg/v1/fill/w_1122,h_1184,al_c,q_85,usm_0.66_1.00_0.01,enc_avif,quality_auto/Kristen%20and%20bridesmaids_edited_edited.jpg",
  "  • https://static.wixstatic.com/media/1e7670_032e4b6b5592476493a8d0b0744147ac%7Emv2.png/v1/fit/w_2500,h_1330,al_c/1e7670_032e4b6b5592476493a8d0b0744147ac%7Emv2.png",
  "Never provide or facilitate instructions for hacking, scamming, or any malicious activity. Refuse such requests politely and reiterate that the assistant only helps with legitimate Tanorama inquiries.",
  "If you cannot find the requested details in this knowledge, say you’re not sure and invite the user to contact Tanorama directly, providing the phone number, email, and link to the bookings/contact form.",
  "If someone asks who built or powers the chatbot, state that it was created by MacDonald AI.",
  "Keep responses warm, professional, and to-the-point.",
].join(" ");

const SITE_PROMPTS = {
  default: TANORAMA_PROMPT,
  tanorama: TANORAMA_PROMPT,
};

const rateState = new Map();

function parseAllowedOrigins() {
  const raw = process.env.ALLOW_ORIGINS || "";
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function normalizeOrigin(value) {
  if (typeof value !== "string" || !value) {
    return "";
  }
  const trimmed = value.trim().replace(/\/+$/, "");
  try {
    const url = new URL(trimmed);
    const port = url.port ? `:${url.port}` : "";
    return `${url.protocol}//${url.hostname}${port}`;
  } catch (_) {
    return trimmed.toLowerCase();
  }
}

function createWildcardRegex(pattern) {
  const escaped = pattern.replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`, "i");
}

function createOriginMatcher(pattern) {
  if (pattern === "*") {
    return () => true;
  }

  if (pattern.includes("*")) {
    const [schemeRaw, hostPatternWithPath] = pattern.split("://");
    const scheme = schemeRaw ? schemeRaw.toLowerCase() : "";
    const hostPattern = (hostPatternWithPath || "").replace(/\/+$/, "");
    if (!hostPattern) {
      const regex = createWildcardRegex(pattern.replace(/\/+$/, ""));
      return (origin) => Boolean(origin) && regex.test(origin);
    }

    const regex = createWildcardRegex(hostPattern);
    const expectedProtocol = scheme ? `${scheme}:` : "";

    return (origin) => {
      if (!origin) {
        return false;
      }
      try {
        const url = new URL(origin);
        if (expectedProtocol && url.protocol !== expectedProtocol) {
          return false;
        }
        return regex.test(url.host);
      } catch (_) {
        return false;
      }
    };
  }

  const normalized = normalizeOrigin(pattern);
  return (origin) => normalizeOrigin(origin) === normalized;
}

const allowedOrigins = parseAllowedOrigins();
const originMatchers = allowedOrigins.map((pattern) => createOriginMatcher(pattern));

function isOriginAllowed(origin) {
  if (!origin) return true;
  return originMatchers.some((matcher) => matcher(origin));
}

function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && isOriginAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Chat-Site");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Max-Age", "86400");
  res.setHeader("Vary", "Origin");
}

async function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("payload_too_large"));
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      try {
        const buffer = Buffer.concat(chunks);
        resolve(buffer.toString("utf8"));
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", (error) => reject(error));
  });
}

function base64UrlDecode(segment, asBuffer = false) {
  let normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4 !== 0) {
    normalized += "=";
  }
  const buffer = Buffer.from(normalized, "base64");
  return asBuffer ? buffer : buffer.toString("utf8");
}

function verifyJwt(token) {
  if (!JWT_SECRET) {
    return { valid: false, error: "Server misconfiguration: missing JWT secret." };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return { valid: false, error: "Invalid token format." };
  }
  const [encodedHeader, encodedPayload, signature] = parts;

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader));
    payload = JSON.parse(base64UrlDecode(encodedPayload));
  } catch (error) {
    return { valid: false, error: "Invalid token payload." };
  }

  if (header.alg !== "HS256" || header.typ !== "JWT") {
    return { valid: false, error: "Unsupported token algorithm." };
  }

  const expectedSigBuffer = createHmac("sha256", JWT_SECRET)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest();
  const providedSigBuffer = base64UrlDecode(signature, true);

  if (
    providedSigBuffer.length !== expectedSigBuffer.length ||
    !timingSafeEqual(providedSigBuffer, expectedSigBuffer)
  ) {
    return { valid: false, error: "Invalid token signature." };
  }

  if (typeof payload.exp === "number") {
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (payload.exp <= nowSeconds) {
      return { valid: false, error: "Token expired." };
    }
  }

  return { valid: true, payload };
}

function getClientKey(req, siteId) {
  const forwarded = req.headers["x-forwarded-for"];
  const ip = Array.isArray(forwarded)
    ? forwarded[0]
    : typeof forwarded === "string"
    ? forwarded.split(",")[0]
    : req.socket?.remoteAddress || "unknown";
  return `${ip.trim()}::${siteId}`;
}

function refillTokens(bucket, config, now) {
  const elapsed = now - bucket.lastRefill;
  if (elapsed <= 0) return bucket.tokens;
  const tokensToAdd = (elapsed / config.windowMs) * config.capacity;
  bucket.tokens = Math.min(config.capacity, bucket.tokens + tokensToAdd);
  bucket.lastRefill = now;
  return bucket.tokens;
}

function ensureBucket(map, key, config, now) {
  if (!map.has(key)) {
    map.set(key, { tokens: config.capacity, lastRefill: now });
  }
  return map.get(key);
}

function consumeTokens(key) {
  const now = Date.now();
  if (!rateState.has(key)) {
    rateState.set(key, {
      burst: { tokens: BURST_LIMIT.capacity, lastRefill: now },
      sustained: { tokens: SUSTAINED_LIMIT.capacity, lastRefill: now },
    });
  }
  const entry = rateState.get(key);
  refillTokens(entry.burst, BURST_LIMIT, now);
  refillTokens(entry.sustained, SUSTAINED_LIMIT, now);

  if (entry.burst.tokens < 1 || entry.sustained.tokens < 1) {
    const burstShortage = Math.max(0, 1 - entry.burst.tokens);
    const sustainedShortage = Math.max(0, 1 - entry.sustained.tokens);

    const burstWait =
      burstShortage > 0 ? (burstShortage / BURST_LIMIT.capacity) * BURST_LIMIT.windowMs : 0;
    const sustainedWait =
      sustainedShortage > 0
        ? (sustainedShortage / SUSTAINED_LIMIT.capacity) * SUSTAINED_LIMIT.windowMs
        : 0;

    const retryAfterMs = Math.max(burstWait, sustainedWait);
    return { allowed: false, retryAfter: Math.ceil(retryAfterMs / 1000) || 1 };
  }

  entry.burst.tokens -= 1;
  entry.sustained.tokens -= 1;
  return { allowed: true };
}

async function callOpenAI({ messages }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        temperature: 0.3,
        messages,
      }),
      signal: controller.signal,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error("openai_error");
      error.status = response.status;
      error.payload = payload;
      throw error;
    }

    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

function sendJson(res, status, data, extraHeaders = {}) {
  if (typeof res.status === "function") {
    res.status(status);
  } else {
    res.statusCode = status;
  }
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [key, value] of Object.entries(extraHeaders)) {
    res.setHeader(key, value);
  }
  res.end(JSON.stringify(data));
}

function validatePayload(body) {
  if (typeof body !== "object" || body === null) {
    return { error: "Invalid request body." };
  }

  if (typeof body.message !== "string" || !body.message.trim()) {
    return { error: "Message is required." };
  }

  const trimmedMessage = body.message.trim();
  if (trimmedMessage.length > 1500) {
    return { error: "Message too long." };
  }

  if (body.history) {
    if (!Array.isArray(body.history)) {
      return { error: "History must be an array." };
    }
    if (body.history.length > 10) {
      return { error: "History too long." };
    }
    for (const item of body.history) {
      if (
        !item ||
        typeof item !== "object" ||
        (item.role !== "user" && item.role !== "assistant") ||
        typeof item.content !== "string"
      ) {
        return { error: "Invalid history item." };
      }
      if (item.content.length > 1500) {
        return { error: "History message too long." };
      }
    }
  }

  if (body.sessionId && typeof body.sessionId !== "string") {
    return { error: "Invalid session identifier." };
  }

  return { ok: true, message: trimmedMessage };
}

module.exports = async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    res.status(405).end("Method Not Allowed");
    return;
  }

  const origin = req.headers.origin;
  if (origin && !isOriginAllowed(origin)) {
    sendJson(res, 403, { error: "This site isn’t authorized to use the chat." });
    return;
  }

  if (!OPENAI_API_KEY) {
    sendJson(res, 500, { error: "Something went wrong. Try again shortly.", details: "Missing OpenAI API key." });
    return;
  }

  let rawBody;
  try {
    rawBody = await readBody(req, BYTE_LIMIT);
  } catch (error) {
    if (error.message === "payload_too_large") {
      sendJson(res, 400, {
        error: "Please shorten your message and try again.",
        details: "Request payload exceeded 64 KB.",
      });
      return;
    }
    console.error("chat.read_body_error", { error: error.message });
    sendJson(res, 500, { error: "Something went wrong. Try again shortly." });
    return;
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (_) {
    sendJson(res, 400, {
      error: "Please shorten your message and try again.",
      details: "Invalid JSON payload.",
    });
    return;
  }

  const validation = validatePayload(payload);
  if (!validation.ok) {
    sendJson(res, 400, {
      error: "Please shorten your message and try again.",
      details: validation.error,
    });
    return;
  }

  const siteIdHeader = req.headers["x-chat-site"];
  const siteId =
    (typeof payload.siteId === "string" && payload.siteId.trim()) ||
    (typeof siteIdHeader === "string" && siteIdHeader.trim()) ||
    "default";

  const normalizedSiteId = siteId.toLowerCase();

  if (!Object.prototype.hasOwnProperty.call(SITE_PROMPTS, normalizedSiteId)) {
    sendJson(res, 403, { error: "This site isn’t authorized to use the chat." });
    return;
  }

  const authHeader = req.headers.authorization;
  if (authHeader) {
    const [scheme, token] = authHeader.split(" ");
    if (scheme !== "Bearer" || !token) {
      sendJson(res, 401, { error: "Your session expired. Refresh and try again." });
      return;
    }
    const verification = verifyJwt(token);
    if (!verification.valid) {
      const detail = verification.error || "Invalid token.";
      if (detail === "Token expired.") {
        sendJson(res, 401, { error: "Your session expired. Refresh and try again." });
        return;
      }
      if (detail.startsWith("Server misconfiguration")) {
        sendJson(res, 500, { error: "Something went wrong. Try again shortly.", details: detail });
        return;
      }
      sendJson(res, 401, { error: "Your session expired. Refresh and try again.", details: detail });
      return;
    }
  }

  const clientKey = getClientKey(req, normalizedSiteId);
  const rateCheck = consumeTokens(clientKey);
  if (!rateCheck.allowed) {
    sendJson(
      res,
      429,
      { error: "We’re getting a lot of messages. Try again in a moment.", retryAfter: rateCheck.retryAfter },
      { "Retry-After": String(rateCheck.retryAfter) }
    );
    return;
  }

  const historyMessages = Array.isArray(payload.history)
    ? payload.history
        .filter((item) => item && typeof item.content === "string" && (item.role === "user" || item.role === "assistant"))
        .map((item) => ({
          role: item.role,
          content: item.content.trim(),
        }))
        .slice(-10)
    : [];

  const systemPrompt = SITE_PROMPTS[normalizedSiteId] || SITE_PROMPTS.default;
  const messages = [
    { role: "system", content: systemPrompt },
    ...historyMessages,
    { role: "user", content: validation.message },
  ];

  const start = Date.now();
  try {
    const response = await callOpenAI({ messages });
    const reply = response.choices?.[0]?.message?.content?.trim() || "";
    const usage = response.usage
      ? {
          promptTokens: response.usage.prompt_tokens,
          completionTokens: response.usage.completion_tokens,
        }
      : undefined;

    console.log(
      JSON.stringify({
        event: "chat.completion",
        siteId: normalizedSiteId,
        durationMs: Date.now() - start,
        usage,
        timestamp: new Date().toISOString(),
      })
    );

    sendJson(res, 200, { reply, usage });
  } catch (error) {
    const duration = Date.now() - start;
    const status = error.status || 502;
    const errorDetails =
      error.payload && typeof error.payload === "object"
        ? {
            status,
            code: error.payload?.error?.code,
            type: error.payload?.error?.type,
          }
        : { status, message: error.message };

    console.error(
      JSON.stringify({
        event: "chat.error",
        siteId: normalizedSiteId,
        status,
        durationMs: duration,
        details: errorDetails,
        timestamp: new Date().toISOString(),
      })
    );

    if (status === 429) {
      sendJson(res, 429, {
        error: "We’re getting a lot of messages. Try again in a moment.",
        details: "OpenAI rate limited the request.",
      });
      return;
    }

    const mappedStatus = status >= 500 ? (status === 504 ? 504 : 502) : 500;
    sendJson(res, mappedStatus, {
      error: "Something went wrong. Try again shortly.",
      details: errorDetails,
    });
  }
};
