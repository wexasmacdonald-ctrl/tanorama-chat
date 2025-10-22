const fs = require("fs");
const path = require("path");

const CHAT_TEMPLATE_PATH = path.join(__dirname, "..", "public", "chat.html");
const chatTemplate = fs.readFileSync(CHAT_TEMPLATE_PATH, "utf8");

function parseAllowedOrigins() {
  const raw = process.env.ALLOW_ORIGINS || "";
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildFrameAncestors() {
  const origins = parseAllowedOrigins();
  const unique = new Set(["'self'"]);
  for (const origin of origins) {
    unique.add(origin);
  }
  return Array.from(unique).join(" ");
}

module.exports = (req, res) => {
  const method = req.method || "GET";
  if (method !== "GET" && method !== "HEAD") {
    res.setHeader("Allow", "GET, HEAD");
    res.status(405).end("Method Not Allowed");
    return;
  }

  try {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.setHeader("Vary", "Origin");
    res.setHeader("Content-Security-Policy", `frame-ancestors ${buildFrameAncestors()};`);
    if (method === "HEAD") {
      res.status(200).end();
      return;
    }
    res.status(200).send(chatTemplate);
  } catch (error) {
    console.error("chat-page.error", { error: error.message });
    res.status(500).json({ error: "Unable to load chat widget." });
  }
};
