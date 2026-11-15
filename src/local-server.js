"use strict";
const http = require("http");
const { loadConfig, SIGNATURE_HEADER } = require("./config");
const { AgentHandler } = require("./handler");
const { SeenStore } = require("./store");

/**
 * Plain Node HTTP server wrapping the AgentHandler.
 * - GET  any path -> health { ok: true, protocolVersion: "v1" }
 * - POST any path -> signed task pipeline (the platform posts to the exact
 *   registered URL; we register the /agent path and accept any path so a
 *   routing mismatch can never 404 a task)
 */
function createAgentServer(cfg = loadConfig()) {
  const handler = new AgentHandler(cfg, new SeenStore(cfg.seenStorePath));
  const server = http.createServer((req, res) => {
    if (req.method === "GET") {
      const r = handler.health();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(r.body);
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "method_not_allowed" }));
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const raw = Buffer.concat(chunks);
      try {
        const r = await handler.handlePost(raw, req.headers[SIGNATURE_HEADER]);
        const headers = { "content-type": "application/json" };
        if (r.signature) headers[SIGNATURE_HEADER] = r.signature;
        res.writeHead(r.status, headers);
        res.end(r.body);
      } catch (err) {
        console.error("[server] unhandled error:", err.message);
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal" }));
      }
    });
    req.on("error", () => {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "bad_request" }));
    });
  });
  return server;
}

if (require.main === module) {
  const cfg = loadConfig();
  const server = createAgentServer(cfg);
  server.listen(cfg.port, () => {
    console.log(`[agent] listening on :${cfg.port} (secret ${cfg.hmacSecret ? "set" : "NOT SET"})`);
  });
}

module.exports = { createAgentServer };
