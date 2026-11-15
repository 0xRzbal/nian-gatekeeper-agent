"use strict";
const fs = require("fs");
const path = require("path");

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";
const SIGNATURE_HEADER = "x-agent-games-signature";

function defaultCircuitsDir() {
  const candidates = [
    path.resolve(__dirname, "..", "circuits"),
    path.resolve(process.cwd(), "circuits"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "gatekeeper.wasm"))) return c;
  }
  return candidates[0];
}

function defaultStorePath() {
  // Serverless filesystems are read-only except /tmp.
  if (process.env.VERCEL) return "/tmp/nian-gatekeeper-seen.json";
  return path.resolve(process.cwd(), "data", "seen.json");
}

function loadConfig(env = process.env) {
  return {
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET ?? "",
    circuitsDir: env.CIRCUITS_DIR ?? defaultCircuitsDir(),
    seenStorePath: env.SEEN_STORE_PATH ?? defaultStorePath(),
    port: Number(env.PORT ?? 8787),
  };
}

module.exports = {
  TASK_TYPE,
  PREFLIGHT_TYPE,
  PROTOCOL_VERSION,
  SIGNATURE_HEADER,
  loadConfig,
};
