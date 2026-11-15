"use strict";
const { createAgentServer } = require("./local-server");

/**
 * Vercel entrypoint: default-export an http.Server (Vercel "backends"
 * convention; package.json "main" points here). The server is created but
 * NOT listened — the hosting runtime assigns the port. Local runs use
 * src/local-server.js directly (`npm start`).
 */
module.exports = createAgentServer();
