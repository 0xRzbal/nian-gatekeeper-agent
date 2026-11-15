"use strict";
const fs = require("fs");
const path = require("path");

/**
 * Seen-set for proof_tx references (PROOF_REUSED trap) plus a
 * task_id -> serialized-response cache so platform redeliveries are answered
 * idempotently instead of being misread as proof reuse.
 * In-memory state is authoritative for the process; a JSON file backs it
 * across restarts (best effort — on serverless it lives in /tmp).
 */
function normalizeTx(tx) {
  return (tx ?? "").toString().trim().toLowerCase();
}

class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    this.load();
  }

  load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      for (const tx of data.proofTx ?? []) this.seenProofTx.add(normalizeTx(tx));
      for (const [k, v] of Object.entries(data.responses ?? {})) {
        this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing/corrupt -> start empty */
    }
  }

  persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofTx],
          responses: Object.fromEntries(this.responseByTaskId),
        }),
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("[store] persist failed:", err.message);
    }
  }

  hasProofTx(proofTx) {
    return this.seenProofTx.has(normalizeTx(proofTx));
  }

  recordProofTx(proofTx) {
    const key = normalizeTx(proofTx);
    if (!key || this.seenProofTx.has(key)) return;
    this.seenProofTx.add(key);
    this.persist();
  }

  getResponse(taskId) {
    return this.responseByTaskId.get(taskId) ?? null;
  }

  recordResponse(taskId, serializedResponse) {
    if (this.responseByTaskId.has(taskId)) return;
    this.responseByTaskId.set(taskId, serializedResponse);
    this.persist();
  }

  get size() {
    return this.seenProofTx.size;
  }
}

module.exports = { SeenStore, normalizeTx };
