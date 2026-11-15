"use strict";
const { signBody, verifyBodySignature, deriveSalt } = require("./hmac");
const { parseInput, evaluate, buildCircuitInputs } = require("./decision");
const { Prover } = require("./prover");
const { TASK_TYPE, PREFLIGHT_TYPE, PROTOCOL_VERSION } = require("./config");

/**
 * Framework-agnostic Agent Games request pipeline (per /build):
 *   1. Verify HMAC over the RAW body vs x-agent-games-signature BEFORE parsing.
 *   2. Preflight (agent-games.preflight.v1) -> signed { ok, protocolVersion }.
 *   3. Gatekeeper task -> deterministic evaluation, local Groth16 proof
 *      (skipped only for PROOF_REUSED), signed response.
 * Fail closed everywhere: errors and uncertainty resolve to REJECT,
 * never to an unproven APPROVE.
 */
class AgentHandler {
  constructor(cfg, store) {
    this.cfg = cfg;
    this.store = store;
    this.prover = new Prover(cfg.circuitsDir);
  }

  health() {
    return {
      status: 200,
      body: JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION }),
      signature: null,
    };
  }

  async handlePost(rawBody, signatureHeader) {
    if (!this.cfg.hmacSecret) {
      return {
        status: 500,
        body: JSON.stringify({
          error: "server_misconfigured",
          detail: "AGENT_GAMES_HMAC_SECRET not set",
        }),
        signature: null,
      };
    }

    // 1. Authenticate the raw body BEFORE parsing.
    if (!verifyBodySignature(this.cfg.hmacSecret, rawBody, signatureHeader)) {
      return {
        status: 401,
        body: JSON.stringify({ error: "invalid_signature" }),
        signature: null,
      };
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return this.signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 2. Preflight handshake.
    if (envelope && envelope.type === PREFLIGHT_TYPE) {
      return this.signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    }

    if (!envelope || envelope.type !== TASK_TYPE) {
      return this.signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 3. Task.
    try {
      return await this.handleTask(envelope);
    } catch (err) {
      console.error("[agent] task handling error:", err.message);
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
  }

  async handleTask(task) {
    // Idempotent redelivery: answer from cache, never re-evaluate
    // (a redelivery must not be mistaken for proof reuse).
    if (task.task_id) {
      const cached = this.store.getResponse(task.task_id);
      if (cached) return this.signedRaw(200, cached);
    }

    // Deadline sanity: only a clearly-past deadline fails the task.
    const now = Date.now();
    const deadlineMs = parseTimestamp(task.deadline_at);
    if (deadlineMs !== null && now > deadlineMs) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const parsed = parseInput(task.input);
    if (!parsed || !task.task_id) {
      return this.signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const evaluation = evaluate(parsed, (tx) => this.store.hasProofTx(tx));
    const response = {
      decision: evaluation.decision,
      reason_code: evaluation.reason_code,
    };

    if (evaluation.provable) {
      const salt = deriveSalt(this.cfg.hmacSecret, task.task_id);
      const circuitInputs = buildCircuitInputs(task, parsed, evaluation.decision, salt);
      try {
        const { proof, publicSignals } = await this.prover.prove(circuitInputs);
        response.proof = proof;
        response.public_signals = publicSignals;
        // No Kurier key configured: the locally generated proof +
        // public_signals are the response evidence (proof_tx echoes the
        // task's proof reference as the on-chain audit pointer).
        response.proof_tx = parsed.proofTx;
      } catch (err) {
        // Proving failed -> fail closed. An APPROVE without a valid proof is
        // the worst outcome; downgrade to REJECT with no proof attached.
        console.error("[agent] proof generation failed:", err.message);
        return this.signed(200, {
          decision: "REJECT",
          reason_code:
            evaluation.decision === "APPROVE" ? "INVALID_TASK" : evaluation.reason_code,
          proof_tx: parsed.proofTx,
        });
      }
    } else {
      // PROOF_REUSED: documented as having no proof to submit.
      response.proof_tx = parsed.proofTx;
    }

    const result = this.signed(200, response);
    // Record only after successful evaluation, so a task never flags itself.
    this.store.recordProofTx(parsed.proofTx);
    this.store.recordResponse(task.task_id, result.body);
    return result;
  }

  signed(status, obj) {
    return this.signedRaw(status, JSON.stringify(obj));
  }

  signedRaw(status, body) {
    return { status, body, signature: signBody(this.cfg.hmacSecret, body) };
  }
}

/** Tolerant timestamp parse: ISO string, epoch seconds, or epoch ms. */
function parseTimestamp(v) {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v < 1e12 ? v * 1000 : v;
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^[0-9]+$/.test(s)) {
      const asNum = Number(s);
      return asNum < 1e12 ? asNum * 1000 : asNum;
    }
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

module.exports = { AgentHandler, parseTimestamp };
