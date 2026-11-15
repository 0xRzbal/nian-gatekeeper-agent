"use strict";
/**
 * Local end-to-end harness for the Gatekeeper agent.
 * Boots the real HTTP server with a test secret, then exercises:
 *   health, preflight (signed/unsigned), a valid task, every trap variant,
 *   boundary conditions, proof reuse, idempotent redelivery, bad signatures,
 *   and the circuit's own enforcement (a wrong decision must be unprovable).
 * Every returned Groth16 proof is verified with snarkjs against
 * circuits/verification_key.json.
 *
 * Run: npm test
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const snarkjs = require("snarkjs");

process.env.AGENT_GAMES_HMAC_SECRET = "harness-test-secret";
process.env.SEEN_STORE_PATH = path.join(
  fs.mkdtempSync(path.join(os.tmpdir(), "gk-harness-")),
  "seen.json",
);

const { createAgentServer } = require("../src/local-server");
const { signBody, verifyBodySignature } = require("../src/hmac");
const { buildCircuitInputs, parseInput } = require("../src/decision");
const { Prover } = require("../src/prover");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR_A = "0xDe42aB1cDe42aB1cDe42aB1cDe42aB1cDe429f01";
const ADDR_B = "0x1234567890AbcdEF1234567890aBcdef12345678";

let base;
let passed = 0;
let failed = 0;

function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name} ${extra}`);
  }
}

async function post(obj, { sign = true, secret = SECRET } = {}) {
  const raw = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = signBody(secret, raw);
  const res = await fetch(`${base}/agent`, { method: "POST", headers, body: raw });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep null */ }
  return { status: res.status, text, json, sig: res.headers.get("x-agent-games-signature") };
}

function taskEnvelope(taskId, overrides = {}) {
  const input = {
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR_A,
    condition_recipient: ADDR_A,
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xtx_" + taskId,
    ...overrides,
  };
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "practice",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 60_000).toISOString(),
    input,
  };
}

async function expectDecision(name, envelope, decision, reason, { proofExpected = true } = {}) {
  const t0 = Date.now();
  const r = await post(envelope);
  const ms = Date.now() - t0;
  check(`${name}: HTTP 200`, r.status === 200, `got ${r.status} ${r.text.slice(0, 200)}`);
  check(`${name}: decision ${decision}`, r.json && r.json.decision === decision, JSON.stringify(r.json));
  check(`${name}: reason ${reason}`, r.json && r.json.reason_code === reason);
  check(`${name}: response signature valid`, verifyBodySignature(SECRET, r.text, r.sig));
  if (proofExpected) {
    check(`${name}: proof present`, !!(r.json && r.json.proof && r.json.public_signals));
    if (r.json && r.json.proof) {
      check(`${name}: 13 public signals`, r.json.public_signals.length === 13,
        `got ${r.json.public_signals.length}`);
      const vk = JSON.parse(fs.readFileSync(
        path.resolve(__dirname, "..", "circuits", "verification_key.json"), "utf8"));
      const ok = await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
      check(`${name}: proof verifies (${ms}ms)`, ok === true);
    }
  } else {
    check(`${name}: no proof attached`, r.json && !r.json.proof);
  }
  return r;
}

async function main() {
  const server = createAgentServer();
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  console.log(`harness server at ${base}`);

  // Health
  const health = await fetch(`${base}/agent`);
  const healthJson = await health.json();
  check("health: 200 + ok", health.status === 200 && healthJson.ok === true);

  // Preflight
  const pre = await post({
    type: "agent-games.preflight.v1",
    agent_id: "agt_harness",
    issued_at: new Date().toISOString(),
    nonce: "abc123",
  });
  check("preflight: 200 {ok,protocolVersion:v1}",
    pre.status === 200 && pre.json.ok === true && pre.json.protocolVersion === "v1");
  check("preflight: response signature valid", verifyBodySignature(SECRET, pre.text, pre.sig));

  const preUnsigned = await post({ type: "agent-games.preflight.v1" }, { sign: false });
  check("preflight unsigned: 401", preUnsigned.status === 401);

  // Valid + traps
  const validEnv = taskEnvelope("gk_h_valid");
  await expectDecision("valid", validEnv, "APPROVE", "VALID_CONDITION");

  // Idempotent redelivery of the exact same task -> cached APPROVE, not REUSED
  const again = await post(validEnv);
  check("redelivery: cached APPROVE", again.json && again.json.decision === "APPROVE"
    && again.json.reason_code === "VALID_CONDITION");

  await expectDecision("vk-substitution",
    taskEnvelope("gk_h_vk", { proof_vk: "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047" }),
    "REJECT", "VK_SUBSTITUTION");
  await expectDecision("threshold",
    taskEnvelope("gk_h_thr", { public_balance: "999" }),
    "REJECT", "THRESHOLD_MISMATCH");
  await expectDecision("expired (current == expiry)",
    taskEnvelope("gk_h_exp", { current_block: 8430000 }),
    "REJECT", "EXPIRED_CONDITION");
  await expectDecision("recipient",
    taskEnvelope("gk_h_rcp", { recipient: ADDR_B }),
    "REJECT", "RECIPIENT_MISMATCH");
  await expectDecision("amount-overflow",
    taskEnvelope("gk_h_amt", { amount: "1001" }),
    "REJECT", "AMOUNT_OVERFLOW");

  // Boundaries that must still APPROVE
  await expectDecision("boundary-valid",
    taskEnvelope("gk_h_bnd", { public_balance: "1000", amount: "1000", current_block: 8429999 }),
    "APPROVE", "VALID_CONDITION");

  // Proof reuse: new task_id, same proof_tx as the first valid task
  await expectDecision("proof-reused",
    taskEnvelope("gk_h_reuse", { proof_tx: "0xtx_gk_h_valid" }),
    "REJECT", "PROOF_REUSED", { proofExpected: false });

  // Bad signature
  const bad = await post(taskEnvelope("gk_h_bad"), { secret: "wrong-secret" });
  check("bad signature: 401", bad.status === 401);

  // Circuit enforcement: a wrong decision must be unprovable
  const trapEnv = taskEnvelope("gk_h_force", { recipient: ADDR_B });
  const parsed = parseInput(trapEnv.input);
  const prover = new Prover(path.resolve(__dirname, "..", "circuits"));
  let threw = false;
  try {
    const inputs = buildCircuitInputs(trapEnv, parsed, "APPROVE", 12345n);
    await prover.prove(inputs);
  } catch {
    threw = true;
  }
  check("circuit: APPROVE on trap input is unprovable", threw);

  server.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error("harness crashed:", err);
  process.exit(1);
});
