# nian — Proof Gatekeeper Agent

An HTTPS agent endpoint for the **Proof Gatekeeper** event in the zkVerify
**Agent Games** (Season 01), competing as **@nian**.

The platform POSTs signed task envelopes describing proof-backed payment
requests. This service verifies the HMAC signature, decides APPROVE or REJECT
with deterministic rules, generates a real Groth16 proof of the decision
locally with snarkjs against the official gatekeeper circuit, and returns a
signed response — typically in well under a second, far inside the
60-second hard deadline.

## Decision policy (deterministic, fail-closed)

APPROVE only when **every** check passes — the gatekeeper circuit enforces
exactly the same conjunction, so a wrong decision cannot even be proven:

| Check | Trap rejected |
| --- | --- |
| `proof_vk == registered_vk` | `VK_SUBSTITUTION` |
| `proof_tx` not seen before | `PROOF_REUSED` (answered without a proof, per the event rules) |
| `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| `current_block < expiry_block` | `EXPIRED_CONDITION` |
| `recipient == condition_recipient` | `RECIPIENT_MISMATCH` |
| `amount <= max_transfer` | `AMOUNT_OVERFLOW` |

All checks pass → `APPROVE` / `VALID_CONDITION`. Malformed envelopes,
signature failures, internal errors and proving failures all fail closed
to REJECT — never to an unproven APPROVE. Redelivered tasks are answered
from an idempotency cache so a retry is never misread as proof reuse.

## Protocol

- **Intake**: `POST /agent` with header `x-agent-games-signature`
  (HMAC-SHA256 over the raw body, verified *before* JSON parsing).
- **Preflight**: `agent-games.preflight.v1` → signed
  `{ ok: true, protocolVersion: "v1" }`.
- **Task**: `agent-games.proof-gatekeeper.v1` → signed
  `{ decision, reason_code, proof, public_signals, proof_tx }`
  (`proof`/`public_signals` omitted only for `PROOF_REUSED`).
- **Health**: `GET /agent` → `{ ok: true, protocolVersion: "v1" }`.

### The circuit

`circuits/gatekeeper.wasm` + `circuits/gatekeeper_final.zkey` are the official
artifacts published at <https://agentgames.zkverify.io/circuits>
(vk_hash `0x6b79c6…d77b0`, also served from `/api/circuit-info`); they are
platform binaries and are not committed here — download them into
`circuits/` to run. `circuits/verification_key.json` (extracted from the
proving key) *is* included so anyone can re-verify proofs locally.

The circuit takes 13 inputs — `taskId, registeredVkHash, proofVkHash,
minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, decision, salt` (private) — and its
public signals are `[commitment, registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, taskId]` where
`commitment = Poseidon(taskId, salt)`. The per-task salt is derived
deterministically as `HMAC(secret, "gatekeeper-salt:" + task_id) mod p`, so a
redelivered task reproduces the identical proof inputs.

## Layout

| Path | Purpose |
| --- | --- |
| `src/server.js` | Hosting entrypoint (default-exports the HTTP server) |
| `src/local-server.js` | Plain Node HTTP server (`npm start`) |
| `src/handler.js` | Framework-agnostic request pipeline |
| `src/hmac.js` | HMAC sign/verify + per-task salt derivation |
| `src/decision.js` | Deterministic policy + envelope→circuit conversion |
| `src/prover.js` | snarkjs `groth16.fullProve` wrapper |
| `src/store.js` | proof_tx seen-set + response cache (JSON-file backed) |
| `src/config.js` | Environment-based configuration |
| `test/harness.js` | End-to-end harness: every trap variant, boundaries, preflight, proof verification |

## Run locally

```bash
npm install
curl -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
AGENT_GAMES_HMAC_SECRET=<your-rotated-secret> npm start   # listens on :8787
npm test                                                  # full harness (61 checks)
```

## Configuration

| Env | Meaning |
| --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | Platform-generated agent secret (dashboard → agent → Rotate Secret). Required. |
| `CIRCUITS_DIR` | Where the circuit artifacts live (default `./circuits`) |
| `SEEN_STORE_PATH` | Seen-set persistence file (default `./data/seen.json`, `/tmp` on Vercel) |
| `PORT` | Local listen port (default `8787`) |

No secret is ever committed; `.env` is git-ignored.
