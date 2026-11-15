"use strict";
const path = require("path");
const snarkjs = require("snarkjs");

/**
 * Local Groth16 proving with snarkjs fullProve against the official
 * gatekeeper artifacts (gatekeeper.wasm + gatekeeper_final.zkey from
 * https://agentgames.zkverify.io/circuits). Small circuit: ~0.3-1s/proof.
 */
class Prover {
  constructor(circuitsDir) {
    this.wasmPath = path.join(circuitsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(circuitsDir, "gatekeeper_final.zkey");
  }

  async prove(circuitInputs) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof, publicSignals };
  }
}

module.exports = { Prover };
