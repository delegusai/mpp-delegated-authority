// A stand-in for Delegus `POST /verify` that runs with no network: the reference engine (@delegus/core `verify`) over
// the state a conformance vector fixes (the issuer's DID document, the signed status list, the replay store, the clock
// and the test receipt key). The seller's own Action is what gets evaluated, exactly as /verify evaluates the Action
// the relying party submits. Replay state is kept per vector across calls, so a Proof used twice is refused.
// In production a seller uses `Delegus.verify` from @delegus/sdk against the hosted API instead.

import { verify, type Action, type MemoryService, type Receipt } from "@delegus/core";
import { evaluateInputFromVector, loadVectors, serviceFromState, testReceiptSigner, type VectorFile } from "@delegus/conformance";
import type { AuthorityVerifier } from "./authority.ts";

export interface VectorWorld {
  verifier: AuthorityVerifier;
  /** The vector whose Grant and Proof the agent presents. */
  vector(id: string): VectorFile;
  /** The verifier's receipt keys (kid → Ed25519 public key) and DID, for checking its signatures. */
  receiptKeys: Record<string, Uint8Array>;
  verifierDid: string;
  /** Make the verifier unreachable, to show the seller failing closed. */
  down: boolean;
  /**
   * The Principal revokes the Grant: from now on the verifier evaluates it against the signed status list of vector
   * `deny-authority-revoked` (same Grant, its bit set). Revocation is the verifier's state, not part of the request.
   */
  revoke(): void;
}

export function vectorWorld(ids: readonly string[]): VectorWorld {
  const files = new Map(
    loadVectors()
      .filter((f) => ids.includes(f.vector))
      .map((f) => [f.vector, f] as const),
  );
  for (const id of ids) if (!files.has(id)) throw new Error(`no conformance vector ${id}`);
  const services = new Map<string, MemoryService>();
  const revoked = new Set<string>();
  const first = files.get(ids[0]!)!.input;
  const world: VectorWorld = {
    down: false,
    revoke: () => void revoked.add("deny-authority-revoked"),
    receiptKeys: Object.fromEntries(Object.entries(first.service.receipt_keys).map(([kid, b64]) => [kid, new Uint8Array(Buffer.from(b64, "base64url"))])),
    verifierDid: first.service.did,
    vector: (id) => files.get(id)!,
    verifier: {
      async verify(req: { grant: string; proof: string; action: Action }): Promise<Receipt> {
        if (world.down) throw new TypeError("fetch failed");
        // The vector this Grant and Proof come from fixes the world they're evaluated in; after revoke(), the revoked one.
        const all = [...files.values()].filter((x) => x.input.grant === req.grant && x.input.proof === req.proof);
        const f = all.find((x) => revoked.has(x.vector)) ?? all.find((x) => x.vector !== "deny-authority-revoked");
        if (f === undefined) throw new Error("unknown grant: this stand-in only knows the conformance vectors");
        const nowMs = Date.parse(f.input.evaluated_at);
        let service = services.get(f.vector);
        if (service === undefined) services.set(f.vector, (service = serviceFromState(f.input, nowMs)));
        return verify({ ...evaluateInputFromVector(f.input, service), action: req.action as never }, testReceiptSigner(f.input));
      },
    },
  };
  return world;
}
