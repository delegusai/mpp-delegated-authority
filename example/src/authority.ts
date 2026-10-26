// The delegated authority extension (docs/mpp/draft-payment-delegated-authority-00.md), seller side: the `authority`
// challenge parameter, the Action built from the seller's own record of the challenge, the Proof's binding to this
// request, the decision from the verifier, and the 403/503 Problem Details. Everything that isn't a verified ALLOW for
// this Grant, this Proof and this Action stops the request before any payment step.

import { canonicalize, normalizeHtu, sha256Utf8, verifyReceiptSignature, type Action, type Receipt } from "@delegus/core";
import { jcsB64u, type Problem } from "./mpp.ts";

export const PROFILE = "delegus-v0.2";

/**
 * A Structured Field Dictionary (RFC 9651) whose members are all sf-strings, as `Payment-Authority` and
 * `Payment-Authority-Receipt` are. Null when it doesn't parse, or when a key repeats (which is also how a field sent
 * twice shows up once the values are combined): the extension treats both as malformed.
 */
export function parseDictionary(value: string): Map<string, string> | null {
  const out = new Map<string, string>();
  let i = 0;
  const ws = () => {
    while (value[i] === " " || value[i] === "\t") i++;
  };
  ws();
  while (i < value.length) {
    const key = /^[a-z*][a-z0-9_.*-]*/.exec(value.slice(i))?.[0];
    if (key === undefined || value[i + key.length] !== "=" || value[i + key.length + 1] !== '"') return null;
    i += key.length + 2;
    let str = "";
    for (;;) {
      const ch = value[i++];
      if (ch === undefined) return null;
      if (ch === '"') break;
      if (ch === "\\") {
        const next = value[i++];
        if (next !== '"' && next !== "\\") return null;
        str += next;
      } else if (ch < " " || ch > "~") return null;
      else str += ch;
    }
    if (out.has(key)) return null;
    out.set(key, str);
    ws();
    if (i === value.length) break;
    if (value[i++] !== ",") return null;
    ws();
    if (i === value.length) return null;
  }
  return out;
}

/** A Dictionary of sf-strings, serialized. */
export const serializeDictionary = (members: Record<string, string>): string =>
  Object.entries(members)
    .map(([k, v]) => `${k}="${v.replace(/[\\"]/g, (c) => `\\${c}`)}"`)
    .join(", ");
export const PROBLEMS = "https://delegus.ai/problems";

export interface AuthorityParam {
  profiles: string[];
  required: boolean;
  /** The seller's relying-party DID: the Proof's `aud`. */
  server: string;
  action: Action;
}
export const authorityParam = (a: AuthorityParam): string => jcsB64u(a as never);

/** A charge request ({amount, currency, externalId}) as a v0.2 Action; null when v0.2 can't express it. */
export function actionOf(request: { amount: string; currency: string; externalId?: string }, resource: string): Action | null {
  if (!/^(0|[1-9][0-9]*)$/.test(request.amount)) return null;
  const amount = Number(request.amount);
  if (!Number.isSafeInteger(amount)) return null;
  // ISO 4217 codes only: the v0.2 vocabulary has no other currencies.
  if (!/^[a-zA-Z]{3}$/.test(request.currency)) return null;
  return { type: "commerce:purchase", resource: request.externalId ?? resource, amount, currency: request.currency.toUpperCase() };
}

/** The one call a seller makes. In production: POST /verify (`Delegus.verify` from @delegus/sdk). */
export interface AuthorityVerifier {
  verify(req: { grant: string; proof: string; action: Action }): Promise<Receipt>;
}

export type Decision = { kind: "allow"; receipt: Receipt; receiptHash: string } | { kind: "refuse"; status: 403 | 503; problem: Problem; retryAfter?: number };

const refuse = (status: 403 | 503, slug: string, title: string, detail: string, reason: string | null, receipt: string | null): Decision => ({
  kind: "refuse",
  status,
  problem: { type: `${PROBLEMS}/${slug}`, title, status, detail, payment: "not_attempted", profile: PROFILE, reason, receipt },
  ...(status === 503 ? { retryAfter: 5 } : {}),
});

function claims(jws: string): Record<string, unknown> | null {
  const part = jws.split(".")[1];
  if (part === undefined) return null;
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * Steps 2 to 6 of the extension's server processing: authority present, the Proof bound to this request, then the
 * verifier's decision (signature checked against the verifier's receipt keys). Called only after the core credential
 * checks passed, and before any payment verification or settlement.
 */
export async function decide(o: {
  headers: Headers;
  method: string;
  /** The URI the client targeted, as the seller publishes it (not an internal one). */
  publicUrl: string;
  action: Action;
  verifier: AuthorityVerifier;
  receiptKeys: Record<string, Uint8Array>;
  verifierDid: string;
  timeoutMs?: number;
}): Promise<Decision> {
  const field = o.headers.get("payment-authority");
  if (field === null) return refuse(403, "authority-required", "Delegated authority required", "This purchase needs a Payment-Authority field with a grant and a proof.", null, null);
  const a = parseDictionary(field);
  const grant = a?.get("grant");
  const proof = a?.get("proof");
  if (a === null || a.get("profile") !== PROFILE || grant === undefined || proof === undefined || grant === "" || proof === "")
    return refuse(403, "authority-malformed", "Delegated authority malformed", `Payment-Authority must be a dictionary with profile="${PROFILE}", grant and proof.`, null, null);

  // The verifier never sees the request, so the method and target URI are checked here.
  const c = claims(proof);
  if (c === null || c["htm"] !== o.method.toUpperCase() || typeof c["htu"] !== "string" || normalizeHtu(c["htu"]) !== normalizeHtu(o.publicUrl))
    return refuse(403, "proof-binding-mismatch", "Proof not bound to this request", "The proof was signed for a different method or address.", null, null);

  let receipt: Receipt;
  try {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error("timeout")), o.timeoutMs ?? 2500)));
    try {
      receipt = await Promise.race([o.verifier.verify({ grant, proof, action: o.action }), timeout]);
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return refuse(503, "authority-unavailable", "Authority could not be checked", "The authority verifier did not answer. Nothing was charged; try again shortly.", null, null);
  }
  // Only a decision signed by the verifier counts, and only for this Action.
  if (typeof receipt?.receipt !== "string" || !verifyReceiptSignature(receipt.receipt, o.receiptKeys, o.verifierDid).ok)
    return refuse(503, "authority-unavailable", "Authority could not be checked", "The verifier's answer is not a signed decision. Nothing was charged.", null, null);
  if (receipt.request_hash !== sha256Utf8(canonicalize(o.action as never)) && receipt.decision === "ALLOW")
    return refuse(503, "authority-unavailable", "Authority could not be checked", "The decision is for a different purchase. Nothing was charged.", null, null);
  if (receipt.decision === "DENY" && receipt.reason === "SERVICE_UNAVAILABLE")
    return refuse(503, "authority-unavailable", "Authority could not be checked", "The verifier could not decide right now. Nothing was charged.", receipt.reason, receipt.receipt);
  if (receipt.decision !== "ALLOW")
    return refuse(403, "authority-denied", "Delegated authority denied", `The grant does not allow this purchase (${receipt.reason}).`, receipt.reason, receipt.receipt);
  return { kind: "allow", receipt, receiptHash: sha256Utf8(receipt.receipt) };
}
