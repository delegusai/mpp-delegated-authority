// A seller that takes MPP payments for orders and checks the buyer's delegated authority first. It answers fetch-style
// Requests, so the example and the tests run it with no port. The order of steps is the extension's (§ Server
// Processing): core credential checks with no side effects, then authority, then payment verification and settlement.
// A denied or unchecked request is never charged.

import { authorityParam, actionOf, decide, PROFILE, serializeDictionary, type AuthorityVerifier } from "./authority.ts";
import { challengeHeader, challengeId, echo, jcsB64u, parseCredential, receiptValue, unb64u, type Challenge, type Problem } from "./mpp.ts";

export interface SellerOptions {
  /** The seller's public origin: what agents target and what `htu` names. */
  origin: string;
  realm: string;
  /** The seller's relying-party DID. */
  rpDid: string;
  secret: string;
  verifier: AuthorityVerifier;
  receiptKeys: Record<string, Uint8Array>;
  verifierDid: string;
  /** Whether a paid request without authority is refused. */
  requireAuthority: boolean;
  now(): Date;
  catalog: Record<string, { amount: string; currency: string }>;
}

export interface Seller {
  handle(req: Request): Promise<Response>;
  /** Settled payments, by payment reference. A denied request never adds one. */
  settled: Map<string, { order: string; amount: string; currency: string; authority: string }>;
  /** One-time payment tokens issued with challenges and not yet spent (the stand-in payment method). */
  unspent: Set<string>;
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": status >= 400 ? "application/problem+json" : "application/json", "cache-control": "no-store", ...headers } });
const problem = (status: number, p: Problem, headers: Record<string, string> = {}): Response => json(status, p, headers);
const core = (status: 400 | 402, slug: string, title: string, detail: string): Problem => ({ type: `https://paymentauth.org/problems/${slug}`, title, status, detail });

export function seller(o: SellerOptions): Seller {
  const settled: Seller["settled"] = new Map();
  const unspent = new Set<string>();
  /** What the seller issued, by challenge id: its own record, never read back from the client. */
  const issued = new Map<string, { challenge: Challenge; order: string }>();

  function challengeFor(order: string): Challenge | null {
    const item = o.catalog[order];
    if (item === undefined) return null;
    const request = { amount: item.amount, currency: item.currency, externalId: order };
    const action = actionOf(request, order);
    const expires = new Date(o.now().getTime() + 5 * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const base = { realm: o.realm, method: "example", intent: "charge", request: jcsB64u(request), expires, header: "Payment-Authorization" as const };
    const c: Challenge = { id: challengeId(o.secret, base), ...base };
    // The extension is offered only where v0.2 can express the purchase (ISO 4217, integer minor units).
    if (action !== null) c.extra = { authority: authorityParam({ profiles: [PROFILE], required: o.requireAuthority, server: o.rpDid, action }) };
    // The stand-in payment method: paying this challenge means presenting its one-time token.
    unspent.add(`paytok_${c.id}`);
    issued.set(c.id, { challenge: c, order });
    return c;
  }

  async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    if (req.method !== "POST" || url.pathname !== "/orders") return json(404, { type: "about:blank", title: "Not found", status: 404, detail: "" });
    const body = (await req.json().catch(() => null)) as { order?: unknown } | null;
    const order = typeof body?.order === "string" ? body.order : "";
    if (o.catalog[order] === undefined) return problem(400, core(400, "bad-request", "Unknown order", "There's no order like that."));

    const fresh = (p: Problem): Response => {
      const c = challengeFor(order)!;
      return problem(402, p, { "www-authenticate": challengeHeader(c) });
    };
    const value = req.headers.get("payment-authorization");
    // (1) No credential: the challenge, with the authority parameter.
    if (value === null) return fresh(core(402, "payment-required", "Payment Required", `Order ${order} needs payment.`));

    // (1) Core credential checks, no side effects: decoding, binding, expiry. Failures are the core's 402s.
    const cred = parseCredential(value);
    if (cred === null) return fresh(core(402, "malformed-credential", "Malformed credential", "The credential isn't valid base64url JSON."));
    const mine = issued.get(cred.challenge.id);
    if (
      mine === undefined ||
      mine.order !== order ||
      challengeId(o.secret, echo(cred.challenge)) !== cred.challenge.id ||
      JSON.stringify(echo(mine.challenge)) !== JSON.stringify(echo(cred.challenge))
    )
      return fresh(core(402, "invalid-challenge", "Invalid challenge", "That challenge isn't one we issued for this order, or was changed."));
    if (Date.parse(mine.challenge.expires!) <= o.now().getTime()) return fresh(core(402, "payment-expired", "Challenge expired", "The challenge expired."));

    // (2–6) Delegated authority, before any payment step. The Action comes from our record of the challenge.
    const request = JSON.parse(unb64u(mine.challenge.request)) as { amount: string; currency: string; externalId?: string };
    const action = actionOf(request, order);
    let authority: { receipt_id: string; receipt_hash: string; jws: string } | null = null;
    const offered = mine.challenge.extra?.["authority"] !== undefined;
    const presented = req.headers.has("payment-authority");
    if (offered && (o.requireAuthority || presented)) {
      const d = await decide({
        headers: req.headers,
        method: req.method,
        publicUrl: `${o.origin}${url.pathname}`,
        action: action!,
        verifier: o.verifier,
        receiptKeys: o.receiptKeys,
        verifierDid: o.verifierDid,
      });
      if (d.kind === "refuse") return problem(d.status, d.problem, d.retryAfter !== undefined ? { "retry-after": String(d.retryAfter) } : {});
      authority = { receipt_id: d.receipt.receipt_id, receipt_hash: d.receiptHash, jws: d.receipt.receipt };
    }

    // (7) Payment verification and settlement, only now. The stand-in method spends its one-time token.
    const token = typeof cred.payload["token"] === "string" ? cred.payload["token"] : "";
    if (token !== `paytok_${cred.challenge.id}` || !unspent.delete(token))
      return fresh(core(402, "verification-failed", "Payment verification failed", "The payment proof isn't valid or was already used."));
    issued.delete(cred.challenge.id);
    const reference = `pay_${cred.challenge.id.slice(0, 8)}`;
    settled.set(reference, { order, amount: request.amount, currency: request.currency, authority: authority?.receipt_id ?? "none" });

    // (8) The receipt, linked to the authority decision it relied on.
    const receipt = {
      status: "success" as const,
      method: "example",
      timestamp: o
        .now()
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z"),
      reference,
      ...(authority !== null ? { authority: { profile: PROFILE, receipt_id: authority.receipt_id, receipt_hash: authority.receipt_hash } } : {}),
    };
    return new Response(JSON.stringify({ order, status: "confirmed" }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "private",
        "payment-receipt": receiptValue(receipt),
        ...(authority !== null ? { "payment-authority-receipt": serializeDictionary({ profile: PROFILE, receipt: authority.jws }) } : {}),
      },
    });
  }

  return { handle, settled, unspent };
}
