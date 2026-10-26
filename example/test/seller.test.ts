// The example seller against the extension draft: ALLOW and DENY from the conformance vectors, the status codes, no
// settlement on any refusal, the receipt link, and the core spec's own HMAC binding test vectors.
import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalize, sha256Utf8, verifyReceiptSignature } from "@delegus/core";
import { buy } from "../src/agent.ts";
import { ORIGIN, setup } from "../src/example.ts";
import { parseDictionary, serializeDictionary } from "../src/authority.ts";
import { challengeId, parseReceiptValue } from "../src/mpp.ts";

const URL_ = `${ORIGIN}/orders`;

test("the core spec's HMAC-SHA256 binding test vectors", () => {
  const base = { realm: "api.example.com", method: "tempo", intent: "charge", request: "eyJhbW91bnQiOiIxMDAwMDAwIn0" };
  assert.equal(challengeId("test-vector-secret", base), "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4");
  assert.equal(challengeId("test-vector-secret", { ...base, header: "Payment-Authorization" }), "S91xi-OFGZPMs-j7GsX0FDpIkmCcZT1P9XyV58WNy_U");
  assert.equal(challengeId("test-vector-secret", { ...base, header: "Payment-Authorization", opaque: "eyJwaSI6InBpXzEyMyJ9" }), "CJ4X1O4aTDmS59hfdhnhBtxIQjWDOf0bcrhsswwMOW8");
});

test("the challenge carries the authority parameter: the profile, required, the seller's DID and the Action the Proof signs", async () => {
  const { shop, presented } = setup();
  const r = await buy(shop.handle, URL_, "order_92813", presented("allow-commerce-purchase"));
  const a = r.authorityParam as { action: unknown; profiles: string[]; required: boolean; server: string };
  assert.deepEqual(a, {
    action: { amount: 42700, currency: "USD", resource: "order_92813", type: "commerce:purchase" },
    profiles: ["delegus-v0.2"],
    required: true,
    server: "did:web:test.delegus.example:rp:seller",
  });
  assert.equal(sha256Utf8(canonicalize(a.action as never)), "sha256:f7efb258ad66b8dcb4aebac2a1c85070821031ab1fa6376b6fa19437f5de4053", "the action_hash in the vector's Proof");
  assert.equal(r.challenge?.header, "Payment-Authorization");
});

test("ALLOW (vector allow-commerce-purchase): settled once, 200, the receipt links the signed decision", async () => {
  const { shop, presented, world } = setup();
  const { response } = await buy(shop.handle, URL_, "order_92813", presented("allow-commerce-purchase"));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "private");
  const receipt = parseReceiptValue(response.headers.get("payment-receipt")!) as unknown as { status: string; authority: { profile: string; receipt_id: string; receipt_hash: string } };
  const carried = parseDictionary(response.headers.get("payment-authority-receipt")!)!;
  assert.equal(carried.get("profile"), "delegus-v0.2");
  const decision = carried.get("receipt")!;
  assert.equal(receipt.status, "success");
  assert.equal(receipt.authority.profile, "delegus-v0.2");
  assert.equal(receipt.authority.receipt_hash, sha256Utf8(decision), "the payment receipt names the exact decision it relied on");
  assert.ok(verifyReceiptSignature(decision, world.receiptKeys, world.verifierDid).ok);
  assert.equal(shop.settled.size, 1);
});

test("DENY (vector deny-amount-exceeds-authority): 403 with the signed reason, no WWW-Authenticate, nothing settled, the payment token unspent", async () => {
  const { shop, presented, world } = setup();
  const { challenge, response } = await buy(shop.handle, URL_, "order_92813", presented("deny-amount-exceeds-authority"));
  const body = (await response.json()) as Record<string, unknown>;
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("www-authenticate"), null);
  assert.equal(response.headers.get("payment-receipt"), null);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(body["type"], "https://delegus.ai/problems/authority-denied");
  assert.equal(body["reason"], "AMOUNT_EXCEEDS_AUTHORITY");
  assert.equal(body["payment"], "not_attempted");
  assert.ok(verifyReceiptSignature(body["receipt"], world.receiptKeys, world.verifierDid).ok, "a signed DENY");
  assert.equal(shop.settled.size, 0);
  assert.ok(shop.unspent.has(`paytok_${challenge!.id}`), "the payment proof was never consumed");
});

test("revoked, replayed, missing, mis-bound: each 403 before payment; an unreachable verifier is 503 with Retry-After", async () => {
  const { shop, presented, world } = setup();
  const reason = async (p: Promise<{ response: Response }>) => {
    const r = (await p).response;
    const b = (await r.json()) as Record<string, unknown>;
    return [r.status, String(b["type"]).split("/").pop(), b["reason"] ?? null, b["payment"]];
  };
  assert.equal((await buy(shop.handle, URL_, "order_92813", presented("allow-commerce-purchase"))).response.status, 200);
  assert.deepEqual(await reason(buy(shop.handle, URL_, "order_92813", presented("allow-commerce-purchase"))), [403, "authority-denied", "PROOF_REPLAYED", "not_attempted"]);
  // The organization revokes the Grant; the next purchase under it is refused (the status list is checked before replay).
  world.revoke();
  assert.deepEqual(await reason(buy(shop.handle, URL_, "order_92813", presented("allow-commerce-purchase"))), [403, "authority-denied", "AUTHORITY_REVOKED", "not_attempted"]);
  assert.deepEqual(await reason(buy(shop.handle, URL_, "order_92813", null)), [403, "authority-required", null, "not_attempted"]);
  // The Proof names https://seller.example/orders; a seller published at another address refuses it before calling
  // the verifier (which never sees the request).
  const elsewhere = setup(true, "https://other.example");
  assert.deepEqual(await reason(buy(elsewhere.shop.handle, "https://other.example/orders", "order_92813", elsewhere.presented("allow-commerce-purchase"))), [
    403,
    "proof-binding-mismatch",
    null,
    "not_attempted",
  ]);
  assert.equal(elsewhere.shop.settled.size, 0);
  world.down = true;
  const down = (await buy(shop.handle, URL_, "order_92813", presented("allow-commerce-purchase"))).response;
  assert.equal(down.status, 503);
  assert.equal(down.headers.get("retry-after"), "5");
  assert.equal(shop.settled.size, 1, "only the one ALLOW was ever charged");
});

test("a seller that offers authority without requiring it still serves an agent with no grant; a malformed credential stays the core's 402", async () => {
  const { shop } = setup(false);
  const r = await buy(shop.handle, URL_, "order_92813", null);
  assert.equal(r.response.status, 200);
  assert.equal((r.authorityParam as { required: boolean }).required, false);
  assert.equal("authority" in parseReceiptValue(r.response.headers.get("payment-receipt")!), false);
  const bad = await shop.handle(new Request(URL_, { method: "POST", headers: { "payment-authorization": "Payment !!!" }, body: JSON.stringify({ order: "order_92813" }) }));
  assert.equal(bad.status, 402);
  assert.ok(bad.headers.get("www-authenticate")?.startsWith("Payment "));
});

test("Payment-Authority: one Dictionary carries the v0.2 Grant and Proof byte for byte; anything malformed is 403 before payment", async () => {
  const { shop, presented } = setup();
  const p = presented("allow-commerce-purchase");
  const field = serializeDictionary({ profile: "delegus-v0.2", grant: p.grant, proof: p.proof });
  const back = parseDictionary(field)!;
  assert.equal(back.get("grant"), p.grant, "the Grant comes out exactly as it went in");
  assert.equal(back.get("proof"), p.proof);
  assert.deepEqual(
    [...parseDictionary('a="x\\"y", b="z"')!],
    [
      ["a", 'x"y'],
      ["b", "z"],
    ],
  );
  for (const bad of ['profile="delegus-v0.2", profile="delegus-v0.2"', "profile=delegus-v0.2", 'profile="delegus-v0.2",', 'profile="x\u0001"']) assert.equal(parseDictionary(bad), null, bad);

  const send = async (value: string) => {
    const first = await shop.handle(new Request(URL_, { method: "POST", body: JSON.stringify({ order: "order_92813" }) }));
    const { parseChallenge, credentialValue, echo } = await import("../src/mpp.ts");
    const c = parseChallenge(first.headers.get("www-authenticate")!)!;
    const r = await shop.handle(
      new Request(URL_, {
        method: "POST",
        headers: { "payment-authorization": credentialValue({ challenge: echo(c), payload: { token: `paytok_${c.id}` } }), "payment-authority": value },
        body: JSON.stringify({ order: "order_92813" }),
      }),
    );
    return [
      r.status,
      String(((await r.json()) as { type: string }).type)
        .split("/")
        .pop(),
    ];
  };
  assert.deepEqual(await send(serializeDictionary({ profile: "delegus-v9", grant: p.grant, proof: p.proof })), [403, "authority-malformed"], "a profile the challenge didn't list");
  assert.deepEqual(await send(serializeDictionary({ profile: "delegus-v0.2", grant: p.grant })), [403, "authority-malformed"], "no proof");
  assert.deepEqual(await send(`${field}, ${field}`), [403, "authority-malformed"], "the field twice");
  assert.equal(shop.settled.size, 0);
});
