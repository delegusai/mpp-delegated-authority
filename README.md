# Delegated authority for MPP payments

A draft extension to MPP, the Payment HTTP Authentication Scheme, and a
small seller that runs it.

- [`draft-payment-delegated-authority-00.md`](draft-payment-delegated-authority-00.md):
  the extension, in the format of the
  [MPP specifications](https://github.com/tempoxyz/mpp-specs).
- [`example/`](example/): a seller that takes MPP payments and checks the
  buyer's delegated authority before it charges.

**Status:** draft 00, October 2026. Not yet proposed upstream; feedback is welcome as issues here.

## The short version

**What MPP already does.** MPP lets a website charge for a request. The
site answers "402: pay this", the client pays and tries again, and the
site checks the payment before it serves the request.

**What it leaves open.** When the client is an AI agent buying for a
company, the payment shows that money can move. It does not show that
the company allowed this agent to spend this much, here, today, or that
the company hasn't since taken that authority back.

**What the extension adds.** The agent sends one more field with its
payment, `Payment-Authority`, holding two things:

- a **grant**: the company's signed note saying what this agent may buy,
  up to how much, until when;
- a **proof**: the agent's own signature tying that grant to this one
  request, this one seller and this exact purchase, usable once.

Before the seller takes any money, it asks a verifier one question:
does this grant cover this purchase right now? The verifier answers yes
or no and signs the answer.

**What the seller does with the answer.**

- **Yes:** the seller takes the payment as usual, and the payment
  receipt points to the signed yes it relied on.
- **No:** the seller refuses (HTTP 403) and **does not charge**. The
  refusal says why (for example "above the limit" or "revoked") and
  carries the signed no.
- **No answer** (the verifier is down): the seller refuses for now
  (HTTP 503, try again later) and does not charge. It never guesses yes.

**Why 403 and not "402, pay again".** Paying again can't fix missing
authority. MPP itself uses 402 when payment is what's missing and 403
when the client isn't authorized, so a refusal of authority is a 403.

**What happens with software that doesn't know about this.** Nothing
breaks. A seller that doesn't support it ignores the extra field and
works as today. An agent that doesn't support it ignores the seller's
request for it; if the seller requires authority, it refuses without
charging.

**What it doesn't do yet.** Each purchase is checked against its own
limit. A shared budget across many purchases and sellers is proposed
for a later version of the Delegus specification and isn't part of this
draft.

**The formats inside.** The field is neutral so that other ways of
expressing authority can use it. The first profile, `delegus-v0.2`,
carries the grant, proof and signed decision of the
[Delegus specification v0.2](https://delegus.ai/docs/spec) exactly as
that specification defines them.

## See it run

Needs Node 22.6 or later.

```
cd example
npm install
npm start
```

```
Grant up to $500.00, buys $427.00            200 paid, 1 settlement
The same Proof again                         403 authority-denied PROOF_REPLAYED (payment not_attempted)
Grant up to $426.99, buys $427.00            403 authority-denied AMOUNT_EXCEEDS_AUTHORITY (payment not_attempted)
The organization revokes; next purchase      403 authority-denied AUTHORITY_REVOKED (payment not_attempted)
No grant presented                           403 authority-required (payment not_attempted)
Verifier unreachable                         503 authority-unavailable (payment not_attempted)
Settled payments: 1 (only the first request was charged).
```

The decisions come from the reference engine in
[`@delegus/core`](https://www.npmjs.com/package/@delegus/core) over the
public conformance vectors in
[`@delegus/conformance`](https://www.npmjs.com/package/@delegus/conformance),
and each one is signed. `npm test` checks the same cases, plus the MPP
core specification's own test vectors for its challenge binding. See
[`example/README.md`](example/README.md) for how the pieces fit.

## Status

The MPP maintainers said delegated authority belongs in an extension,
outside the core specification, and that anyone may author one. This
is that draft, version 00. Comments and issues are welcome here.

## Licence

The draft is CC0 1.0, as the MPP specifications are. The example code
is dual-licensed under Apache 2.0 or MIT. See [LICENSE.md](LICENSE.md).
