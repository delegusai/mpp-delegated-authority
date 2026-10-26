# Example: an MPP seller that checks delegated authority before it charges

A seller takes payments over MPP and, before it takes any money, asks
one question: did the buyer's organization authorize this agent to make
this purchase, and does that authority still hold? It follows
[`draft-payment-delegated-authority-00`](../draft-payment-delegated-authority-00.md).

```
npm install
npm start
npm test
```

It depends only on two published packages, `@delegus/core` (the
reference engine) and `@delegus/conformance` (the public test vectors),
and runs with no network and no ports: the seller answers fetch-style
`Request` objects directly.

## What runs

- **The seller** (`src/seller.ts`) answers an order with a 402 Payment
  challenge that also states the authority it needs: the `authority`
  parameter names the profile, whether authority is required, the
  seller's identifier and the exact purchase. On the paid request it
  runs the core credential checks, then the authority check, and only
  on ALLOW verifies and settles the payment. Every refusal is 403, or
  503 when the verifier can't be reached, and says
  `payment: "not_attempted"`. On success the `Payment-Receipt` names the
  signed decision it relied on, by hash, and `Payment-Authority-Receipt`
  carries the decision itself.
- **The authority check** (`src/authority.ts`) reads the
  `Payment-Authority` field (a Structured Field Dictionary with
  `profile`, `grant` and `proof`), checks that the proof was signed for
  this method and address, asks the verifier, and checks the verifier's
  signature before it trusts the answer.
- **The payment method** (`src/mpp.ts`) is a stand-in called `example`:
  paying means presenting a one-time token the seller issued. The
  challenge `id` uses the MPP core specification's HMAC-SHA256 binding
  and is tested against that specification's own test vectors. A real
  seller uses a registered payment method here.
- **The verifier** (`src/vector-verifier.ts`) stands in for the Delegus
  `POST /verify` service: the reference engine over the state fixed by
  three public conformance vectors (`allow-commerce-purchase`,
  `deny-amount-exceeds-authority`, `deny-authority-revoked`). The
  decisions are real signed receipts. Revocation is modelled as what it
  is, a change in the verifier's state: after `revoke()`, the same grant
  is evaluated against a status list with its bit set.
- **The agent** (`src/agent.ts`) presents the grant and proof from those
  vectors. A real agent signs a new proof for every request.

## Against the hosted service

Replace the stand-in verifier with a call to the Delegus `POST /verify`
service (with the seller's API key), and the vectors' grant and proof
with ones your agent signs. Nothing else in the seller changes.
