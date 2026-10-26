---
title: Delegated Authority Extension for HTTP Payment Authentication
abbrev: Payment Delegated Authority
docname: draft-payment-delegated-authority-00
version: "00"
category: info
ipr: noModificationTrust200902
submissiontype: IETF
consensus: true

author:
  - name: Inam Haq
    ins: I. Haq
    email: hello@delegus.ai
    org: Delegus
    country: US

normative:
  RFC2119:
  RFC4648:
  RFC8174:
  RFC8259:
  RFC8785:
  RFC9110:
  RFC9111:
  RFC9449:
  RFC9457:
  RFC9651:
  I-D.httpauth-payment:
    title: "The 'Payment' HTTP Authentication Scheme"
    target: https://datatracker.ietf.org/doc/draft-ryan-httpauth-payment/
    author:
      - name: Brendan Ryan
    date: 2026-01
  I-D.payment-intent-charge:
    title: "'charge' Intent for HTTP Payment Authentication"
    target: https://datatracker.ietf.org/doc/draft-payment-intent-charge/
    author:
      - name: Jake Moxey
      - name: Brendan Ryan
    date: 2026
  DELEGUS-V0.2:
    title: "Delegus Specification v0.2 (frozen)"
    target: https://delegus.ai/docs/spec
    author:
      - org: Delegus
    date: 2026-09

informative:
  RFC9421:
  W3C-VC2:
    title: "Verifiable Credentials Data Model v2.0"
    target: https://www.w3.org/TR/vc-data-model-2.0/
    author:
      - org: W3C
  W3C-BSL:
    title: "Bitstring Status List v1.0"
    target: https://www.w3.org/TR/vc-bitstring-status-list/
    author:
      - org: W3C
  AP2:
    title: "Agent Payments Protocol (AP2)"
    target: https://github.com/google-agentic-commerce/AP2
    author:
      - org: Google
    date: 2025
  WEB-BOT-AUTH:
    title: "HTTP Message Signatures for automated traffic
      Architecture"
    target: https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/
    date: 2025
  DELEGUS-VECTORS:
    title: "Delegus v0.2 conformance vectors"
    target: https://www.npmjs.com/package/@delegus/conformance
    author:
      - org: Delegus
    date: 2026
---

--- abstract

This document defines the "delegated authority" extension for the
Payment HTTP Authentication Scheme {{I-D.httpauth-payment}}. It lets
a client acting for an organization present, beside its Payment
credential, a signed delegation of authority and a proof bound to
the exact request, so that the server can confirm the organization
authorized this purchase before any value moves. A denial is
reported with 403 and a signed decision receipt; the payment is not
attempted.

--- middle

# Introduction

A Payment credential shows that a payment can be made. When the
payer is an automated agent acting for an organization, it does not
show that the organization authorized this agent to make this
purchase, or that the authority still holds when the request
arrives. Identity mechanisms such as request signatures
{{RFC9421}} {{WEB-BOT-AUTH}} identify the agent; they do not carry
what the agent is allowed to do.

This extension carries that second question. The client sends a
Grant (a delegation signed by the organization) and a Proof (signed
by the agent for this one request) in one request header field beside
the Payment credential. The server asks an authority verifier for a
decision before it verifies or settles the payment, settles only on
ALLOW, and links the signed decision to the `Payment-Receipt`.

This extension is OPTIONAL. Servers MAY implement it to accept
payments from agents only within authority their organization
granted. Clients that do not implement it remain able to pay any
server that does not require it.

## Scope

This extension:

- DOES define how a client presents delegated authority with a
  Payment credential, how a server orders the authority decision
  against payment verification and settlement, which status codes
  it uses, and how the decision is linked to the receipt.
- DOES define one authority profile, `delegus-v0.2`, which carries
  the Grant and Proof formats of {{DELEGUS-V0.2}}.
- DOES NOT define agent identity, a payment method, or a payment
  intent, and does not change the core challenge binding.
- DOES NOT define limits that span several payments. Per-payment
  limits only (see {{open-issues}}).
- In this version, applies to the "charge" intent
  {{I-D.payment-intent-charge}} only.

## Relationship to the Core Specification

This document extends {{I-D.httpauth-payment}}. Implementations of
this extension MUST also implement the core specification. Nothing
here changes the meaning of a Payment challenge, credential or
receipt for a peer that does not implement this extension.

# Requirements Language

{::boilerplate bcp14-tagged}

# Terminology

Principal
: The organization (or person) that delegates authority, identified
  by a DID and holding the key that signs the Grant.

Agent
: The client acting for the Principal, holding the key that signs
  each Proof.

Grant
: A credential signed by the Principal stating what the Agent may
  do, for how long and at which servers, with a revocation status
  entry. In the `delegus-v0.2` profile, a compact JWS as defined in
  {{DELEGUS-V0.2}}.

Proof
: A short-lived JWS signed by the Agent that binds the Grant to one
  HTTP request (method and target URI), one server, and one Action.
  Modeled on DPoP {{RFC9449}}.

Action
: A JSON object describing what the request does, constructed by
  the server from its own record of the challenge. For a charge, it
  states the amount and currency.

Authority Verifier
: The service that evaluates a Grant, a Proof and an Action and
  returns a signed decision. In the `delegus-v0.2` profile, an
  implementation of `POST /verify` in {{DELEGUS-V0.2}}.

Decision Receipt
: The verifier's signed record of one decision (ALLOW or DENY), its
  reason, and the evidence it was made against. It can be checked
  later without contacting the verifier.

Authority Profile
: A named set of formats and rules for the Grant, Proof, Action,
  verification and receipt. This document defines `delegus-v0.2`.

# Protocol Overview

~~~
   Agent                     Server                    Verifier
     │                          │                          │
     │ (1) POST /orders         │                          │
     ├─────────────────────────>│                          │
     │ (2) 402, WWW-Authenticate: Payment ...,             │
     │     authority="<profiles, server, Action>"          │
     │<─────────────────────────┤                          │
     │                          │                          │
     │ (3) sign payment; sign Proof over the Action        │
     │                          │                          │
     │ (4) POST /orders         │                          │
     │     Payment-Authorization: Payment <credential>     │
     │     Payment-Authority: profile="delegus-v0.2",      │
     │       grant="<Grant>", proof="<Proof>"              │
     ├─────────────────────────>│                          │
     │                          │ (5) core credential      │
     │                          │     checks, no effects   │
     │                          │ (6) Grant, Proof, Action │
     │                          ├─────────────────────────>│
     │                          │ (7) signed decision      │
     │                          │<─────────────────────────┤
     │                          │ (8) ALLOW: verify and    │
     │                          │     settle the payment   │
     │ (9) 200 OK               │                          │
     │     Payment-Receipt: <receipt with authority link>  │
     │     Payment-Authority-Receipt: <decision receipt>   │
     │<─────────────────────────┤                          │
~~~

On DENY at step (7) the server answers 403 and never performs step
(8): the payment is not verified, not settled, and the payment proof
is not consumed.

# Authority Profiles {#profiles}

An authority profile fixes the formats and rules this extension
leaves open: the Grant and Proof formats and the request header
fields that carry them, how the server constructs the Action from a
challenge, how the server obtains a decision, and the decision
receipt format.

A server MUST NOT accept a profile it does not implement. A client
MUST NOT send authority for a profile the challenge does not list.

## The delegus-v0.2 Profile {#delegus-profile}

Profile identifier: `delegus-v0.2`.

Grant and Proof:
: As defined in {{DELEGUS-V0.2}}: the Grant is a Verifiable
  Credential {{W3C-VC2}} in compact JWS form signed with EdDSA; its
  revocation is a Bitstring Status List entry {{W3C-BSL}}. The Proof
  is a compact JWS with claims `iss`, `aud`, `grant`, `jti`, `iat`,
  `htm`, `htu` and `action_hash`.

Carriage:
: The Grant and the Proof travel as the `grant` and `proof` members of
  the `Payment-Authority` field ({{field}}), each the compact JWS
  exactly as {{DELEGUS-V0.2}} defines it, byte for byte. (That
  specification also defines the fields `Delegus-Grant` and
  `Delegus-Proof` for the same values; under this extension the
  neutral field carries them instead, and the values do not change.)

Action:
: Constructed as in {{action}}.

Decision:
: The server calls `POST /verify` with `{"grant", "proof",
  "action"}`. The verifier evaluates the checks of
  {{DELEGUS-V0.2}} in their canonical order and returns the Decision
  Receipt. The verifier performs no DID resolution, status list
  retrieval or other third-party request while deciding; revocation
  completed before the request began is always observed.

Receipt:
: The Decision Receipt of {{DELEGUS-V0.2}}: a compact JWS signed
  with EdDSA whose payload records the decision, the reason, the
  hashes of the Grant, Proof and Action, and the evidence used.

Per-payment limits only:
: The v0.2 vocabulary limits each purchase by `maxAmount` and
  `currency`. It has no running total across purchases.

# The Payment-Authority Field {#field}

The client carries delegated authority in the `Payment-Authority`
request header field. Its value is a Structured Field Dictionary
{{RFC9651}}:

~~~abnf
Payment-Authority = sf-dictionary
~~~

| Member | Type | Required | Description |
|--------|------|----------|-------------|
| `profile` | sf-string | Yes | The authority profile ({{profiles}}) |
| other members | per profile | Per profile | The profile's artifacts |

For the `delegus-v0.2` profile the members `grant` and `proof` are
REQUIRED sf-strings, each holding one compact JWS.

~~~http
Payment-Authority: profile="delegus-v0.2",
    grant="eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3...",
    proof="eyJhbGciOiJFZERTQSIsInR5cCI6ImRlbGVn..."
~~~

A server MUST treat a request as carrying malformed authority, and
answer 403 with problem type `authority-malformed`, when the field
does not parse as a Dictionary, when it occurs more than once, when
`profile` is missing or names a profile the challenge did not list,
or when a member the profile requires is missing or not an
sf-string. Members a profile does not define are ignored.

The field name is neutral so that the same carrier serves further
profiles; what a profile carries inside it is that profile's own
format, unchanged.

The server returns the decision in the `Payment-Authority-Receipt`
response header field ({{receipt}}), also a Dictionary, with the
members `profile` and `receipt` (an sf-string holding the Decision
Receipt in the profile's format).

# Challenge Parameter: authority {#authority-param}

A server that implements this extension MAY include an `authority`
auth-param in a Payment challenge. Its value is a base64url-encoded
{{RFC4648}} JSON {{RFC8259}} object, serialized with JCS {{RFC8785}},
without padding:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `profiles` | array of strings | Yes | Authority profiles the server accepts, in preference order |
| `required` | boolean | Yes | Whether the server refuses a paid request that carries no authority |
| `server` | string | Yes | The server's identifier for the profile; for `delegus-v0.2`, its relying-party DID, used as the Proof `aud` |
| `action` | object | Yes | The Action the server will submit for this challenge ({{action}}) |

Clients that do not implement this extension ignore the parameter,
as the core specification requires for unknown parameters.

The `authority` parameter is not an input to the core challenge
binding, whose layout is fixed. It does not need to be: the server
never reads authority data back from the client. At step (6) it
submits the Action from its own record of the challenge, so a
modified `action` value produces a Proof whose `action_hash` does
not match, and the verifier denies it.

A server that requires authority MUST include `authority` with
`required: true` in every challenge for the resource, so that a
client can decide before paying.

## Example

~~~http
HTTP/1.1 402 Payment Required
Cache-Control: no-store
WWW-Authenticate: Payment id="kM9xPqWvT2nRsY4hBcZa7L",
    realm="seller.example",
    method="example",
    intent="charge",
    header="Payment-Authorization",
    expires="2026-09-10T12:05:00Z",
    request="eyJhbW91bnQiOiI0MjcwMCIsImN1cnJlbmN5IjoidXNkIiwi...",
    authority="eyJhY3Rpb24iOnsiYW1vdW50Ijo0MjcwMCwiY3VycmVuY3..."
~~~

Decoded `request`:

~~~json
{
  "amount": "42700",
  "currency": "usd",
  "externalId": "order_92813"
}
~~~

Decoded `authority`:

~~~json
{
  "action": {
    "amount": 42700,
    "currency": "USD",
    "resource": "order_92813",
    "type": "commerce:purchase"
  },
  "profiles": ["delegus-v0.2"],
  "required": true,
  "server": "did:web:test.delegus.example:rp:seller"
}
~~~

Using `header="Payment-Authorization"` keeps `Authorization` free
for the client's ordinary authentication, as the core specification
allows. This extension does not require it.

# Constructing the Action {#action}

For the `delegus-v0.2` profile and the "charge" intent, the server
constructs the Action from the `request` it issued:

| Action field | Value |
|--------------|-------|
| `type` | `"commerce:purchase"` |
| `resource` | The server's identifier for what is bought: `externalId` when present, else a stable server-chosen identifier |
| `amount` | The integer value of `amount` |
| `currency` | The ISO 4217 code of `currency`, in uppercase |

The server MUST NOT offer the `delegus-v0.2` profile for a challenge
whose `currency` is not an ISO 4217 code, or whose `amount` is not a
string of ASCII digits without leading zeros whose value is at most
2^53-1. The v0.2 vocabulary expresses ISO 4217 currencies in minor
units only; for those currencies the charge intent's base units are
the same minor units.

The server MUST construct the Action from its own record of the
challenge identified by the credential's `id`, never from values
supplied by the client.

# Presenting Authority {#request}

A client that accepts a challenge listing a profile it implements,
and that acts under a Grant, sends with its Payment credential:

~~~http
POST /orders HTTP/1.1
Host: seller.example
Payment-Authorization: Payment eyJjaGFsbGVuZ2UiOnsi...
Payment-Authority: profile="delegus-v0.2",
    grant="eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3...",
    proof="eyJhbGciOiJFZERTQSIsInR5cCI6ImRlbGVn..."
~~~

For the `delegus-v0.2` profile the client signs a new Proof for each
request with:

- `aud` equal to `server` from the `authority` parameter;
- `grant` equal to the Grant's `id`;
- `htm` and `htu` equal to the method and the target URI of this
  request, `htu` in the canonical form of {{RFC9449}} as profiled in
  {{DELEGUS-V0.2}};
- `action_hash` equal to `sha256:` followed by the lowercase hex
  SHA-256 of the JCS form of `action` from the `authority`
  parameter;
- a fresh `jti` with at least 128 random bits, and `iat` set to the
  current time.

A Proof is used once. A retry, including one after a 402, needs a
new Proof.

# Server Processing {#processing}

A server that implements this extension processes a request that
carries a Payment credential in this order. Steps 1 to 4 perform no
settlement and do not consume the payment proof.

1. Perform the core credential checks that have no side effects:
   decoding, header field selection, challenge binding, expiry and
   digest. A failure is answered as the core specification requires
   (402 with a fresh challenge). Authority is not evaluated and no
   Proof is consumed.

2. If the challenge required authority and the request carries no
   `Payment-Authority` field, answer 403 with problem type
   `authority-required` ({{responses}}). If the field is present but
   malformed ({{field}}), answer 403 with problem type
   `authority-malformed`.

3. Check the Proof's binding to this request: `htm` MUST equal the
   request method and `htu` MUST equal the canonical form of the
   URI the client targeted (the server's public URI for the
   resource, not an internal one). On mismatch answer 403 with
   problem type `proof-binding-mismatch`. The verifier cannot make
   this check because it does not see the request.

4. Obtain the decision: for `delegus-v0.2`, call `POST /verify` with
   the Grant and Proof as received and the Action from {{action}}.

5. On DENY, answer 403 with problem type `authority-denied` and the
   Decision Receipt. The server MUST NOT verify or settle the
   payment.

6. If the verifier cannot be reached, does not answer in time,
   answers with something that is not a Decision Receipt, or
   answers DENY with reason `SERVICE_UNAVAILABLE`, answer 503 with
   problem type `authority-unavailable` and a `Retry-After` field.
   The server MUST NOT verify or settle the payment.

7. On ALLOW, continue with the core payment verification and
   settlement. If they fail, answer as the core specification
   requires (402 with a fresh challenge). The client's next attempt
   needs a new Proof.

8. On success, answer as the core specification requires and add
   the authority link to the `Payment-Receipt` ({{receipt}}).

A server MUST fail closed: anything other than a verified ALLOW for
this Grant, this Proof and this Action ends the request before
settlement.

A server MAY also check authority on a request that carries no
Payment credential but does carry authority, before issuing a
challenge, and answer 403 at once on DENY. The Proof used there is
consumed; the paid request needs a new one.

# Responses {#responses}

## Status Codes {#status}

| Condition | Status | Settlement |
|-----------|--------|------------|
| Core credential check fails | 402, fresh challenge | Not attempted |
| Authority required, none presented | 403 | Not attempted |
| Authority field malformed | 403 | Not attempted |
| Proof not bound to this request | 403 | Not attempted |
| Verifier answers DENY | 403 | Not attempted |
| Verifier unavailable or no decision | 503 | Not attempted |
| ALLOW, payment verification fails | 402, fresh challenge | Failed |
| ALLOW, payment settled | 200 | Settled |

## Why 403 and not 402 {#why-403}

The core specification distinguishes 402 ("a payment barrier,
initial challenge or retry needed") from 403 ("payment succeeded but
access is denied by policy"), and tells servers not to return 402
when "the client is authenticated but lacks authorization". A
denial of authority is a lack of authorization. Paying again cannot
change it, so a fresh Payment challenge would invite a retry that
must fail the same way.

The core's 403 row assumes the payment was already verified. Under
this extension the denial happens before payment verification, so
the 403 response also states that payment was not attempted
(`payment: "not_attempted"`). This keeps the core rule that a server
performs no side effects for a request it has not been paid for, and
it means a denied agent is never charged.

A verifier outage is not a verdict. 503 with `Retry-After` {{RFC9110}}
tells the
client that the same request may succeed later, which 403 would not.

## Problem Details {#problems}

Errors use Problem Details {{RFC9457}}. Problem types are under
`https://delegus.ai/problems/`:

| Type | Status | Meaning |
|------|--------|---------|
| `authority-required` | 403 | The resource needs delegated authority and none was presented |
| `authority-malformed` | 403 | The `Payment-Authority` field is not valid for the profile |
| `proof-binding-mismatch` | 403 | The Proof's `htm` or `htu` is not this request |
| `authority-denied` | 403 | The verifier answered DENY |
| `authority-unavailable` | 503 | No decision could be obtained |

The body carries, in addition to the RFC 9457 members:

| Member | Type | Description |
|--------|------|-------------|
| `payment` | string | Always `"not_attempted"` |
| `profile` | string | The authority profile used |
| `reason` | string or null | The verifier's reason code, for example `AMOUNT_EXCEEDS_AUTHORITY` or `AUTHORITY_REVOKED` |
| `receipt` | string or null | The Decision Receipt (compact JWS), when one was issued |

A 403 or 503 response under this extension MUST NOT include a
`WWW-Authenticate: Payment` challenge or a `Payment-Receipt`.

~~~http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Cache-Control: no-store

{
  "type": "https://delegus.ai/problems/authority-denied",
  "title": "Delegated authority denied",
  "status": 403,
  "detail": "The amount is above what the grant allows.",
  "payment": "not_attempted",
  "profile": "delegus-v0.2",
  "reason": "AMOUNT_EXCEEDS_AUTHORITY",
  "receipt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3..."
}
~~~

## Receipt Linking {#receipt}

On success the server adds an `authority` member to the
`Payment-Receipt` JSON object, which the core specification allows
receipts to carry and requires peers that do not know it to ignore:

| Field | Type | Description |
|-------|------|-------------|
| `profile` | string | The authority profile used |
| `receipt_id` | string | The Decision Receipt's identifier |
| `receipt_hash` | string | `sha256:` and the lowercase hex SHA-256 of the Decision Receipt's compact JWS bytes |

The server SHOULD also return the Decision Receipt itself in the
`Payment-Authority-Receipt` response header field ({{field}}):

~~~http
Payment-Authority-Receipt: profile="delegus-v0.2",
    receipt="eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3..."
~~~ The hash in the payment
receipt lets anyone holding both confirm which authority decision a
settled payment relied on.

~~~json
{
  "authority": {
    "profile": "delegus-v0.2",
    "receipt_hash": "sha256:6d2c0f...",
    "receipt_id": "drc_01K4Q7ZP9X2M3N4R5S6T7V8W9Y"
  },
  "method": "example",
  "reference": "pay_8f3a21",
  "status": "success",
  "timestamp": "2026-09-10T12:00:01Z"
}
~~~

# Interoperability

## Peers That Do Not Implement This Extension

A client that does not implement this extension ignores the
`authority` parameter. A server that does not require authority
serves it as usual; a server that requires authority answers 403
`authority-required` without settling, so the client is not
charged.

A server that does not implement this extension ignores the
`Payment-Authority` field as an unknown header field.
The client's payment proceeds without an authority check; the Proof
is never consumed and expires. A client that must not pay without
an authority check MUST NOT send a Payment credential to a server
whose challenge lacks an `authority` parameter listing a profile it
implements.

## Agent Identity

Request signatures {{RFC9421}}, Web Bot Auth {{WEB-BOT-AUTH}} and
the credential's `source` field identify a client. This extension
does not replace them and does not read `source`. Identity answers
which agent is calling; this extension answers whether its
organization authorized this purchase. A server MAY use both.

## Other Authority Formats

Other ways of expressing delegated spending authority exist, for
example payment mandates in {{AP2}}. Such a format could be carried
by a further authority profile in the same `Payment-Authority` field,
with its own members and decision rules. This document defines none besides `delegus-v0.2`.

## Other Intents and Transports

This version applies to the "charge" intent over HTTP. Intents that
settle several payments under one credential, such as sessions and
subscriptions, need limits that span payments, which the
`delegus-v0.2` profile does not express ({{open-issues}}).

# Security Considerations

## Authorization Boundary

The server relies on the verifier's signed decision. It MUST verify
the Decision Receipt's signature against the verifier's published
key, or rely on an authenticated TLS connection to the verifier it
chose, before treating a decision as ALLOW. A decision for a
different Grant, Proof or Action MUST NOT be used.

## Ordering Against Settlement

Settling before the authority decision would charge an agent the
server then refuses. Servers MUST obtain the decision before any
step that moves value or consumes the payment proof. Some payment
methods settle inside their verification step; for those, the
authority decision MUST come before that step.

## Replay

Each Proof carries a `jti` the verifier records once per server
({{DELEGUS-V0.2}}, check T5); a second use is denied
`PROOF_REPLAYED`. Concurrent requests with the same Proof therefore
yield at most one ALLOW, alongside the core rule that a payment
proof is used once. A server answering an `Idempotency-Key` retry
from its stored response MUST NOT obtain a new decision for it and
MUST NOT settle again.

## Revocation Freshness

A server MUST obtain a new decision for every settlement and MUST
NOT cache an ALLOW across requests. In the `delegus-v0.2` profile a
revocation that completed before a `/verify` call began is always
observed by it, so a revoked Grant stops working at every server at
once.

## Downgrade

An attacker that strips the `Payment-Authority` field from a request
can
at most cause a 403 at a server that requires authority. A server
that does not set `required: true` gives no assurance that a payment
was authorized. Servers that need the assurance MUST set it.

## Tampering With the Challenge Parameter

The `authority` parameter is outside the core challenge binding. A
modified `server` value produces a Proof with the wrong `aud`; a
modified `action` produces a mismatched `action_hash`. Both are
denied by the verifier. The server never reads either value back
from the client.

## Information Disclosure

A Grant reveals the Principal, the Agent and the limits granted to
the server receiving it. Clients SHOULD use Grants whose audience
and limits are no wider than the purchase needs. Servers and
intermediaries SHOULD NOT log Grants or Proofs and MUST NOT log
Payment credentials. Responses to requests carrying a Payment
credential outside `Authorization` already require `Cache-Control:
private` or `no-store` under the core specification; 403 and 503
responses under this extension MUST carry `Cache-Control: no-store`
{{RFC9111}}.

## Denial of Service

Each paid request costs the server one verifier call. Servers SHOULD
rate-limit authority checks per client and SHOULD perform the core
credential checks of step 1 first, which are local.

## Verifier Availability

When no decision can be obtained, the server refuses (503). A
server MUST NOT treat a verifier outage as ALLOW.

# IANA Considerations

## HTTP Field Names

This document requests provisional registration in the "Hypertext
Transfer Protocol (HTTP) Field Name Registry":

| Field Name | Status | Reference |
|------------|--------|-----------|
| Payment-Authority | provisional | This document, {{field}} |
| Payment-Authority-Receipt | provisional | This document, {{field}} |

Both are Dictionary Structured Fields {{RFC9651}}.

## Payment Challenge Parameter and Receipt Field

The core specification defines no registry for challenge parameters
or receipt fields. This document uses the `authority` challenge
parameter and the `authority` receipt member. If such registries are
created, these should be registered with a reference to this
document.

## Problem Types

The problem types in {{problems}} are defined by this document under
`https://delegus.ai/problems/`. No IANA action is requested.

# Open Issues {#open-issues}

This section is to be removed before publication.

1. Limits across payments. Budgets that span several payments and
   servers are needed for sessions, subscriptions and procurement.
   They are proposed for a later version of the Delegus
   specification and are not part of `delegus-v0.2`.
2. The v0.2 field names. {{DELEGUS-V0.2}} also defines
   `Delegus-Grant` and `Delegus-Proof` for the same values. Whether a
   server implementing this extension should also accept those two
   fields, for clients built before it, is open.
3. Problem type URIs. The URIs under `https://delegus.ai/problems/`
   should resolve to documentation before publication.
4. The MCP transport. A mapping for
   draft-payment-transport-mcp is not yet defined.

--- back

# Complete Example

The values below are from the public conformance vectors
{{DELEGUS-VECTORS}} (case `allow-commerce-purchase` and its DENY
counterpart `deny-amount-exceeds-authority`) and are not real.

The Agent requests an order:

~~~http
POST /orders HTTP/1.1
Host: seller.example
Content-Type: application/json

{"order":"order_92813"}
~~~

The server answers with a challenge as in {{authority-param}}. The
Agent pays and signs a Proof with `aud`
`did:web:test.delegus.example:rp:seller`, `htm` `POST`, `htu`
`https://seller.example/orders`, and `action_hash`
`sha256:f7efb258ad66b8dcb4aebac2a1c85070821031ab1fa6376b6fa19437f5de4053`,
the hash of:

~~~json
{"amount":42700,"currency":"USD","resource":"order_92813","type":"commerce:purchase"}
~~~

Under a Grant allowing purchases of up to 50000 USD minor units, the
verifier answers ALLOW, the server settles and answers 200 with the
authority link in `Payment-Receipt`. Under the same request with a
Grant allowing 42699, the verifier answers DENY
`AMOUNT_EXCEEDS_AUTHORITY` (check P19); the server answers 403 as in
{{problems}} and does not settle.

# Acknowledgments
{:numbered="false"}

Thanks to the maintainers of the Payment HTTP Authentication Scheme
for their guidance that delegated authority belongs in an extension.
