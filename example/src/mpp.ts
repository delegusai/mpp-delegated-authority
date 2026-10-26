// The parts of the Payment HTTP Authentication Scheme (draft-httpauth-payment-01) this example needs, written from the
// spec text: the challenge with its HMAC-SHA256 `id` binding, the credential encoding, and the Payment-Receipt. The
// payment method is a stand-in called "example": its payload is a one-time token the seller issued, so the example
// runs with no payment network. A real seller uses a registered method (tempo, stripe, …) in its place.

import { createHmac } from "node:crypto";
import { canonicalize, type JsonValue } from "@delegus/core";

export const b64u = (s: string): string => Buffer.from(s, "utf8").toString("base64url");
export const unb64u = (s: string): string => Buffer.from(s, "base64url").toString("utf8");
/** base64url of the JCS form of a JSON value, as the spec requires for `request` and `opaque`. */
export const jcsB64u = (v: JsonValue): string => b64u(canonicalize(v));

export interface Challenge {
  id: string;
  realm: string;
  method: string;
  intent: string;
  request: string;
  expires?: string;
  digest?: string;
  header?: "Payment-Authorization";
  opaque?: string;
  /** Extension parameters (here: `authority`). Not part of the core binding. */
  extra?: Record<string, string>;
}

/** The core spec's recommended HMAC-SHA256 binding of `id` to the challenge parameters. */
export function challengeId(secret: string, c: Omit<Challenge, "id" | "extra">): string {
  const slots = [c.realm, c.method, c.intent, c.request, c.expires ?? "", c.digest ?? ""];
  if (c.header !== undefined) slots.push(c.header);
  slots.push(c.opaque ?? "");
  return createHmac("sha256", Buffer.from(secret, "utf8")).update(slots.join("|"), "utf8").digest("base64url");
}

/** The WWW-Authenticate value for one challenge. */
export function challengeHeader(c: Challenge): string {
  const params: Array<[string, string]> = [
    ["id", c.id],
    ["realm", c.realm],
    ["method", c.method],
    ["intent", c.intent],
  ];
  if (c.header !== undefined) params.push(["header", c.header]);
  if (c.expires !== undefined) params.push(["expires", c.expires]);
  if (c.digest !== undefined) params.push(["digest", c.digest]);
  if (c.opaque !== undefined) params.push(["opaque", c.opaque]);
  params.push(["request", c.request]);
  for (const [k, v] of Object.entries(c.extra ?? {})) params.push([k, v]);
  return `Payment ${params.map(([k, v]) => `${k}="${v}"`).join(", ")}`;
}

/** Parse one Payment challenge (the quoted-string auth-params this example emits). Null when it isn't one. */
export function parseChallenge(value: string): Challenge | null {
  if (!value.startsWith("Payment ")) return null;
  const p: Record<string, string> = {};
  for (const m of value.slice(8).matchAll(/([a-z][a-z0-9-]*)="((?:[^"\\]|\\.)*)"/g)) p[m[1]!] = m[2]!.replace(/\\(.)/g, "$1");
  const { id, realm, method, intent, request, expires, digest, header, opaque, ...extra } = p;
  if (!id || !realm || !method || !intent || !request) return null;
  if (header !== undefined && header !== "Payment-Authorization") return null;
  return {
    id,
    realm,
    method,
    intent,
    request,
    ...(expires !== undefined ? { expires } : {}),
    ...(digest !== undefined ? { digest } : {}),
    ...(header !== undefined ? { header } : {}),
    ...(opaque !== undefined ? { opaque } : {}),
    extra,
  };
}

export interface Credential {
  challenge: Omit<Challenge, "extra">;
  source?: string;
  payload: Record<string, unknown>;
}

/** The credential field value: "Payment " and base64url (no padding) of its JSON. */
export const credentialValue = (c: Credential): string => `Payment ${b64u(JSON.stringify(c))}`;

/** A credential from its field value; null when malformed (the core answers 402 malformed-credential). */
export function parseCredential(value: string | null): Credential | null {
  if (value === null || !/^Payment [A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const c = JSON.parse(unb64u(value.slice(8))) as Credential;
    return typeof c === "object" && c !== null && typeof c.challenge === "object" && typeof c.payload === "object" ? c : null;
  } catch {
    return null;
  }
}

/** The echoed parameters a credential carries, without extension parameters. */
export function echo(c: Challenge): Omit<Challenge, "extra"> {
  const { extra: _extra, ...core } = c;
  return core;
}

export interface PaymentReceipt {
  status: "success";
  method: string;
  timestamp: string;
  reference: string;
  [extra: string]: unknown;
}
export const receiptValue = (r: PaymentReceipt): string => b64u(JSON.stringify(r));
export const parseReceiptValue = (v: string): PaymentReceipt => JSON.parse(unb64u(v)) as PaymentReceipt;

/** RFC 9457 Problem Details. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  [member: string]: unknown;
}
