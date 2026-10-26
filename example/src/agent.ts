// The agent side: ask for an order, read the challenge, pay it with the stand-in method, and send the Grant and Proof
// beside the Payment credential, in the one Payment-Authority field. Here the Grant and Proof come from a conformance vector (signed with its fixed test
// keys); a real agent signs a fresh Proof per request with @delegus/sdk.

import { PROFILE, serializeDictionary } from "./authority.ts";
import { credentialValue, echo, parseChallenge, unb64u, type Challenge } from "./mpp.ts";

export interface Presented {
  grant: string;
  proof: string;
}

export async function buy(
  handle: (r: Request) => Promise<Response>,
  url: string,
  order: string,
  authority: Presented | null,
): Promise<{ challenge: Challenge | null; authorityParam: unknown; response: Response }> {
  const post = (headers: Record<string, string> = {}) => handle(new Request(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ order }) }));
  const first = await post();
  const challenge = parseChallenge(first.headers.get("www-authenticate") ?? "");
  if (first.status !== 402 || challenge === null) return { challenge, authorityParam: null, response: first };
  const param = challenge.extra?.["authority"];
  const authorityParam = param === undefined ? null : (JSON.parse(unb64u(param)) as unknown);
  const credential = credentialValue({ challenge: echo(challenge), payload: { token: `paytok_${challenge.id}` } });
  const response = await post({
    "payment-authorization": credential,
    ...(authority !== null ? { "payment-authority": serializeDictionary({ profile: PROFILE, grant: authority.grant, proof: authority.proof }) } : {}),
  });
  return { challenge, authorityParam, response };
}
