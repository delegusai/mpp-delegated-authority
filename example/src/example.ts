// Run: npm start (or node --experimental-strip-types src/example.ts)
// One seller, one order, six agents' requests. Every decision comes from the reference engine over a public
// conformance vector, and is signed. The seller settles only after ALLOW.

import { buy } from "./agent.ts";
import { parseReceiptValue } from "./mpp.ts";
import { seller } from "./seller.ts";
import { vectorWorld } from "./vector-verifier.ts";

export const ORIGIN = "https://seller.example";
export const VECTORS = ["allow-commerce-purchase", "deny-amount-exceeds-authority", "deny-authority-revoked"] as const;
type Presentable = "allow-commerce-purchase" | "deny-amount-exceeds-authority";

export function setup(requireAuthority = true, origin = ORIGIN) {
  const world = vectorWorld(VECTORS);
  const allow = world.vector("allow-commerce-purchase").input;
  const shop = seller({
    origin,
    realm: "seller.example",
    rpDid: allow.relying_party,
    secret: "example-challenge-secret",
    verifier: world.verifier,
    receiptKeys: world.receiptKeys,
    verifierDid: world.verifierDid,
    requireAuthority,
    // The conformance vectors' fixed clock, so the Proofs in them are fresh.
    now: () => new Date(allow.evaluated_at),
    catalog: { order_92813: { amount: "42700", currency: "usd" } },
  });
  const presented = (id: Presentable) => ({ grant: world.vector(id).input.grant, proof: world.vector(id).input.proof });
  return { world, shop, presented };
}

async function main() {
  const { world, shop, presented } = setup();
  const url = `${ORIGIN}/orders`;
  const line = async (label: string, run: Promise<{ response: Response }>) => {
    const { response } = await run;
    const body = (await response.clone().json()) as Record<string, unknown>;
    const receipt = response.headers.get("payment-receipt");
    const says =
      response.status === 200
        ? `200 paid, Payment-Receipt authority ${JSON.stringify((parseReceiptValue(receipt!) as { authority?: unknown }).authority)}`
        : `${response.status} ${String(body["type"]).split("/").pop()}${body["reason"] ? ` ${String(body["reason"])}` : ""} (payment ${String(body["payment"] ?? "n/a")})`;
    console.log(`${label.padEnd(44)} ${says}`);
  };

  const first = await buy(shop.handle, url, "order_92813", presented("allow-commerce-purchase"));
  console.log("The challenge's authority parameter:", JSON.stringify(first.authorityParam));
  const s = first.response;
  console.log(`${"Grant up to $500.00, buys $427.00".padEnd(44)} ${s.status} paid, ${shop.settled.size} settlement`);
  await line("The same Proof again", buy(shop.handle, url, "order_92813", presented("allow-commerce-purchase")));
  await line("Grant up to $426.99, buys $427.00", buy(shop.handle, url, "order_92813", presented("deny-amount-exceeds-authority")));
  world.revoke();
  await line("The organization revokes; next purchase", buy(shop.handle, url, "order_92813", presented("allow-commerce-purchase")));
  await line("No grant presented", buy(shop.handle, url, "order_92813", null));
  world.down = true;
  await line("Verifier unreachable", buy(shop.handle, url, "order_92813", presented("allow-commerce-purchase")));
  console.log(`Settled payments: ${shop.settled.size} (only the first request was charged).`);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
