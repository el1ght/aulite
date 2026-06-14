import { generateKeyPairSync, sign, createHash } from "node:crypto";

const REKOR = process.env.AULITE_REKOR_URL ?? "https://rekor.sigstore.dev";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

const nonce = createHash("sha256").update(String(process.hrtime.bigint())).digest("hex");
const artifact = JSON.stringify({ entry_hash: `smoke-${nonce}`, sequence: 1 });
const data = Buffer.from(artifact, "utf-8");

const sha256Hex = createHash("sha256").update(data).digest("hex");
const signatureB64 = sign("sha256", data, privateKey).toString("base64");
const pubPem = publicKey.export({ type: "spki", format: "pem" });

const body = {
  apiVersion: "0.0.1",
  kind: "hashedrekord",
  spec: {
    data: { hash: { algorithm: "sha256", value: sha256Hex } },
    signature: {
      content: signatureB64,
      publicKey: { content: Buffer.from(pubPem).toString("base64") },
    },
  },
};

console.log(`POST ${REKOR}/api/v1/log/entries`);
const res = await fetch(`${REKOR}/api/v1/log/entries`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Accept: "application/json" },
  body: JSON.stringify(body),
});

const text = await res.text();
console.log("status:", res.status);

if (!res.ok) {
  console.error("FAILED:\n" + text.slice(0, 1000));
  process.exit(1);
}

const [uuid, entry] = Object.entries(JSON.parse(text))[0];
console.log("uuid:    ", uuid);
console.log("logIndex:", entry.logIndex);
console.log("verify:  ", `${REKOR}/api/v1/log/entries/${uuid}`);
console.log("search:  ", `https://search.sigstore.dev/?logIndex=${entry.logIndex}`);
