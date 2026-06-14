import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export const DEFAULT_REKOR_URL = "https://rekor.sigstore.dev";

export const REKOR_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----`;

export interface RekorInclusionProof {
  logIndex: number;
  rootHash: string;
  treeSize: number;
  hashes: string[];
  checkpoint: string;
}

export interface RekorEntry {
  uuid: string;
  logIndex: number;
  integratedTime: number;
  logUrl: string;
  body: string;
  inclusionProof?: RekorInclusionProof;
  signedEntryTimestamp?: string;
}

export interface HashedRekordInput {
  sha256Hex: string;
  signatureB64: string;
  publicKeyPem: string;
}

export interface RekorOptions {
  rekorUrl?: string;
  fetchImpl?: typeof fetch;
}

type RawEntry = {
  logIndex?: number;
  integratedTime?: number;
  body?: string;
  verification?: {
    inclusionProof?: {
      logIndex?: number;
      rootHash?: string;
      treeSize?: number;
      hashes?: string[];
      checkpoint?: string;
    };
    signedEntryTimestamp?: string;
  };
};

function parseEntriesResponse(data: Record<string, RawEntry>, rekorUrl: string): RekorEntry {
  const entries = Object.entries(data);
  if (entries.length === 0) {
    throw new Error("Rekor returned an empty entries response");
  }
  const [uuid, raw] = entries[0];
  const ip = raw.verification?.inclusionProof;
  return {
    uuid,
    logIndex: raw.logIndex ?? -1,
    integratedTime: raw.integratedTime ?? 0,
    logUrl: `${rekorUrl}/api/v1/log/entries/${uuid}`,
    body: raw.body ?? "",
    inclusionProof:
      ip && ip.rootHash && ip.hashes && ip.checkpoint
        ? {
            logIndex: ip.logIndex ?? 0,
            rootHash: ip.rootHash,
            treeSize: ip.treeSize ?? 0,
            hashes: ip.hashes,
            checkpoint: ip.checkpoint,
          }
        : undefined,
    signedEntryTimestamp: raw.verification?.signedEntryTimestamp,
  };
}

export function buildHashedRekord(input: HashedRekordInput): Record<string, unknown> {
  return {
    apiVersion: "0.0.1",
    kind: "hashedrekord",
    spec: {
      data: { hash: { algorithm: "sha256", value: input.sha256Hex } },
      signature: {
        content: input.signatureB64,
        publicKey: { content: Buffer.from(input.publicKeyPem, "utf-8").toString("base64") },
      },
    },
  };
}

export async function createHashedRekord(input: HashedRekordInput, opts: RekorOptions = {}): Promise<RekorEntry> {
  const rekorUrl = opts.rekorUrl ?? DEFAULT_REKOR_URL;
  const f = opts.fetchImpl ?? fetch;

  const res = await f(`${rekorUrl}/api/v1/log/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(buildHashedRekord(input)),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Rekor upload failed (${res.status}): ${text}`);
  }

  const data = (await res.json()) as Record<string, RawEntry>;
  return parseEntriesResponse(data, rekorUrl);
}

export async function getRekorEntry(uuid: string, opts: RekorOptions = {}): Promise<RekorEntry> {
  const rekorUrl = opts.rekorUrl ?? DEFAULT_REKOR_URL;
  const f = opts.fetchImpl ?? fetch;

  const res = await f(`${rekorUrl}/api/v1/log/entries/${uuid}`, {
    method: "GET",
    headers: { Accept: "application/json" },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Rekor lookup failed (${res.status}): ${text}`);
  }

  const data = (await res.json()) as Record<string, RawEntry>;
  return parseEntriesResponse(data, rekorUrl);
}

export function extractHashFromBody(bodyB64: string): string | null {
  try {
    const decoded = JSON.parse(Buffer.from(bodyB64, "base64").toString("utf-8"));
    return decoded?.spec?.data?.hash?.value ?? null;
  } catch {
    return null;
  }
}

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

const PREFIX_LEAF = Buffer.from([0x00]);
const PREFIX_NODE = Buffer.from([0x01]);

export function rfc6962LeafHash(leafData: Buffer): Buffer {
  return sha256(PREFIX_LEAF, leafData);
}

function hashChildren(left: Buffer, right: Buffer): Buffer {
  return sha256(PREFIX_NODE, left, right);
}

function bitLength(n: bigint): number {
  let len = 0;
  while (n > 0n) {
    len++;
    n >>= 1n;
  }
  return len;
}

function onesCount(n: bigint): number {
  let count = 0;
  while (n > 0n) {
    count += Number(n & 1n);
    n >>= 1n;
  }
  return count;
}

export function rootFromInclusionProof(index: number, treeSize: number, leafHash: Buffer, proof: Buffer[]): Buffer {
  const idx = BigInt(index);
  const size = BigInt(treeSize);
  if (idx >= size) throw new Error("leaf index beyond tree size");

  const inner = bitLength(idx ^ (size - 1n));
  const border = onesCount(idx >> BigInt(inner));
  if (proof.length !== inner + border) {
    throw new Error(`unexpected inclusion proof length: ${proof.length} != ${inner + border}`);
  }

  let seed = leafHash;
  for (let i = 0; i < inner; i++) {
    const bit = (idx >> BigInt(i)) & 1n;
    seed = bit === 0n ? hashChildren(seed, proof[i]) : hashChildren(proof[i], seed);
  }
  for (let i = inner; i < proof.length; i++) {
    seed = hashChildren(proof[i], seed);
  }
  return seed;
}

export interface ParsedCheckpoint {
  origin: string;
  size: number;
  rootHashHex: string;
  signedText: string;
  signatureB64: string;
}

export function parseCheckpoint(checkpoint: string): ParsedCheckpoint | null {
  const sepIdx = checkpoint.indexOf("\n— ");
  if (sepIdx === -1) return null;

  const signedText = checkpoint.slice(0, sepIdx);
  const sigLine = checkpoint.slice(sepIdx + 1).trim();
  const parts = sigLine.split(" ");
  if (parts.length < 3) return null;

  const lines = signedText.split("\n");
  if (lines.length < 3) return null;

  return {
    origin: lines[0],
    size: parseInt(lines[1], 10),
    rootHashHex: Buffer.from(lines[2], "base64").toString("hex"),
    signedText,
    signatureB64: parts.slice(2).join(""),
  };
}

export function verifyCheckpointSignature(checkpoint: string, publicKeyPem: string = REKOR_PUBLIC_KEY_PEM): boolean {
  const parsed = parseCheckpoint(checkpoint);
  if (!parsed) return false;
  try {
    const sig = Buffer.from(parsed.signatureB64, "base64").subarray(4);
    const key = createPublicKey(publicKeyPem);
    return cryptoVerify("sha256", Buffer.from(parsed.signedText, "utf-8"), key, sig);
  } catch {
    return false;
  }
}

export interface InclusionVerifyResult {
  valid: boolean;
  reason?: string;
}

export function verifyInclusionProofOffline(
  bodyB64: string,
  proof: RekorInclusionProof,
  opts: { rekorPublicKey?: string; requireCheckpointSignature?: boolean } = {},
): InclusionVerifyResult {
  try {
    const leaf = rfc6962LeafHash(Buffer.from(bodyB64, "base64"));
    const root = rootFromInclusionProof(
      proof.logIndex,
      proof.treeSize,
      leaf,
      proof.hashes.map((h) => Buffer.from(h, "hex")),
    );
    if (root.toString("hex") !== proof.rootHash) {
      return { valid: false, reason: "recomputed Merkle root does not match inclusion proof" };
    }

    const cp = parseCheckpoint(proof.checkpoint);
    if (!cp) return { valid: false, reason: "unparseable checkpoint" };
    if (cp.rootHashHex !== proof.rootHash) {
      return { valid: false, reason: "checkpoint root does not match inclusion proof" };
    }

    if (opts.requireCheckpointSignature !== false) {
      if (!verifyCheckpointSignature(proof.checkpoint, opts.rekorPublicKey ?? REKOR_PUBLIC_KEY_PEM)) {
        return { valid: false, reason: "checkpoint signature invalid" };
      }
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, reason: String(err) };
  }
}
