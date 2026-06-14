import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync, rmSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { initDatabase } from "../src/logging/schema.js";
import { AuditLog } from "../src/logging/audit-log.js";
import {
  loadOrCreateSigningKey,
  signArtifact,
  verifyArtifactSignature,
  chainHeadArtifact,
  verifyAnchorsAgainstChain,
  verifyAnchorInRekor,
  Anchorer,
  type SigningKey,
} from "../src/logging/anchor.js";
import {
  createHashedRekord,
  buildHashedRekord,
  verifyInclusionProofOffline,
  verifyCheckpointSignature,
  rootFromInclusionProof,
  rfc6962LeafHash,
  type RekorInclusionProof,
} from "../src/logging/rekor.js";

const fixtureEntry = Object.values(
  JSON.parse(readFileSync("tests/fixtures/rekor-entry.json", "utf-8")) as Record<string, any>,
)[0] as any;
const fixtureBody: string = fixtureEntry.body;
const fixtureProof: RekorInclusionProof = {
  logIndex: fixtureEntry.verification.inclusionProof.logIndex,
  rootHash: fixtureEntry.verification.inclusionProof.rootHash,
  treeSize: fixtureEntry.verification.inclusionProof.treeSize,
  hashes: fixtureEntry.verification.inclusionProof.hashes,
  checkpoint: fixtureEntry.verification.inclusionProof.checkpoint,
};

let keyPath: string;
let key: SigningKey;

beforeAll(() => {
  keyPath = join(tmpdir(), `aulite-test-key-${process.pid}.pem`);
  key = loadOrCreateSigningKey(keyPath);
});

afterAll(() => {
  if (existsSync(keyPath)) rmSync(keyPath);
});

function mockRekorFetch(uuid = "abc123", logIndex = 42, integratedTime = 1700000000): typeof fetch {
  return vi.fn(async (_url: string | URL, init?: RequestInit) => {
    let bodyB64 = "";
    try {
      bodyB64 = Buffer.from(String(init?.body), "utf-8").toString("base64");
    } catch {
      bodyB64 = "";
    }
    return {
      ok: true,
      status: 201,
      json: async () => ({ [uuid]: { logIndex, integratedTime, body: bodyB64 } }),
      text: async () => "",
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

function seed(auditLog: AuditLog, n: number): void {
  for (let i = 0; i < n; i++) {
    auditLog.append({
      requestBody: `request-${i}`,
      responseBody: `response-${i}`,
      provider: "openai",
      model: "gpt-4",
    });
  }
}

describe("signing primitives", () => {
  it("signs and verifies an artifact (ECDSA P-256)", () => {
    const artifact = chainHeadArtifact(3, "deadbeef");
    const { signatureB64, sha256Hex } = signArtifact(artifact, key);

    expect(signatureB64.length).toBeGreaterThan(0);
    expect(sha256Hex).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyArtifactSignature(artifact, signatureB64, key.publicKeyPem)).toBe(true);
  });

  it("rejects a signature over tampered content", () => {
    const { signatureB64 } = signArtifact(chainHeadArtifact(1, "aaaa"), key);
    expect(verifyArtifactSignature(chainHeadArtifact(1, "bbbb"), signatureB64, key.publicKeyPem)).toBe(false);
  });

  it("produces a deterministic, sequence-bound artifact", () => {
    expect(chainHeadArtifact(5, "abc")).toBe('{"entry_hash":"abc","sequence":5}');
    expect(chainHeadArtifact(5, "abc")).toBe(chainHeadArtifact(5, "abc"));
    expect(chainHeadArtifact(5, "abc")).not.toBe(chainHeadArtifact(6, "abc"));
  });

  it("persists and reuses the signing key", () => {
    const reloaded = loadOrCreateSigningKey(keyPath);
    expect(existsSync(keyPath)).toBe(true);
    expect(reloaded.publicKeyPem).toBe(key.publicKeyPem);
  });
});

describe("Rekor client", () => {
  it("builds a valid hashedrekord body", () => {
    const body = buildHashedRekord({ sha256Hex: "aa", signatureB64: "sig", publicKeyPem: "PEMDATA" });
    expect(body.kind).toBe("hashedrekord");
    const spec = body.spec as { data: { hash: { value: string } }; signature: { publicKey: { content: string } } };
    expect(spec.data.hash.value).toBe("aa");
    expect(spec.signature.publicKey.content).toBe(Buffer.from("PEMDATA", "utf-8").toString("base64"));
  });

  it("parses the created entry from a Rekor response", async () => {
    const entry = await createHashedRekord(
      { sha256Hex: "aa", signatureB64: "bb", publicKeyPem: "pem" },
      { fetchImpl: mockRekorFetch("u1", 7, 123) },
    );
    expect(entry.uuid).toBe("u1");
    expect(entry.logIndex).toBe(7);
    expect(entry.integratedTime).toBe(123);
    expect(entry.logUrl).toContain("/api/v1/log/entries/u1");
  });

  it("throws on a non-OK Rekor response", async () => {
    const fail = vi.fn(async () => ({ ok: false, status: 500, text: async () => "boom" }) as unknown as Response);
    await expect(createHashedRekord({ sha256Hex: "a", signatureB64: "b", publicKeyPem: "c" }, { fetchImpl: fail })).rejects.toThrow(/500/);
  });
});

describe("Anchorer", () => {
  let db: Database.Database;
  let auditLog: AuditLog;

  beforeEach(() => {
    db = initDatabase(":memory:");
    auditLog = new AuditLog(db);
  });

  afterEach(() => {
    db.close();
    vi.restoreAllMocks();
  });

  it("anchors the chain head and stores the Rekor reference", async () => {
    seed(auditLog, 3);
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: mockRekorFetch("u2", 99) });

    const rec = await anchorer.anchorNow();
    expect(rec).not.toBeNull();
    expect(rec!.status).toBe("anchored");
    expect(rec!.anchoredSequence).toBe(3);
    expect(rec!.rekorLogIndex).toBe(99);
    expect(rec!.rekorUuid).toBe("u2");
  });

  it("verifies a clean anchored chain", async () => {
    seed(auditLog, 3);
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: mockRekorFetch() });
    await anchorer.anchorNow();

    const result = verifyAnchorsAgainstChain(db);
    expect(result.valid).toBe(true);
    expect(result.anchorsChecked).toBe(1);
    expect(result.problems).toEqual([]);
  });

  it("detects a chain rewrite after anchoring", async () => {
    seed(auditLog, 3);
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: mockRekorFetch() });
    await anchorer.anchorNow();

    db.prepare("UPDATE audit_entries SET entry_hash = 'REWRITTEN' WHERE sequence = 3").run();

    const result = verifyAnchorsAgainstChain(db);
    expect(result.valid).toBe(false);
    expect(result.problems[0]).toContain("rewritten");
  });

  it("returns null for an empty chain", async () => {
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: mockRekorFetch() });
    expect(await anchorer.anchorNow()).toBeNull();
  });

  it("does not double-anchor the same sequence", async () => {
    seed(auditLog, 2);
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: mockRekorFetch() });
    expect(await anchorer.anchorNow()).not.toBeNull();
    expect(await anchorer.anchorNow()).toBeNull();
    expect(anchorer.list().length).toBe(1);
  });

  it("keeps a locally-signed checkpoint even when Rekor is unreachable", async () => {
    seed(auditLog, 2);
    const fail = vi.fn(async () => ({ ok: false, status: 503, text: async () => "down" }) as unknown as Response);
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: fail });

    const rec = await anchorer.anchorNow();
    expect(rec!.status).toBe("failed");
    expect(verifyArtifactSignature(rec!.artifact, rec!.signature, rec!.publicKey)).toBe(true);
    expect(verifyAnchorsAgainstChain(db).anchorsChecked).toBe(0);
  });

  it("confirms an anchor against the public Rekor log", async () => {
    seed(auditLog, 2);
    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: mockRekorFetch("u3", 5) });
    const rec = await anchorer.anchorNow();

    const getFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        u3: {
          logIndex: 5,
          integratedTime: 1,
          body: Buffer.from(
            JSON.stringify(buildHashedRekord({ sha256Hex: rec!.artifactSha256, signatureB64: "x", publicKeyPem: "y" })),
            "utf-8",
          ).toString("base64"),
        },
      }),
      text: async () => "",
    }) as unknown as Response);

    expect(await verifyAnchorInRekor(rec!, { fetchImpl: getFetch })).toBe(true);
  });
});

describe("offline inclusion verification", () => {
  it("verifies a real Rekor inclusion proof end-to-end (golden fixture)", () => {
    expect(verifyInclusionProofOffline(fixtureBody, fixtureProof).valid).toBe(true);
  });

  it("verifies the checkpoint signature against the pinned Rekor key", () => {
    expect(verifyCheckpointSignature(fixtureProof.checkpoint)).toBe(true);
    expect(verifyCheckpointSignature("X" + fixtureProof.checkpoint.slice(1))).toBe(false);
  });

  it("rejects a tampered inclusion proof", () => {
    const bad: RekorInclusionProof = { ...fixtureProof, hashes: [...fixtureProof.hashes] };
    bad.hashes[0] = "00".repeat(32);
    expect(verifyInclusionProofOffline(fixtureBody, bad).valid).toBe(false);
  });

  it("computes the RFC 6962 root for a single-leaf tree", () => {
    const leaf = rfc6962LeafHash(Buffer.from("hello"));
    expect(rootFromInclusionProof(0, 1, leaf, []).equals(leaf)).toBe(true);
  });

  it("computes the RFC 6962 root for a two-leaf tree", () => {
    const l0 = rfc6962LeafHash(Buffer.from("a"));
    const l1 = rfc6962LeafHash(Buffer.from("b"));
    const expected = createHash("sha256").update(Buffer.concat([Buffer.from([1]), l0, l1])).digest();
    expect(rootFromInclusionProof(0, 2, l0, [l1]).equals(expected)).toBe(true);
    expect(rootFromInclusionProof(1, 2, l1, [l0]).equals(expected)).toBe(true);
  });
});

describe("anchor inclusion binding", () => {
  let db: Database.Database;
  let auditLog: AuditLog;

  beforeEach(() => {
    db = initDatabase(":memory:");
    auditLog = new AuditLog(db);
  });

  afterEach(() => {
    db.close();
    vi.restoreAllMocks();
  });

  it("flags an anchor whose Rekor entry attests a different hash", async () => {
    seed(auditLog, 2);
    const fetchFixture = vi.fn(async () => ({
      ok: true,
      status: 201,
      json: async () => ({
        uX: {
          logIndex: 1,
          integratedTime: 1,
          body: fixtureBody,
          verification: { inclusionProof: fixtureProof, signedEntryTimestamp: "x" },
        },
      }),
      text: async () => "",
    }) as unknown as Response);

    const anchorer = new Anchorer(db, auditLog, key, { fetchImpl: fetchFixture });
    await anchorer.anchorNow();

    const result = verifyAnchorsAgainstChain(db);
    expect(result.inclusionChecked).toBe(1);
    expect(result.valid).toBe(false);
    expect(result.problems.some((p) => p.includes("does not attest"))).toBe(true);
  });
});
