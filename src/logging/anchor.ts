import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
  type KeyObject,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import type Database from "better-sqlite3";
import { v4 as uuidv4 } from "uuid";
import type { AuditLog } from "./audit-log.js";
import {
  createHashedRekord,
  getRekorEntry,
  extractHashFromBody,
  verifyInclusionProofOffline,
  type RekorInclusionProof,
  type RekorOptions,
} from "./rekor.js";
import { logger } from "../utils/logger.js";

export const DEFAULT_KEY_PATH = "./aulite-signing-key.pem";

export interface SigningKey {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyPem: string;
}

export interface AnchorRecord {
  id: string;
  createdAt: string;
  anchoredSequence: number;
  chainHeadHash: string;
  artifact: string;
  artifactSha256: string;
  signature: string;
  publicKey: string;
  rekorUuid: string | null;
  rekorLogIndex: number | null;
  rekorIntegratedTime: number | null;
  rekorLogUrl: string | null;
  rekorBody: string | null;
  inclusionProof: RekorInclusionProof | null;
  signedEntryTimestamp: string | null;
  status: "pending" | "anchored" | "failed";
}

export interface AnchorVerifyResult {
  valid: boolean;
  anchorsChecked: number;
  inclusionChecked: number;
  inclusionValid: number;
  problems: string[];
}

interface AnchorRow {
  id: string;
  created_at: string;
  anchored_sequence: number;
  chain_head_hash: string;
  artifact: string;
  artifact_sha256: string;
  signature: string;
  public_key: string;
  rekor_uuid: string | null;
  rekor_log_index: number | null;
  rekor_integrated_time: number | null;
  rekor_log_url: string | null;
  rekor_body: string | null;
  inclusion_proof_json: string | null;
  signed_entry_timestamp: string | null;
  status: AnchorRecord["status"];
}

function parseInclusionProof(json: string | null): RekorInclusionProof | null {
  if (!json) return null;
  try {
    return JSON.parse(json) as RekorInclusionProof;
  } catch {
    return null;
  }
}

function rowToRecord(r: AnchorRow): AnchorRecord {
  return {
    id: r.id,
    createdAt: r.created_at,
    anchoredSequence: r.anchored_sequence,
    chainHeadHash: r.chain_head_hash,
    artifact: r.artifact,
    artifactSha256: r.artifact_sha256,
    signature: r.signature,
    publicKey: r.public_key,
    rekorUuid: r.rekor_uuid,
    rekorLogIndex: r.rekor_log_index,
    rekorIntegratedTime: r.rekor_integrated_time,
    rekorLogUrl: r.rekor_log_url,
    rekorBody: r.rekor_body,
    inclusionProof: parseInclusionProof(r.inclusion_proof_json),
    signedEntryTimestamp: r.signed_entry_timestamp,
    status: r.status,
  };
}

export function loadOrCreateSigningKey(path = DEFAULT_KEY_PATH): SigningKey {
  if (existsSync(path)) {
    const privateKey = createPrivateKey(readFileSync(path, "utf-8"));
    const publicKey = createPublicKey(privateKey);
    return { privateKey, publicKey, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }) as string };
  }

  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }) as string, { mode: 0o600 });
  logger.info("Generated audit signing key", { path });
  return { privateKey, publicKey, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }) as string };
}

export function chainHeadArtifact(sequence: number, entryHash: string): string {
  return JSON.stringify({ entry_hash: entryHash, sequence });
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

export function signArtifact(artifact: string, key: SigningKey): { signatureB64: string; sha256Hex: string } {
  const data = Buffer.from(artifact, "utf-8");
  const signature = cryptoSign("sha256", data, key.privateKey);
  return { signatureB64: signature.toString("base64"), sha256Hex: sha256Hex(artifact) };
}

export function verifyArtifactSignature(artifact: string, signatureB64: string, publicKeyPem: string): boolean {
  try {
    const data = Buffer.from(artifact, "utf-8");
    const pub = createPublicKey(publicKeyPem);
    return cryptoVerify("sha256", data, pub, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

export function verifyAnchorsAgainstChain(db: Database.Database): AnchorVerifyResult {
  const rows = db
    .prepare("SELECT * FROM anchors WHERE status != 'failed' ORDER BY anchored_sequence ASC")
    .all() as AnchorRow[];

  const problems: string[] = [];
  let inclusionChecked = 0;
  let inclusionValid = 0;

  for (const r of rows) {
    const seq = r.anchored_sequence;

    if (!verifyArtifactSignature(r.artifact, r.signature, r.public_key)) {
      problems.push(`anchor seq=${seq}: signature invalid`);
      continue;
    }

    if (sha256Hex(r.artifact) !== r.artifact_sha256) {
      problems.push(`anchor seq=${seq}: artifact hash mismatch`);
    }

    const entry = db.prepare("SELECT entry_hash FROM audit_entries WHERE sequence = ?").get(seq) as
      | { entry_hash: string }
      | undefined;

    if (!entry) {
      problems.push(`anchor seq=${seq}: no audit entry at this sequence (chain truncated?)`);
      continue;
    }

    const expected = chainHeadArtifact(seq, entry.entry_hash);
    if (expected !== r.artifact) {
      problems.push(`anchor seq=${seq}: chain head was rewritten after anchoring (anchored hash != current entry_hash)`);
    }

    const proof = parseInclusionProof(r.inclusion_proof_json);
    if (proof && r.rekor_body) {
      inclusionChecked++;
      const result = verifyInclusionProofOffline(r.rekor_body, proof);
      const bound = extractHashFromBody(r.rekor_body) === r.artifact_sha256;
      if (result.valid && bound) {
        inclusionValid++;
      } else {
        const reason = !result.valid ? result.reason : "Rekor entry does not attest this anchor's hash";
        problems.push(`anchor seq=${seq}: Rekor inclusion proof invalid (${reason})`);
      }
    }
  }

  return {
    valid: problems.length === 0,
    anchorsChecked: rows.length,
    inclusionChecked,
    inclusionValid,
    problems,
  };
}

export async function verifyAnchorInRekor(anchor: AnchorRecord, opts: RekorOptions = {}): Promise<boolean> {
  if (!anchor.rekorUuid) return false;
  try {
    const entry = await getRekorEntry(anchor.rekorUuid, opts);
    const loggedHash = extractHashFromBody(entry.body);
    return loggedHash === anchor.artifactSha256;
  } catch {
    return false;
  }
}

export async function verifyAllAnchorsInRekor(
  db: Database.Database,
  opts: RekorOptions = {},
): Promise<{ checked: number; confirmed: number; results: { sequence: number; logIndex: number | null; ok: boolean }[] }> {
  const rows = db
    .prepare("SELECT * FROM anchors WHERE status = 'anchored' ORDER BY anchored_sequence ASC")
    .all() as AnchorRow[];

  const results: { sequence: number; logIndex: number | null; ok: boolean }[] = [];
  for (const r of rows) {
    const ok = await verifyAnchorInRekor(rowToRecord(r), opts);
    results.push({ sequence: r.anchored_sequence, logIndex: r.rekor_log_index, ok });
  }
  return { checked: rows.length, confirmed: results.filter((x) => x.ok).length, results };
}

export interface AnchorerOptions extends RekorOptions {}

export class Anchorer {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private db: Database.Database,
    private auditLog: AuditLog,
    private key: SigningKey,
    private opts: AnchorerOptions = {},
  ) {}

  async anchorNow(): Promise<AnchorRecord | null> {
    const head = this.auditLog.getChainHead();
    if (!head.sequence || head.sequence < 1) return null;

    const existing = this.db
      .prepare("SELECT id FROM anchors WHERE anchored_sequence = ? AND status != 'failed'")
      .get(head.sequence);
    if (existing) return null;

    const artifact = chainHeadArtifact(head.sequence, head.hash);
    const { signatureB64, sha256Hex: hashHex } = signArtifact(artifact, this.key);
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    this.db
      .prepare(
        `INSERT INTO anchors (id, created_at, anchored_sequence, chain_head_hash, artifact, artifact_sha256, signature, public_key, status)
         VALUES (@id, @createdAt, @seq, @hash, @artifact, @sha, @sig, @pub, 'pending')`,
      )
      .run({ id, createdAt, seq: head.sequence, hash: head.hash, artifact, sha: hashHex, sig: signatureB64, pub: this.key.publicKeyPem });

    try {
      const entry = await createHashedRekord(
        { sha256Hex: hashHex, signatureB64, publicKeyPem: this.key.publicKeyPem },
        this.opts,
      );
      this.db
        .prepare(
          `UPDATE anchors SET rekor_uuid=@uuid, rekor_log_index=@idx, rekor_integrated_time=@t, rekor_log_url=@url,
             rekor_body=@body, inclusion_proof_json=@ip, signed_entry_timestamp=@set, status='anchored' WHERE id=@id`,
        )
        .run({
          uuid: entry.uuid,
          idx: entry.logIndex,
          t: entry.integratedTime,
          url: entry.logUrl,
          body: entry.body || null,
          ip: entry.inclusionProof ? JSON.stringify(entry.inclusionProof) : null,
          set: entry.signedEntryTimestamp ?? null,
          id,
        });
      logger.info("Audit chain anchored to Rekor", { sequence: head.sequence, logIndex: entry.logIndex });
    } catch (err) {
      this.db.prepare("UPDATE anchors SET status='failed' WHERE id=@id").run({ id });
      logger.warn("Rekor anchoring failed (checkpoint signed locally, will retry)", {
        error: String(err),
        sequence: head.sequence,
      });
    }

    return this.get(id);
  }

  start(intervalMs: number): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.anchorNow().catch((err) => logger.error("Anchor tick failed", { error: String(err) }));
    }, intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  get(id: string): AnchorRecord | null {
    const row = this.db.prepare("SELECT * FROM anchors WHERE id = ?").get(id) as AnchorRow | undefined;
    return row ? rowToRecord(row) : null;
  }

  list(): AnchorRecord[] {
    const rows = this.db.prepare("SELECT * FROM anchors ORDER BY anchored_sequence ASC").all() as AnchorRow[];
    return rows.map(rowToRecord);
  }
}
