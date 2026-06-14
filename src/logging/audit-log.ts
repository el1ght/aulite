import type Database from "better-sqlite3";
import { v4 as uuidv4 } from "uuid";
import { hashAuditEntry } from "../utils/hash.js";
import { logger } from "../utils/logger.js";

export interface AuditEntry {
  requestBody: string;
  responseBody: string | null;
  provider: string;
  model: string | null;
  riskScore?: number;
  riskLevel?: string;
  actionTaken?: string;
  checksJson?: string;
  domains?: string[];
  clientId?: string;
  metadata?: string;
}

interface ParsedCheck {
  check: string;
  riskScore: number;
  details: string;
  flaggedContent?: string;
  articleRef?: string;
}

export class AuditLog {
  private db: Database.Database;
  private insertStmt: Database.Statement;
  private insertCheckStmt: Database.Statement;
  private lastHash: string;
  private lastSequence: number;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = db.prepare(`
      INSERT INTO audit_entries (
        id, sequence, timestamp, prev_hash, entry_hash,
        request_body, response_body, provider, model,
        risk_score, risk_level, action_taken, checks_json, domains,
        client_id, metadata
      ) VALUES (
        @id, @sequence, @timestamp, @prevHash, @entryHash,
        @requestBody, @responseBody, @provider, @model,
        @riskScore, @riskLevel, @actionTaken, @checksJson, @domains,
        @clientId, @metadata
      )
    `);

    this.insertCheckStmt = db.prepare(`
      INSERT INTO check_details (audit_entry_id, check_type, category, risk_score, article_ref, flagged_content)
      VALUES (@auditEntryId, @checkType, @category, @riskScore, @articleRef, @flaggedContent)
    `);

    const last = db
      .prepare("SELECT sequence, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1")
      .get() as { sequence: number; entry_hash: string } | undefined;

    this.lastHash = last?.entry_hash ?? "0";
    this.lastSequence = last?.sequence ?? 0;
  }

  append(entry: AuditEntry): string {
    const id = uuidv4();
    const sequence = this.lastSequence + 1;
    const timestamp = new Date().toISOString();
    const prevHash = this.lastHash;
    const domainsJson = JSON.stringify(entry.domains ?? []);

    const entryHash = hashAuditEntry({
      id,
      sequence,
      timestamp,
      prevHash,
      requestBody: entry.requestBody,
      responseBody: entry.responseBody,
      provider: entry.provider,
      model: entry.model,
      riskScore: entry.riskScore ?? 0,
      riskLevel: entry.riskLevel ?? "none",
      actionTaken: entry.actionTaken ?? "pass",
      checksJson: entry.checksJson ?? "[]",
    });

    const insertAll = this.db.transaction(() => {
      this.insertStmt.run({
        id,
        sequence,
        timestamp,
        prevHash,
        entryHash,
        requestBody: entry.requestBody,
        responseBody: entry.responseBody ?? null,
        provider: entry.provider,
        model: entry.model ?? null,
        riskScore: entry.riskScore ?? 0,
        riskLevel: entry.riskLevel ?? "none",
        actionTaken: entry.actionTaken ?? "pass",
        checksJson: entry.checksJson ?? "[]",
        domains: domainsJson,
        clientId: entry.clientId ?? null,
        metadata: entry.metadata ?? null,
      });

      if (entry.checksJson && entry.checksJson !== "[]") {
        try {
          const checks: ParsedCheck[] = JSON.parse(entry.checksJson);
          for (const check of checks) {
            const categoryMatch = check.details?.match(/^\[([^\]]+)\]/);
            const category = categoryMatch?.[1] ?? check.check;

            this.insertCheckStmt.run({
              auditEntryId: id,
              checkType: check.check,
              category,
              riskScore: check.riskScore,
              articleRef: check.articleRef ?? null,
              flaggedContent: check.flaggedContent ?? null,
            });
          }
        } catch {
          // Malformed checks_json — skip detail insertion
        }
      }
    });

    insertAll();

    this.lastHash = entryHash;
    this.lastSequence = sequence;

    logger.debug("Audit entry written", { id, sequence });
    return id;
  }

  verify(): { valid: boolean; brokenAt?: number; entriesChecked: number } {
    const iter = this.db
      .prepare(
        `SELECT id, sequence, timestamp, prev_hash, entry_hash,
                request_body, response_body, provider, model,
                risk_score, risk_level, action_taken, checks_json
         FROM audit_entries ORDER BY sequence ASC`,
      )
      .iterate() as Iterable<Record<string, unknown>>;

    let expectedPrevHash = "0";
    let count = 0;

    for (const row of iter) {
      count++;

      if (row.prev_hash !== expectedPrevHash) {
        return { valid: false, brokenAt: row.sequence as number, entriesChecked: count };
      }

      const computed = hashAuditEntry({
        id: row.id,
        sequence: row.sequence,
        timestamp: row.timestamp,
        prevHash: row.prev_hash,
        requestBody: row.request_body,
        responseBody: row.response_body,
        provider: row.provider,
        model: row.model,
        riskScore: row.risk_score,
        riskLevel: row.risk_level,
        actionTaken: row.action_taken,
        checksJson: row.checks_json,
      });

      if (computed !== row.entry_hash) {
        return { valid: false, brokenAt: row.sequence as number, entriesChecked: count };
      }

      expectedPrevHash = row.entry_hash as string;
    }

    return { valid: true, entriesChecked: count };
  }

  getStats(): { total: number; lastSequence: number } {
    const row = this.db
      .prepare("SELECT COUNT(*) as total FROM audit_entries")
      .get() as { total: number };
    return { total: row.total, lastSequence: this.lastSequence };
  }

  getChainHead(): { sequence: number; hash: string } {
    return { sequence: this.lastSequence, hash: this.lastHash };
  }

  getDatabase(): Database.Database {
    return this.db;
  }
}
