import type Database from "better-sqlite3";
import { createDoc, header, sectionTitle, paragraph, keyValue, table, footer } from "./pdf.js";
import { getOverviewStats, getTopCategories, getTopArticleViolations, getTimeSeries, getProviderStats, type DateRange } from "./stats.js";
import { listAnchors, verifyAnchorsAgainstChain } from "../logging/anchor.js";

/**
 * Generate an EU AI Act Art. 12 Compliance Audit Report.
 * Provides evidence of continuous monitoring and record-keeping.
 */
export function generateAuditReport(db: Database.Database, range: DateRange): PDFKit.PDFDocument {
  const overview = getOverviewStats(db, range);
  const topCategories = getTopCategories(db, range, 15);
  const topArticles = getTopArticleViolations(db, range, 15);
  const timeSeries = getTimeSeries(db, range);
  const providers = getProviderStats(db, range);

  const doc = createDoc();

  header(
    doc,
    "EU AI Act Compliance Audit Report",
    `Regulation (EU) 2024/1689 — Art. 12 Record-Keeping | Period: ${range.from} to ${range.to}`,
  );

  paragraph(doc,
    "This report provides evidence of continuous automated monitoring of AI system interactions " +
    "in accordance with Art. 12 of the EU AI Act (Regulation 2024/1689). All entries are stored " +
    "in a tamper-evident, hash-chained audit trail (SHA-256).",
  );

  sectionTitle(doc, "1. Monitoring Overview");

  keyValue(doc, "Report Period", `${range.from} — ${range.to}`);
  keyValue(doc, "Total Requests Monitored", overview.totalRequests);
  keyValue(doc, "Requests with Compliance Flags", overview.flaggedRequests);
  keyValue(doc, "Requests Blocked (Enforcing Mode)", overview.blockedRequests);
  keyValue(doc, "Clean Requests", overview.passedRequests);
  keyValue(doc, "Average Risk Score", `${overview.avgRiskScore} / 10`);
  keyValue(doc, "Maximum Risk Score", `${overview.maxRiskScore} / 10`);
  doc.moveDown(0.5);

  const mitigationRate = overview.totalRequests > 0
    ? Math.round((overview.flaggedRequests / overview.totalRequests) * 100)
    : 0;
  keyValue(doc, "Detection Rate", `${mitigationRate}% of requests flagged for review`);

  sectionTitle(doc, "2. Risk Distribution (Art. 9 — Risk Management)");

  const riskRows = Object.entries(overview.riskDistribution)
    .sort(([, a], [, b]) => b - a)
    .map(([level, count]) => {
      const pct = overview.totalRequests > 0
        ? Math.round((count / overview.totalRequests) * 100)
        : 0;
      return [level.toUpperCase(), String(count), `${pct}%`];
    });

  if (riskRows.length > 0) {
    table(doc, ["Risk Level", "Count", "Percentage"], riskRows, [160, 160, 160]);
  } else {
    paragraph(doc, "No requests recorded in this period.");
  }

  sectionTitle(doc, "3. Top Violation Categories");

  if (topCategories.length > 0) {
    const catRows = topCategories.map((c) => [
      c.category,
      String(c.count),
      String(c.avgScore),
      c.articleRef ?? "—",
    ]);
    table(doc, ["Category", "Occurrences", "Avg Score", "Article Reference"], catRows, [130, 80, 70, 215]);
  } else {
    paragraph(doc, "No violations detected in this period.");
  }

  sectionTitle(doc, "4. EU AI Act Article Violations");
  paragraph(doc,
    "Breakdown of detected compliance risks mapped to specific articles of the EU AI Act, " +
    "EU anti-discrimination directives, and GDPR.",
  );

  if (topArticles.length > 0) {
    const artRows = topArticles.map((a) => [
      a.articleRef,
      String(a.count),
      String(a.avgScore),
    ]);
    table(doc, ["Article / Directive", "Occurrences", "Avg Score"], artRows, [280, 110, 105]);
  } else {
    paragraph(doc, "No article-specific violations detected.");
  }

  sectionTitle(doc, "5. Monitoring Activity Timeline");

  if (timeSeries.length > 0) {
    const tsRows = timeSeries.slice(-30).map((t) => [
      t.period,
      String(t.totalRequests),
      String(t.flaggedRequests),
      String(t.avgRiskScore),
    ]);
    table(doc, ["Period", "Total", "Flagged", "Avg Score"], tsRows, [160, 100, 100, 135]);
  } else {
    paragraph(doc, "No activity recorded.");
  }

  sectionTitle(doc, "6. AI Provider & Model Usage");

  if (providers.length > 0) {
    const provRows = providers.map((p) => [
      p.provider,
      p.model ?? "—",
      String(p.count),
      String(p.avgRiskScore),
    ]);
    table(doc, ["Provider", "Model", "Requests", "Avg Score"], provRows, [120, 160, 80, 135]);
  } else {
    paragraph(doc, "No provider data recorded.");
  }

  sectionTitle(doc, "7. Audit Trail Integrity (Art. 12 Compliance)");
  paragraph(doc,
    "All audit entries are stored with SHA-256 hash chain verification. Each entry contains " +
    "the hash of the previous entry, creating a tamper-evident chain of custody. The integrity " +
    "of the complete audit trail can be verified at any time via the /verify endpoint.",
  );
  keyValue(doc, "Hash Algorithm", "SHA-256");
  keyValue(doc, "Storage Format", "Append-only SQLite with WAL mode");
  keyValue(doc, "Retention Policy", "Per Art. 26(6): minimum 6 months; Art. 11: technical docs 10 years");

  sectionTitle(doc, "8. External Transparency-Log Anchoring");

  const anchors = listAnchors(db).filter((a) => a.status === "anchored");
  if (anchors.length > 0) {
    const latest = anchors[anchors.length - 1];
    const anchorCheck = verifyAnchorsAgainstChain(db);
    paragraph(doc,
      "The audit chain head is periodically anchored to the Sigstore Rekor public transparency log, " +
      "operated by the Linux Foundation. Once published, a Rekor entry is immutable and cannot be " +
      "removed, providing independent third-party evidence that the chain was not rewritten after the " +
      "fact. Anchors are verifiable by any party against public infrastructure, without trusting the " +
      "system operator or Aulite.",
    );
    keyValue(doc, "Transparency Log", "Sigstore Rekor (rekor.sigstore.dev)");
    keyValue(doc, "Anchors Published", anchors.length);
    keyValue(doc, "Latest Anchor — Chain Sequence", latest.anchoredSequence);
    keyValue(doc, "Latest Anchor — Rekor Log Index", latest.rekorLogIndex ?? "—");
    if (latest.rekorLogIndex != null) {
      keyValue(doc, "Independent Verification", `https://search.sigstore.dev/?logIndex=${latest.rekorLogIndex}`);
    }
    const incOk = anchorCheck.inclusionChecked > 0 && anchorCheck.inclusionValid === anchorCheck.inclusionChecked;
    const incLabel = anchorCheck.inclusionChecked === 0
      ? "Pending (anchors created before offline-proof support)"
      : `${incOk ? "Verified" : "FAILED"} (${anchorCheck.inclusionValid}/${anchorCheck.inclusionChecked} offline)`;
    keyValue(doc, "Offline Inclusion Proof", incLabel);
  } else {
    paragraph(doc,
      "External transparency-log anchoring (Sigstore Rekor) is supported but not enabled for this " +
      "deployment. When enabled, chain-head snapshots are published to a public append-only log, " +
      "adding independent tamper-evidence verifiable without trusting the operator.",
    );
  }

  footer(doc, `Generated by Aulite — EU AI Act Compliance Proxy | ${new Date().toISOString()}`);

  doc.end();
  return doc;
}
