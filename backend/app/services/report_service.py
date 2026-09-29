from datetime import datetime
from sqlalchemy.orm import Session
from app.models.investigation import Investigation, InvestigationRound
from app.models.evidence import EvidenceArtifact, ProvenanceRecord
from app.models.execution import CorrelationMatch, EscalationAction
from app.models.timeline import TimelineEvent
from app.models.machine import Machine
from app.utils.datetime_utils import to_iso_utc

class ReportService:
    @staticmethod
    def generate_report(db: Session, investigation_id: str) -> dict:
        """Generate comprehensive Markdown and HTML digital forensic reports."""
        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")

        machine = db.query(Machine).filter(Machine.id == inv.machine_id).first()
        rounds = db.query(InvestigationRound).filter(
            InvestigationRound.investigation_id == investigation_id
        ).order_by(InvestigationRound.round_number.asc()).all()

        artifacts = db.query(EvidenceArtifact).filter(
            EvidenceArtifact.investigation_id == investigation_id
        ).order_by(EvidenceArtifact.round_number.asc(), EvidenceArtifact.collected_at.asc()).all()

        correlations = db.query(CorrelationMatch).filter(
            CorrelationMatch.investigation_id == investigation_id
        ).all()

        escalations = db.query(EscalationAction).filter(
            EscalationAction.investigation_id == investigation_id
        ).all()

        timeline = db.query(TimelineEvent).filter(
            TimelineEvent.investigation_id == investigation_id
        ).order_by(TimelineEvent.timestamp.asc()).all()

        # Deduplicate correlations by rule_name to display unique findings cleanly
        seen_rules = set()
        unique_correlations = []
        for c in correlations:
            if c.rule_name not in seen_rules:
                seen_rules.add(c.rule_name)
                unique_correlations.append(c)

        # Build Markdown
        md_lines = [
            f"# JOCKY FORENSIC INVESTIGATION REPORT",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"",
            f"> **FORENSIC NOTICE**: Observed Evidence represents raw empirical system state captured through read-only OS instrumentation. Correlation / Rule Matches represent heuristic indicators that guided automated adaptive escalation. A rule match provides investigative leads and does not constitute absolute proof of malicious intent.",
            f"",
            f"---",
            f"## INVESTIGATION METADATA",
            f"- **Investigation ID:** `{inv.id}`",
            f"- **Primary Intent:** `{inv.intent}`",
            f"- **Investigation Status:** `{inv.status}`",
            f"- **Target Machine:** `{machine.id if machine else 'N/A'}` ({machine.hostname if machine else 'N/A'} - {machine.os_name if machine else 'N/A'})",
            f"- **Start Time:** `{to_iso_utc(inv.start_time)}`",
            f"- **End Time:** `{to_iso_utc(inv.end_time) if inv.end_time else 'In Progress'}`",
            f"- **Total Rounds:** `{len(rounds)}`",
            f"- **Total Artifacts:** `{len(artifacts)}`",
            f"- **Correlation Matches:** `{len(unique_correlations)}`",
            f"",
            f"---",
            f"## 1. EXECUTIVE SUMMARY",
            f"An intent-driven forensic triage was initiated under the objective **`{inv.intent}`**.",
            f"The JOCKY framework compiled this objective into an initial evidence requirement graph, executed read-only system collectors, and evaluated correlation rules.",
        ]

        if unique_correlations:
            md_lines.append(f"During correlation analysis, **{len(unique_correlations)} investigation indicator(s)** were identified, triggering dynamic adaptive escalation into subsequent investigative rounds.")
        else:
            md_lines.append("No anomalous indicators were matched during correlation; the investigation concluded within the initial collection scope.")

        # Rounds breakdown
        md_lines.extend([
            f"",
            f"---",
            f"## 2. MULTI-ROUND ADAPTIVE EXECUTION BREAKDOWN",
        ])

        for r in rounds:
            md_lines.append(f"### Round {r.round_number} (Status: {r.status})")
            md_lines.append(f"- **Trigger Reason:** {r.trigger_reason}")
            r_arts = [a for a in artifacts if a.round_number == r.round_number]
            md_lines.append(f"- **Artifacts Collected ({len(r_arts)}):**")
            for a in r_arts:
                md_lines.append(f"  - `{a.name}` (`{a.operation}`) | SHA-256: `{a.sha256}` | Status: `{a.integrity_status}`")
            md_lines.append("")

        # Correlation Results
        md_lines.extend([
            f"---",
            f"## 3. CORRELATION RESULTS & HEURISTIC INDICATORS",
            f"*Note: These items represent rule-based triggers evaluated against observed evidence, not absolute proof of malicious intent.*",
            f""
        ])
        if unique_correlations:
            for c in unique_correlations:
                md_lines.append(f"- **Rule:** `{c.rule_name}`")
                md_lines.append(f"  - **Detected in Round:** {c.round_number}")
                md_lines.append(f"  - **Status Label:** `{c.status_label}`")
                md_lines.append(f"  - **Confidence:** `{c.confidence}`")
                md_lines.append(f"  - **Description:** {c.description}")
        else:
            md_lines.append("No correlation rules triggered.")

        # Adaptive Escalations
        md_lines.extend([
            f"",
            f"---",
            f"## 4. ADAPTIVE ESCALATION ACTIONS",
        ])
        if escalations:
            for esc in escalations:
                md_lines.append(f"- **Triggered by Rule:** `{esc.trigger_rule}`")
                md_lines.append(f"  - **New Operations Added:** `{esc.new_operations}`")
                md_lines.append(f"  - **Status:** `{esc.status}`")
        else:
            md_lines.append("No adaptive escalations triggered.")

        # Timeline Highlights
        md_lines.extend([
            f"",
            f"---",
            f"## 5. NORMALIZED FORENSIC TIMELINE (TOP 20 EVENTS)",
        ])
        for ev in timeline[:20]:
            md_lines.append(f"- **[{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S')}]** `[{ev.source}]` **{ev.event_type}**: {ev.description}")

        # Provenance and Integrity
        md_lines.extend([
            f"",
            f"---",
            f"## 6. EVIDENCE PROVENANCE & CRYPTOGRAPHIC INTEGRITY",
            f"| Artifact ID | File Name | Collector | Round | SHA-256 | Integrity |",
            f"|---|---|---|---|---|---|"
        ])
        for a in artifacts:
            md_lines.append(f"| `{a.id}` | `{a.name}` | `{a.collector}` | {a.round_number} | `{a.sha256[:16]}...` | `{a.integrity_status}` |")

        md_content = "\n".join(md_lines)

        # Structured JSON Representation
        report_json = {
            "investigation_id": inv.id,
            "intent": inv.intent,
            "status": inv.status,
            "machine": {
                "id": machine.id if machine else "N/A",
                "hostname": machine.hostname if machine else "N/A",
                "os": machine.os_name if machine else "N/A"
            },
            "start_time": to_iso_utc(inv.start_time),
            "end_time": to_iso_utc(inv.end_time),
            "rounds_executed": len(rounds),
            "collectors_executed": list({a.operation for a in artifacts}),
            "correlation_rules_triggered": [
                {
                    "rule_name": c.rule_name,
                    "round_number": c.round_number,
                    "status_label": c.status_label,
                    "confidence": c.confidence,
                    "description": c.description
                }
                for c in unique_correlations
            ],
            "escalation_history": [
                {
                    "trigger_rule": esc.trigger_rule,
                    "new_operations": esc.new_operations,
                    "status": esc.status
                }
                for esc in escalations
            ],
            "evidence_summary": [
                {
                    "id": a.id,
                    "name": a.name,
                    "operation": a.operation,
                    "round": a.round_number,
                    "sha256": a.sha256,
                    "integrity_status": a.integrity_status,
                    "file_size_bytes": a.file_size_bytes
                }
                for a in artifacts
            ],
            "timeline": [
                {
                    "timestamp": ev.timestamp.isoformat(),
                    "source": ev.source,
                    "event_type": ev.event_type,
                    "description": ev.description
                }
                for ev in timeline[:50]
            ],
            "disclaimer": "Observed evidence represents empirical endpoint state. Correlation rules represent heuristic triggers that guided adaptive escalation."
        }

        # Professional HTML representation
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>JOCKY Forensic Report - {inv.id}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; line-height: 1.6; color: #1e293b; max-width: 960px; margin: 30px auto; padding: 0 24px; background: #f8fafc; }}
  .header {{ background: #0f172a; color: #f8fafc; padding: 24px 30px; border-radius: 8px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0 0 6px 0; font-size: 24px; color: #38bdf8; }}
  .header .meta {{ font-size: 13px; color: #94a3b8; display: flex; gap: 20px; flex-wrap: wrap; }}
  .notice {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 14px 18px; margin: 20px 0; font-size: 13px; color: #1e3a8a; border-radius: 4px; }}
  h2 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-top: 32px; font-size: 18px; }}
  h3 {{ color: #1e293b; font-size: 15px; margin-top: 20px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
  th, td {{ border: 1px solid #e2e8f0; padding: 10px 14px; text-align: left; font-size: 13px; }}
  th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; color: #0284c7; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .badge-valid {{ background: #dcfce7; color: #166534; }}
  .badge-warn {{ background: #fef3c7; color: #92400e; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px; margin-bottom: 14px; }}
  @media print {{ body {{ max-width: 100%; margin: 0; background: #fff; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>JOCKY Forensic Investigation Report</h1>
  <div class="meta">
    <span><strong>Case:</strong> {inv.id}</span>
    <span><strong>Intent:</strong> {inv.intent}</span>
    <span><strong>Status:</strong> {inv.status}</span>
    <span><strong>Rounds:</strong> {len(rounds)}</span>
    <span><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
  </div>
</div>

<div class="notice">
  <strong>Forensic Integrity Notice:</strong> Observed Evidence represents raw empirical system state captured through read-only OS instrumentation. Correlation / Rule Matches represent heuristic indicators that guided automated adaptive escalation. A rule match provides investigative leads and does not constitute absolute proof of malicious intent.
</div>

<h2>1. Executive Summary</h2>
<p>An intent-driven forensic triage was conducted for objective <strong>{inv.intent}</strong> on target endpoint <strong>{machine.hostname if machine else 'N/A'}</strong>.</p>
<p>{f"During correlation analysis, <strong>{len(unique_correlations)} unique forensic indicator(s)</strong> were identified, triggering dynamic adaptive escalation." if unique_correlations else "All checks completed without triggering rule-based escalation indicators."}</p>

<h2>2. Evidence Provenance &amp; Cryptographic Ledger</h2>
<table>
  <thead>
    <tr>
      <th>Artifact ID</th>
      <th>File Name</th>
      <th>Collector</th>
      <th>Round</th>
      <th>SHA-256 Hash</th>
      <th>Integrity</th>
    </tr>
  </thead>
  <tbody>
    {''.join(f"<tr><td><code>{a.id}</code></td><td>{a.name}</td><td><code>{a.collector}</code></td><td>Round {a.round_number}</td><td><code>{a.sha256[:16]}...</code></td><td><span class='badge badge-valid'>{a.integrity_status}</span></td></tr>" for a in artifacts)}
  </tbody>
</table>

<h2>3. Correlation &amp; Rule Matching Indicators</h2>
{(''.join(f"<div class='card'><strong>{c.rule_name}</strong> <span class='badge badge-warn'>{c.status_label}</span> <span style='font-size: 12px; color: #64748b;'>(Round {c.round_number})</span><p style='margin: 6px 0 0; font-size: 13px; color: #475569;'>{c.description}</p></div>" for c in unique_correlations)) if unique_correlations else "<p>No correlation rules triggered.</p>"}

<h2>4. Chronological Timeline Highlights</h2>
<table>
  <thead>
    <tr>
      <th>Timestamp</th>
      <th>Source</th>
      <th>Event Type</th>
      <th>Description</th>
    </tr>
  </thead>
  <tbody>
    {''.join(f"<tr><td style='white-space:nowrap;'>{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td><td><code>{ev.source}</code></td><td><strong>{ev.event_type}</strong></td><td>{ev.description}</td></tr>" for ev in timeline[:20])}
  </tbody>
</table>

</body>
</html>"""

        return {
            "investigation_id": investigation_id,
            "markdown": md_content,
            "html": html_content,
            "json": report_json
        }
