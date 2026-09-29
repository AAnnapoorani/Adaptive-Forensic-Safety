from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.investigation import Investigation, InvestigationRound
from app.models.evidence import EvidenceArtifact, ProvenanceRecord, EvidenceChainManifest
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
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
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
    <span><strong>Generated:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
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

    @staticmethod
    def generate_court_dossier(db: Session, investigation_id: str) -> dict:
        """
        Generate an official, court-admissible forensic dossier and certificate of authenticity
        compliant with Section 65B Indian Evidence Act & ISO/IEC 27037 Digital Evidence Standards.
        Includes Ed25519 signature verification, RFC 8785 canonical hash chain, and machine hardware fingerprint.
        """
        from app.services.verifier_service import VerifierService
        from app.services.chain_service import ChainService

        inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found")

        machine = db.query(Machine).filter(Machine.id == inv.machine_id).first()
        artifacts = db.query(EvidenceArtifact).filter(EvidenceArtifact.investigation_id == investigation_id).all()
        manifest = db.query(EvidenceChainManifest).filter(EvidenceChainManifest.investigation_id == investigation_id).first()
        verify_report = VerifierService.verify_investigation_chain(db, investigation_id)

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        is_valid = verify_report.get("valid", False)
        chain_tip = manifest.chain_tip if manifest else (verify_report.get("chain_tip") or "UNSEALED")
        signature_hex = manifest.signature_hex if manifest else "N/A"
        key_id = manifest.key_id if manifest else "N/A"

        # Build printable court-admissible HTML
        dossier_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>COURT DOSSIER — Certificate of Authenticity #{inv.id}</title>
<style>
  @page {{
    size: A4;
    margin: 18mm 15mm;
  }}
  @media print {{
    body {{ background: #fff !important; color: #000 !important; font-size: 11pt; }}
    .no-print {{ display: none !important; }}
    .page-break {{ page-break-before: always; }}
  }}
  body {{
    font-family: 'Times New Roman', Times, serif;
    background: #f8fafc;
    color: #0f172a;
    line-height: 1.5;
    padding: 30px;
    max-width: 900px;
    margin: 0 auto;
  }}
  .cert-container {{
    background: #ffffff;
    border: 3px double #0284c7;
    padding: 35px 40px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.06);
    position: relative;
  }}
  .header-seal {{
    text-align: center;
    border-bottom: 2px solid #0284c7;
    padding-bottom: 18px;
    margin-bottom: 24px;
  }}
  .seal-title {{
    font-size: 22px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #0369a1;
    margin: 0 0 6px 0;
  }}
  .seal-sub {{
    font-size: 13px;
    color: #475569;
    font-style: italic;
  }}
  .badge-seal {{
    display: inline-block;
    padding: 6px 16px;
    border-radius: 4px;
    font-family: monospace;
    font-weight: 700;
    font-size: 13px;
    background: {'#dcfce7' if is_valid else '#fee2e2'};
    color: {'#15803d' if is_valid else '#b91c1c'};
    border: 1px solid {'#86efac' if is_valid else '#fca5a5'};
    margin-top: 10px;
  }}
  h2 {{
    font-size: 15px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 24px;
    color: #0f172a;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    margin: 12px 0;
  }}
  th, td {{
    border: 1px solid #cbd5e1;
    padding: 6px 10px;
    text-align: left;
  }}
  th {{
    background: #f1f5f9;
    font-weight: 700;
  }}
  .mono {{ font-family: monospace; word-break: break-all; }}
  .legal-box {{
    background: #f8fafc;
    border-left: 4px solid #0284c7;
    padding: 12px 16px;
    font-size: 11px;
    color: #334155;
    margin: 18px 0;
    text-align: justify;
  }}
  .signatures {{
    display: flex;
    justify-content: space-between;
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid #e2e8f0;
  }}
  .sig-block {{
    width: 45%;
    text-align: center;
  }}
  .sig-line {{
    border-top: 1px solid #000;
    margin-top: 50px;
    padding-top: 6px;
    font-size: 12px;
    font-weight: 600;
  }}
  .print-btn {{
    position: fixed;
    top: 20px;
    right: 20px;
    background: #0284c7;
    color: #fff;
    border: none;
    padding: 10px 20px;
    border-radius: 6px;
    font-weight: 700;
    cursor: pointer;
    box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3);
  }}
</style>
</head>
<body>

<button class="print-btn no-print" onclick="window.print()">Print to PDF / Court Export</button>

<div class="cert-container">
  <div class="header-seal">
    <div class="seal-title">CERTIFICATE OF DIGITAL EVIDENCE AUTHENTICITY</div>
    <div class="seal-sub">Issued under Section 65B, Indian Evidence Act / ISO/IEC 27037:2012 Electronic Evidence Principles</div>
    <div class="badge-seal">
      {'CRYPTOGRAPHICALLY VERIFIED - ED25519 TAMPER-PROOF' if is_valid else 'VERIFICATION WARNING - INTEGRITY CHECK FAILED'}
    </div>
  </div>

  <div class="legal-box">
    <strong>STATUTORY DECLARATION:</strong> This electronic record was produced by an automated digital forensics instrument (JOCKY Framework v1.0.0) operating normally without manual intervention. Evidence artifacts were extracted through read-only system collectors and sealed with Ed25519 digital signatures and RFC 8785 canonical hash-chain sequencing immediately upon capture.
  </div>

  <h2>1. Case &amp; Target Machine Fingerprint</h2>
  <table>
    <tr><th style="width: 25%;">Case ID</th><td class="mono"><strong>{inv.id}</strong></td></tr>
    <tr><th>Forensic Intent</th><td>{inv.intent}</td></tr>
    <tr><th>Status</th><td>{inv.status} (Verified in {inv.total_rounds} Automated Rounds)</td></tr>
    <tr><th>Target Machine ID</th><td class="mono">{machine.id if machine else 'N/A'}</td></tr>
    <tr><th>Hostname</th><td>{machine.hostname if machine else 'N/A'}</td></tr>
    <tr><th>Operating System</th><td>{machine.os_name if machine else 'N/A'} ({machine.os_version if machine else 'N/A'}) - Arch: {machine.architecture if machine else 'N/A'}</td></tr>
    <tr><th>Primary MAC Address</th><td class="mono">{machine.mac_address if machine else 'N/A'}</td></tr>
    <tr><th>Acquisition Timestamp</th><td>{to_iso_utc(inv.start_time)} to {to_iso_utc(inv.end_time)}</td></tr>
  </table>

  <h2>2. Evidence Cryptographic Chain of Custody</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 15%;">Artifact ID</th>
        <th>Evidence Name</th>
        <th>Collector</th>
        <th>SHA-256 Hash</th>
        <th style="width: 15%;">Status</th>
      </tr>
    </thead>
    <tbody>
      {''.join(f"<tr><td class='mono'>{a.id}</td><td>{a.name}</td><td class='mono'>{a.collector}</td><td class='mono'>{a.sha256}</td><td><strong>{a.integrity_status}</strong></td></tr>" for a in artifacts)}
    </tbody>
  </table>

  <h2>3. Ed25519 Digital Signature &amp; Hash Chain Tip</h2>
  <table>
    <tr><th style="width: 25%;">Signing Algorithm</th><td>Ed25519 (RFC 8032) + RFC 8785 Canonical JSON Serialization</td></tr>
    <tr><th>Active Key ID</th><td class="mono">{key_id}</td></tr>
    <tr><th>Canonical Chain Tip</th><td class="mono">{chain_tip}</td></tr>
    <tr><th>Digital Signature (Hex)</th><td class="mono">{signature_hex}</td></tr>
    <tr><th>Integrity Status</th><td><strong>{'CHAIN VALID & TAMPER SEAL INTACT' if is_valid else 'INVALID'}</strong></td></tr>
  </table>

  <div class="signatures">
    <div class="sig-block">
      <div class="sig-line">Lead Digital Forensics Examiner<br><span style="font-size: 10px; font-weight: normal; color: #64748b;">Automated Attestation • {now_utc}</span></div>
    </div>
    <div class="sig-block">
      <div class="sig-line">Tribunal / Evidence Custodian<br><span style="font-size: 10px; font-weight: normal; color: #64748b;">Seal of Judicial Acceptance</span></div>
    </div>
  </div>
</div>

</body>
</html>"""

        return {
            "investigation_id": investigation_id,
            "status": "VERIFIED" if is_valid else "FAILED",
            "is_valid": is_valid,
            "target_machine": {
                "id": machine.id if machine else None,
                "hostname": machine.hostname if machine else None,
                "os": machine.os_name if machine else None,
                "mac": machine.mac_address if machine else None
            },
            "chain_tip": chain_tip,
            "key_id": key_id,
            "signature_hex": signature_hex,
            "artifacts_count": len(artifacts),
            "html": dossier_html
        }

