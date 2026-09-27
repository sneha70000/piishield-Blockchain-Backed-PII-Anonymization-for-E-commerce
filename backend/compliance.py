"""
compliance.py — GDPR / CCPA compliance report generator for PIIShield.

Directly implements the report's claims:
  "helps organizations use customer data safely for analytics while
   protecting privacy and meeting data security regulations"
  "supports reporting and monitoring features that make it easier for
   businesses to demonstrate compliance when required"

This produces a structured, human-readable summary tying each
detection/anonymisation action on a dataset to the specific regulatory
principle it satisfies, sourced from the actual audit chain (Fabric).
"""

from dataclasses import dataclass, field
from typing import List, Dict


# Mapping of anonymisation technique -> which regulatory principles it
# helps satisfy. Kept intentionally explicit and traceable rather than
# a black box, since compliance reporting needs to be auditable.
TECHNIQUE_COMPLIANCE_MAP = {
    "MASK": {
        "principle": "Data Minimisation",
        "gdpr_article": "GDPR Art. 5(1)(c) — data minimisation",
        "ccpa_section": "CCPA §1798.100 — right to know / minimise collection",
        "description": "Irreversibly obscures direct identifiers, reducing the personal data surface retained.",
    },
    "HASH": {
        "principle": "Pseudonymisation (one-way)",
        "gdpr_article": "GDPR Art. 32(1)(a) — pseudonymisation as a security measure",
        "ccpa_section": "CCPA §1798.140(r) — de-identified information",
        "description": "Converts identifiers into irreversible digests, preventing re-identification while preserving uniqueness for analytics.",
    },
    "ENCRYPT": {
        "principle": "Pseudonymisation (reversible, key-controlled)",
        "gdpr_article": "GDPR Art. 32(1)(a) — encryption of personal data",
        "ccpa_section": "CCPA §1798.150 — reasonable security procedures",
        "description": "Protects data at rest with AES-256; only authorised key-holders can reverse it.",
    },
    "TOKENISE": {
        "principle": "Data Protection by Design",
        "gdpr_article": "GDPR Art. 25 — data protection by design and by default",
        "ccpa_section": "CCPA §1798.140(r) — de-identified/pseudonymised information",
        "description": "Replaces identifiers with non-sensitive tokens, decoupling analytics use from raw personal data.",
    },
}


@dataclass
class ComplianceReport:
    dataset_id: int
    filename: str
    total_rows: int
    total_pii_cells_found: int
    columns_processed: List[Dict] = field(default_factory=list)
    audit_blocks_count: int = 0
    audit_chain_verified: bool = False
    summary_statement: str = ""


def generate_compliance_report(
    dataset_id: int,
    filename: str,
    total_rows: int,
    total_pii_cells: int,
    anonymisation_summary: List[dict],
    audit_blocks_count: int,
    audit_chain_verified: bool,
) -> ComplianceReport:
    """
    Builds a compliance report from data already computed elsewhere in the
    pipeline (detection results, anonymisation summary, and the Fabric
    audit chain) — this function does not re-run any processing, it only
    assembles and interprets results already produced and audited.
    """
    columns_processed = []
    for item in anonymisation_summary:
        technique = item.get("technique", "UNKNOWN")
        mapping = TECHNIQUE_COMPLIANCE_MAP.get(technique, {
            "principle": "Unmapped technique",
            "gdpr_article": "N/A",
            "ccpa_section": "N/A",
            "description": "This technique is not yet mapped to a specific regulatory clause.",
        })
        columns_processed.append({
            "column": item.get("column"),
            "pii_type": item.get("pii_type"),
            "technique_applied": technique,
            "rows_affected": item.get("rows_changed", 0),
            **mapping,
        })

    verified_note = (
        "verified via cryptographic hash-chain on Hyperledger Fabric"
        if audit_chain_verified
        else "WARNING: audit chain verification failed — investigate before relying on this report"
    )

    summary = (
        f"Dataset '{filename}' (ID {dataset_id}, {total_rows} rows) was processed through "
        f"PIIShield's detection and anonymisation pipeline. {total_pii_cells} PII cells were "
        f"identified across {len(columns_processed)} column(s) and protected using regulation-aligned "
        f"techniques (see below). All processing steps are recorded as {audit_blocks_count} immutable "
        f"audit block(s), {verified_note}."
    )

    return ComplianceReport(
        dataset_id=dataset_id,
        filename=filename,
        total_rows=total_rows,
        total_pii_cells_found=total_pii_cells,
        columns_processed=columns_processed,
        audit_blocks_count=audit_blocks_count,
        audit_chain_verified=audit_chain_verified,
        summary_statement=summary,
    )
