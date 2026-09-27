"""
PII Detector — hybrid BERT NER + Regex engine.
Detects: NAME, EMAIL, PHONE, ADDRESS, CREDIT_CARD, AADHAAR, PAN, IP_ADDRESS, DATE_OF_BIRTH
"""

import re
import pandas as pd
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

# ── Lazy-load BERT so the app starts fast even without GPU ──────────────────
_bert_pipeline = None

def _get_bert():
    global _bert_pipeline
    if _bert_pipeline is None:
        try:
            from transformers import pipeline
            import os
            model = os.getenv("BERT_MODEL", "dslim/bert-base-NER")
            print(f"Loading BERT model: {model} …")
            _bert_pipeline = pipeline(
                "ner",
                model=model,
                aggregation_strategy="simple",
                device=-1   # CPU; change to 0 for GPU
            )
            print("✅ BERT NER model loaded.")
        except Exception as e:
            print(f"⚠️  BERT unavailable ({e}). Falling back to regex-only mode.")
            _bert_pipeline = "unavailable"
    return None if _bert_pipeline == "unavailable" else _bert_pipeline


# ── Regex patterns ───────────────────────────────────────────────────────────
PATTERNS: Dict[str, re.Pattern] = {
    "EMAIL":       re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "PHONE":       re.compile(r"(\+91[-\s]?)?[6-9]\d{9}|(\+1[-\s]?)?\(?\d{3}\)?[-\s.]?\d{3}[-\s.]\d{4}"),
    "CREDIT_CARD": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
    "AADHAAR":     re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
    "PAN":         re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "IP_ADDRESS":  re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:0?[1-9]|[12]\d|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b"
        r"|\b(?:19|20)\d{2}[/\-.]\d{2}[/\-.]\d{2}\b"
    ),
    "ZIP_CODE":    re.compile(r"\b[1-9]\d{5}\b|\b\d{5}(?:-\d{4})?\b"),
}

# Column name hints — if a column name contains these keywords, flag it
COLUMN_HINTS: Dict[str, str] = {
    "name": "NAME", "first_name": "NAME", "last_name": "NAME",
    "full_name": "NAME", "customer_name": "NAME",
    "email": "EMAIL", "mail": "EMAIL",
    "phone": "PHONE", "mobile": "PHONE", "contact": "PHONE", "tel": "PHONE",
    "address": "ADDRESS", "street": "ADDRESS", "city": "ADDRESS",
    "pincode": "ZIP_CODE", "zip": "ZIP_CODE", "postal": "ZIP_CODE",
    "dob": "DATE_OF_BIRTH", "birth": "DATE_OF_BIRTH", "birthdate": "DATE_OF_BIRTH",
    "pan": "PAN", "aadhaar": "AADHAAR", "aadhar": "AADHAAR",
    "card": "CREDIT_CARD", "credit": "CREDIT_CARD",
    "ip": "IP_ADDRESS",
    "ssn": "SSN", "passport": "PASSPORT",
    "salary": "FINANCIAL", "income": "FINANCIAL", "account": "FINANCIAL",
}


@dataclass
class PIIHit:
    column: str
    pii_type: str
    method: str          # "BERT" or "REGEX" or "COLUMN_HINT"
    count: int = 0
    sample: str = ""


@dataclass
class DetectionReport:
    total_rows: int = 0
    hits: List[PIIHit] = field(default_factory=list)
    pii_columns: Dict[str, str] = field(default_factory=dict)  # col → pii_type

    @property
    def total_pii_cells(self) -> int:
        return sum(h.count for h in self.hits)


# ── Core functions ────────────────────────────────────────────────────────────

def _regex_scan_value(value: str) -> List[Tuple[str, str]]:
    """Return list of (pii_type, matched_text) from a single string value."""
    found = []
    for pii_type, pattern in PATTERNS.items():
        if pattern.search(value):
            found.append((pii_type, pattern.search(value).group()))
    return found


def _bert_scan_texts(texts: List[str]) -> List[str]:
    """
    Run BERT NER on a sample of text values.
    Returns list of entity types found (PER → NAME, LOC/GPE → ADDRESS, etc.)
    """
    pipe = _get_bert()
    if pipe is None:
        return []

    entity_map = {
        "PER": "NAME",
        "LOC": "ADDRESS",
        "GPE": "ADDRESS",
        "ORG": "ORGANISATION",
        "MISC": "MISC",
    }

    found_types = set()
    try:
        # Sample up to 50 non-null values
        sample = [str(t) for t in texts if t and str(t).strip()][:50]
        if not sample:
            return []
        results = pipe(sample)
        for doc_entities in results:
            if isinstance(doc_entities, list):
                for ent in doc_entities:
                    label = ent.get("entity_group", ent.get("entity", ""))
                    mapped = entity_map.get(label.replace("B-", "").replace("I-", ""), None)
                    if mapped:
                        found_types.add(mapped)
    except Exception as e:
        print(f"BERT scan error: {e}")

    return list(found_types)


def detect_pii(df: pd.DataFrame) -> DetectionReport:
    """
    Full PII detection on a DataFrame.
    Returns a DetectionReport with all hits.
    """
    report = DetectionReport(total_rows=len(df))

    for col in df.columns:
        col_lower = col.lower().replace(" ", "_")
        values = df[col].dropna().astype(str).tolist()

        hits_for_col: Dict[str, PIIHit] = {}

        # 1. Column-name hint scan
        for keyword, pii_type in COLUMN_HINTS.items():
            if keyword in col_lower:
                hit = PIIHit(
                    column=col, pii_type=pii_type,
                    method="COLUMN_HINT",
                    count=len(values),
                    sample=str(values[0])[:40] if values else ""
                )
                hits_for_col[pii_type] = hit
                break

        # 2. Regex scan on values
        for value in values[:500]:  # cap at 500 rows for speed
            for pii_type, _ in _regex_scan_value(value):
                if pii_type not in hits_for_col:
                    hits_for_col[pii_type] = PIIHit(
                        column=col, pii_type=pii_type,
                        method="REGEX", count=0,
                        sample=value[:40]
                    )
                hits_for_col[pii_type].count += 1

        # 3. BERT NER on text columns (skip numeric columns)
        if df[col].dtype == object and len(values) > 0:
            bert_types = _bert_scan_texts(values)
            for pii_type in bert_types:
                if pii_type not in hits_for_col:
                    hits_for_col[pii_type] = PIIHit(
                        column=col, pii_type=pii_type,
                        method="BERT", count=len(values),
                        sample=str(values[0])[:40] if values else ""
                    )

        # Collect hits
        for pii_type, hit in hits_for_col.items():
            if hit.count == 0:
                hit.count = len(values)
            report.hits.append(hit)
            report.pii_columns[col] = pii_type  # last wins (fine for display)

    return report
