"""
preprocessing.py — Data cleaning & normalization pipeline for PIIShield.

Runs BEFORE detection. Directly implements the report's Section 1.2.1:
  "data cleaning ensures removal of duplicate records, incorrect entries,
   and irrelevant information... normalization techniques are applied to
   maintain consistency in formats, such as standardizing date formats,
   phone numbers, and email structures."
"""

import re
from dataclasses import dataclass, field
from typing import List
import pandas as pd


@dataclass
class PreprocessingReport:
    original_rows: int
    final_rows: int
    duplicates_removed: int
    empty_rows_removed: int
    columns_normalized: List[str] = field(default_factory=list)
    missing_values_filled: dict = field(default_factory=dict)


PHONE_CLEAN_RE = re.compile(r"[^\d+]")
DATE_COL_HINTS = ("dob", "date_of_birth", "birth", "date")
PHONE_COL_HINTS = ("phone", "mobile", "contact")
EMAIL_COL_HINTS = ("email", "mail")


def _looks_like(col_name: str, hints) -> bool:
    lname = col_name.lower()
    return any(h in lname for h in hints)


def _normalize_phone_series(s: pd.Series) -> pd.Series:
    def clean(v):
        if pd.isna(v):
            return v
        digits = PHONE_CLEAN_RE.sub("", str(v))
        return digits
    return s.apply(clean)


def _normalize_email_series(s: pd.Series) -> pd.Series:
    return s.apply(lambda v: str(v).strip().lower() if pd.notna(v) else v)


def _normalize_date_series(s: pd.Series) -> pd.Series:
    def to_iso(v):
        if pd.isna(v):
            return v
        parsed = pd.to_datetime(v, errors="coerce", dayfirst=True)
        if pd.isna(parsed):
            return v  # leave as-is if unparseable, don't destroy data
        return parsed.strftime("%Y-%m-%d")
    return s.apply(to_iso)


def preprocess_dataframe(df: pd.DataFrame) -> "tuple[pd.DataFrame, PreprocessingReport]":
    """
    Cleans and normalizes a raw uploaded dataframe.
    Returns (cleaned_df, report) — report is written to the audit trail
    by the caller (main.py), same as detection/anonymisation results are.
    """
    original_rows = len(df)

    # 1. Drop fully-empty rows
    df = df.dropna(how="all")
    empty_removed = original_rows - len(df)

    # 2. Drop exact duplicate rows
    before_dedup = len(df)
    df = df.drop_duplicates()
    duplicates_removed = before_dedup - len(df)

    # 3. Strip whitespace from all string/object columns
    for col in df.select_dtypes(include="object").columns:
        df[col] = df[col].apply(lambda v: v.strip() if isinstance(v, str) else v)

    # 4. Format-specific normalization based on column name hints
    normalized_cols = []
    for col in df.columns:
        if _looks_like(col, PHONE_COL_HINTS):
            df[col] = _normalize_phone_series(df[col])
            normalized_cols.append(col)
        elif _looks_like(col, EMAIL_COL_HINTS):
            df[col] = _normalize_email_series(df[col])
            normalized_cols.append(col)
        elif _looks_like(col, DATE_COL_HINTS):
            df[col] = _normalize_date_series(df[col])
            normalized_cols.append(col)

    # 5. Fill missing values conservatively (only for non-PII-looking numeric columns,
    #    to avoid fabricating sensitive data — text/PII columns are left as NaN)
    missing_filled = {}
    for col in df.columns:
        na_count = df[col].isna().sum()
        if na_count == 0:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)
            missing_filled[col] = int(na_count)
        # non-numeric columns: leave missing as-is, don't invent PII data

    df = df.reset_index(drop=True)

    report = PreprocessingReport(
        original_rows=original_rows,
        final_rows=len(df),
        duplicates_removed=duplicates_removed,
        empty_rows_removed=empty_removed,
        columns_normalized=normalized_cols,
        missing_values_filled=missing_filled,
    )
    return df, report
