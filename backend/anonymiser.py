"""
Anonymiser — applies protection techniques to detected PII columns.

Techniques:
  MASK       — partial hide:  john.doe@gmail.com → j***.d**@g***l.com
  HASH       — SHA-256 (irreversible)
  ENCRYPT    — AES-256-CBC (reversible with key)
  TOKENISE   — replace with UUID token; mapping kept in DB
"""

import hashlib
import uuid
import os
import re
import base64
import pandas as pd
from typing import Dict, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# ── AES key setup ──────────────────────────────────────────────────────────
_RAW_KEY = os.getenv("AES_KEY", "piishield-aes-256-encryption-key!!")
AES_KEY = hashlib.sha256(_RAW_KEY.encode()).digest()   # always 32 bytes

IV_SIZE = 16   # AES block size


# ── Default technique per PII type ────────────────────────────────────────
DEFAULT_TECHNIQUE: Dict[str, str] = {
    "NAME":        "MASK",
    "EMAIL":       "MASK",
    "PHONE":       "MASK",
    "ADDRESS":     "MASK",
    "ZIP_CODE":    "MASK",
    "DATE_OF_BIRTH": "MASK",
    "CREDIT_CARD": "HASH",
    "AADHAAR":     "HASH",
    "PAN":         "HASH",
    "SSN":         "HASH",
    "PASSPORT":    "HASH",
    "IP_ADDRESS":  "MASK",
    "FINANCIAL":   "ENCRYPT",
    "ORGANISATION": "TOKENISE",
    "MISC":        "MASK",
}


# ── Individual value transformers ─────────────────────────────────────────

def mask_value(value: str, pii_type: str) -> str:
    """Context-aware masking."""
    v = str(value).strip()
    if not v or v in ("nan", "None", ""):
        return v

    if pii_type == "EMAIL":
        # john.doe@gmail.com → j***.d**@g***.com
        parts = v.split("@")
        if len(parts) == 2:
            local = parts[0]
            domain_parts = parts[1].split(".")
            masked_local = local[0] + "*" * (len(local) - 1)
            masked_domain = domain_parts[0][0] + "*" * (len(domain_parts[0]) - 1)
            return f"{masked_local}@{masked_domain}.{'.'.join(domain_parts[1:])}"

    if pii_type == "PHONE":
        # keep last 4 digits: ****6789
        digits = re.sub(r"\D", "", v)
        return "*" * (len(digits) - 4) + digits[-4:] if len(digits) >= 4 else "****"

    if pii_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", v)
        return "*" * (len(digits) - 4) + digits[-4:] if len(digits) >= 4 else "****"

    if pii_type == "AADHAAR":
        digits = re.sub(r"\D", "", v)
        return "XXXX-XXXX-" + digits[-4:] if len(digits) >= 4 else "XXXX-XXXX-XXXX"

    if pii_type in ("NAME", "ADDRESS"):
        words = v.split()
        masked = []
        for w in words:
            if len(w) <= 1:
                masked.append(w)
            elif len(w) <= 3:
                masked.append(w[0] + "*" * (len(w) - 1))
            else:
                masked.append(w[0] + "*" * (len(w) - 2) + w[-1])
        return " ".join(masked)

    if pii_type == "IP_ADDRESS":
        parts = v.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.*.*"

    if pii_type == "DATE_OF_BIRTH":
        # keep only year
        year_match = re.search(r"(19|20)\d{2}", v)
        return f"****-**-{year_match.group()}" if year_match else "****-**-**"

    if pii_type == "ZIP_CODE":
        return v[:3] + "***" if len(v) >= 3 else "***"

    # Generic: show first char + stars
    return v[0] + "*" * (len(v) - 1) if len(v) > 1 else "*"


def hash_value(value: str) -> str:
    """SHA-256 hash (irreversible)."""
    v = str(value).strip()
    if not v or v in ("nan", "None"):
        return v
    return "SHA256:" + hashlib.sha256(v.encode("utf-8")).hexdigest()[:16] + "…"


def encrypt_value(value: str) -> str:
    """AES-256-CBC encryption (reversible with key)."""
    v = str(value).strip()
    if not v or v in ("nan", "None"):
        return v
    iv = os.urandom(IV_SIZE)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(v.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    encoded = base64.b64encode(iv + ct).decode()
    return f"ENC:{encoded}"


def decrypt_value(value: str) -> Optional[str]:
    """Decrypt an AES-256-CBC value produced by encrypt_value."""
    if not value.startswith("ENC:"):
        return value
    raw = base64.b64decode(value[4:])
    iv, ct = raw[:IV_SIZE], raw[IV_SIZE:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def tokenise_value(value: str, token_store: Dict[str, str]) -> str:
    """Replace value with a stable UUID token. Store mapping in token_store."""
    v = str(value).strip()
    if not v or v in ("nan", "None"):
        return v
    h = hashlib.sha256(v.encode()).hexdigest()
    if h not in token_store:
        token_store[h] = "TOK-" + str(uuid.uuid4())[:8].upper()
    return token_store[h]


# ── DataFrame-level anonymiser ─────────────────────────────────────────────

def anonymise_dataframe(
    df: pd.DataFrame,
    pii_columns: Dict[str, str],          # {col: pii_type}
    technique_overrides: Dict[str, str] = None   # {col: technique}
) -> Dict:
    """
    Returns:
      {
        "anonymised_df": pd.DataFrame,
        "summary": [{col, pii_type, technique, rows_changed}],
        "token_store": {hash: token}   # for tokenised columns
      }
    """
    result_df = df.copy()
    summary = []
    token_store: Dict[str, str] = {}
    technique_overrides = technique_overrides or {}

    for col, pii_type in pii_columns.items():
        if col not in result_df.columns:
            continue

        technique = technique_overrides.get(col) or DEFAULT_TECHNIQUE.get(pii_type, "MASK")
        rows_changed = 0

        def apply(val):
            nonlocal rows_changed
            if pd.isna(val) or str(val).strip() in ("", "nan", "None"):
                return val
            rows_changed += 1
            if technique == "MASK":
                return mask_value(str(val), pii_type)
            elif technique == "HASH":
                return hash_value(str(val))
            elif technique == "ENCRYPT":
                return encrypt_value(str(val))
            elif technique == "TOKENISE":
                return tokenise_value(str(val), token_store)
            return mask_value(str(val), pii_type)

        result_df[col] = result_df[col].apply(apply)
        summary.append({
            "column": col,
            "pii_type": pii_type,
            "technique": technique,
            "rows_changed": rows_changed,
        })

    return {
        "anonymised_df": result_df,
        "summary": summary,
        "token_store": token_store,
    }
