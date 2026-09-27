"""
PIIShield FastAPI Backend
Endpoints:
  POST /api/upload                     — upload CSV/JSON dataset
  POST /api/detect/{id}                — run preprocessing + PII detection
  POST /api/anonymise/{id}             — run anonymisation
  GET  /api/results/{id}               — get detection + anonymisation results
  GET  /api/download/{id}              — download anonymised file
  GET  /api/audit/{id}                 — get blockchain audit log for a dataset
  GET  /api/audit/verify               — verify chain integrity
  GET  /api/datasets                   — list all datasets
  GET  /api/stats                      — dashboard stats
  GET  /api/compliance-report/{id}     — GDPR/CCPA compliance report
  GET  /api/dp-stats/{id}              — differentially-private aggregate stats
  POST /api/auth/bootstrap-admin-key   — one-time admin API key creation
  GET  /api/admin/ping                 — example endpoint protected by API key
  GET  /api/datasets/{dataset_id}/insights — generated insights from anonymised data
"""

import os
import uuid
import json
import shutil
import pandas as pd
from datetime import datetime
from typing import Optional, Dict
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from models import init_db, get_db, Dataset, DetectionResult, AuditLog
from detector import detect_pii
from anonymiser import anonymise_dataframe
import blockchain as bc

# report-completion modules
import auth
import preprocessing
import differential_privacy as dp
import compliance

load_dotenv()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./data/uploads")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./data/outputs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("./data", exist_ok=True)

app = FastAPI(
    title="PIIShield API",
    description="Blockchain-Backed Automated PII Anonymisation System",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


# ── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _read_file(path: str) -> pd.DataFrame:
    if path.endswith(".csv"):
        return pd.read_csv(path)
    elif path.endswith(".json"):
        return pd.read_json(path)
    elif path.endswith(".xlsx"):
        return pd.read_excel(path)
    raise ValueError(f"Unsupported file type: {path}")


def _save_output(df: pd.DataFrame, original_path: str, dataset_id: int) -> str:
    ext = os.path.splitext(original_path)[1]
    out_path = os.path.join(OUTPUT_DIR, f"anonymised_{dataset_id}{ext}")
    if ext == ".csv":
        df.to_csv(out_path, index=False)
    elif ext == ".json":
        df.to_json(out_path, orient="records", indent=2)
    elif ext == ".xlsx":
        df.to_excel(out_path, index=False)
    return out_path


def _optional_api_key(x_api_key: str = Header(None, alias="X-API-Key"), db: Session = Depends(get_db)):
    if not x_api_key:
        return None
    return auth.require_api_key(x_api_key=x_api_key, db=db)


def _get_owned_dataset(dataset_id: int, caller: auth.ApiKey, db: Session) -> Dataset:
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(404, "Dataset not found.")
    if dataset.company != caller.company:
        raise HTTPException(403, "This dataset does not belong to your company.")
    return dataset


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "PIIShield", "version": "1.0.0"}


class RegisterRequest(BaseModel):
    company: str
    role: str 
    password: str
    security_question: str
    security_answer: str


class LoginRequest(BaseModel):
    username: str
    password: str


def _make_username(company: str, role: str) -> str:
    slug = "".join(c for c in company.lower().strip().replace(" ", "-") if c.isalnum() or c == "-")
    if not slug:
        raise HTTPException(400, "Company name must contain at least one letter or number.")
    suffix = "" if role == "admin" else f"-{role}"
    return f"{slug}{suffix}@piishield"


@app.post("/api/auth/register")
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if body.role not in ("admin", "auditor", "analyst"):
        raise HTTPException(400, "Role must be one of: admin, auditor, analyst.")
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")

    username = _make_username(body.company, body.role)
    try:
        user = auth.create_user(
            db, username=username, password=body.password,
            company=body.company.strip(), role=body.role,
            security_question=body.security_question,
            security_answer=body.security_answer
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    token = auth.issue_session_token(db, user)
    return {"token": token, "username": user.username, "company": user.company, "role": user.role}


@app.post("/api/auth/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = auth.authenticate_user(db, body.username, body.password)
    if not user:
        raise HTTPException(401, "Incorrect username or password.")

    token = auth.issue_session_token(db, user)
    return {"token": token, "username": user.username, "company": user.company, "role": user.role}


@app.get("/api/stats")
def get_stats(caller: auth.ApiKey = Depends(auth.require_api_key), db: Session = Depends(get_db)):
    q = db.query(Dataset).filter(Dataset.company == caller.company)
    total = q.count()
    completed = q.filter(Dataset.status == "completed").count()
    total_pii = db.query(DetectionResult).join(
        Dataset, DetectionResult.dataset_id == Dataset.id
    ).filter(Dataset.company == caller.company).count()
    
    chain_data = bc.verify_chain()
    company_datasets = db.query(Dataset.id).filter(Dataset.company == caller.company).all()
    company_dataset_ids = {d[0] for d in company_datasets}
    
    company_blocks = [
        b for b in chain_data.get("chain", []) 
        if b.get("index") == 0 or b.get("dataset_id") in company_dataset_ids
    ]
    
    return {
        "total_datasets": total,
        "completed": completed,
        "total_pii_detections": total_pii,
        "blockchain_valid": chain_data.get("valid", False),
        "total_blocks": len(company_blocks),
    }


@app.get("/api/datasets")
def list_datasets(caller: auth.ApiKey = Depends(auth.require_api_key), db: Session = Depends(get_db)):
    datasets = db.query(Dataset).filter(
        Dataset.company == caller.company
    ).order_by(Dataset.uploaded_at.desc()).all()
    return [
        {
            "id": d.id, "filename": d.filename,
            "total_rows": d.total_rows, "pii_detected": d.pii_detected,
            "status": d.status,
            "uploaded_at": d.uploaded_at.isoformat() if d.uploaded_at else None,
        }
        for d in datasets
    ]


@app.post("/api/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    caller: auth.ApiKey = Depends(auth.require_api_key),
):
    allowed = {".csv", ".json", ".xlsx"}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed:
        raise HTTPException(400, f"Only {', '.join(allowed)} files are accepted.")

    safe_name = f"{uuid.uuid4()}{ext}"
    save_path = os.path.join(UPLOAD_DIR, safe_name)

    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    try:
        df = _read_file(save_path)
        row_count = len(df)
    except Exception as e:
        os.remove(save_path)
        raise HTTPException(400, f"Could not read file: {e}")

    dataset = Dataset(
        filename=file.filename,
        original_path=save_path,
        total_rows=row_count,
        status="uploaded",
        company=caller.company,
    )
    db.add(dataset)
    db.commit()
    db.refresh(dataset)

    bc.add_block(
        action="UPLOAD",
        dataset_id=dataset.id,
        payload={
            "filename": file.filename, "rows": row_count, "path": save_path,
            "uploaded_by": caller.name,
        },
    )

    return {
        "id": dataset.id, "filename": file.filename,
        "total_rows": row_count, "status": "uploaded",
    }


@app.post("/api/detect/{dataset_id}")
def run_detection(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    dataset = _get_owned_dataset(dataset_id, caller, db)

    dataset.status = "detecting"
    db.commit()

    try:
        df = _read_file(dataset.original_path)

        df, prep_report = preprocessing.preprocess_dataframe(df)
        bc.add_block(
            action="PREPROCESS",
            dataset_id=dataset_id,
            payload={
                "duplicates_removed": prep_report.duplicates_removed,
                "empty_rows_removed": prep_report.empty_rows_removed,
                "columns_normalized": prep_report.columns_normalized,
                "missing_values_filled": prep_report.missing_values_filled,
            },
        )

        report = detect_pii(df)

        db.query(DetectionResult).filter(DetectionResult.dataset_id == dataset_id).delete()
        for hit in report.hits:
            db.add(DetectionResult(
                dataset_id=dataset_id,
                column_name=hit.column,
                pii_type=hit.pii_type,
                detection_method=hit.method,
                count=hit.count,
                sample_value=hit.sample[:200],
            ))

        dataset.pii_detected = report.total_pii_cells
        dataset.status = "detected"
        db.commit()

        bc.add_block(
            action="DETECT",
            dataset_id=dataset_id,
            payload={
                "columns_with_pii": list(report.pii_columns.keys()),
                "total_pii_cells": report.total_pii_cells,
            },
            records_affected=report.total_pii_cells,
        )

        return {
            "dataset_id": dataset_id,
            "total_rows": report.total_rows,
            "total_pii_cells": report.total_pii_cells,
            "pii_columns": report.pii_columns,
            "preprocessing": {
                "duplicates_removed": prep_report.duplicates_removed,
                "empty_rows_removed": prep_report.empty_rows_removed,
                "columns_normalized": prep_report.columns_normalized,
            },
            "hits": [
                {
                    "column": h.column, "pii_type": h.pii_type,
                    "method": h.method, "count": h.count, "sample": h.sample,
                }
                for h in report.hits
            ],
        }

    except Exception as e:
        dataset.status = "failed"
        db.commit()
        raise HTTPException(500, f"Detection failed: {e}")


class AnonymiseRequest(BaseModel):
    technique_overrides: Optional[Dict[str, str]] = None 


@app.post("/api/anonymise/{dataset_id}")
def run_anonymisation(
    dataset_id: int,
    body: AnonymiseRequest = AnonymiseRequest(),
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    dataset = _get_owned_dataset(dataset_id, caller, db)
    if dataset.status not in ("detected", "completed"):
        raise HTTPException(400, "Run /detect first.")

    dataset.status = "anonymising"
    db.commit()

    try:
        df = _read_file(dataset.original_path)

        det_results = db.query(DetectionResult).filter(
            DetectionResult.dataset_id == dataset_id
        ).all()
        pii_columns = {r.column_name: r.pii_type for r in det_results}

        result = anonymise_dataframe(
            df, pii_columns,
            technique_overrides=body.technique_overrides or {}
        )
        anon_df = result["anonymised_df"]
        summary = result["summary"]

        out_path = _save_output(anon_df, dataset.original_path, dataset_id)
        dataset.anonymised_path = out_path
        dataset.status = "completed"
        dataset.completed_at = datetime.utcnow()
        db.commit()

        for s in summary:
            bc.add_block(
                action="ANONYMISE",
                dataset_id=dataset_id,
                payload={"column": s["column"]},
                pii_type=s["pii_type"],
                anonymisation_method=s["technique"],
                records_affected=s["rows_changed"],
            )

        return {
            "dataset_id": dataset_id,
            "status": "completed",
            "output_file": os.path.basename(out_path),
            "summary": summary,
        }

    except Exception as e:
        dataset.status = "failed"
        db.commit()
        raise HTTPException(500, f"Anonymisation failed: {e}")


@app.get("/api/results/{dataset_id}")
def get_results(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    dataset = _get_owned_dataset(dataset_id, caller, db)

    det_results = db.query(DetectionResult).filter(
        DetectionResult.dataset_id == dataset_id
    ).all()

    return {
        "dataset": {
            "id": dataset.id, "filename": dataset.filename,
            "total_rows": dataset.total_rows, "pii_detected": dataset.pii_detected,
            "status": dataset.status,
        },
        "all_columns": {c: True for c in pd.read_csv(dataset.original_path, nrows=0).columns.tolist()} if dataset.original_path and os.path.exists(dataset.original_path) else {},
        "detections": [
            {
                "column": r.column_name, "pii_type": r.pii_type,
                "method": r.detection_method, "count": r.count, "sample": r.sample_value,
            }
            for r in det_results
        ],
    }


@app.get("/api/download/{dataset_id}")
def download_result(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    dataset = _get_owned_dataset(dataset_id, caller, db)
    if not dataset.anonymised_path:
        raise HTTPException(404, "Anonymised file not ready.")
    if not os.path.exists(dataset.anonymised_path):
        raise HTTPException(404, "Output file missing on disk.")

    bc.add_block(
        action="DOWNLOAD", dataset_id=dataset_id,
        payload={"file": os.path.basename(dataset.anonymised_path)},
    )

    return FileResponse(
        path=dataset.anonymised_path,
        filename=f"anonymised_{dataset.filename}",
        media_type="application/octet-stream",
    )


_reset_tokens = {}

class ForgotQ(BaseModel):
    username: str

class ForgotV(BaseModel):
    username: str
    answer: str

class ForgotR(BaseModel):
    reset_token: str
    new_password: str

@app.post("/api/auth/forgot-password/question")
def forgot_question(body: ForgotQ, db: Session = Depends(get_db)):
    from models import User
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not user.security_question:
        raise HTTPException(404, "Username not found or no security question set.")
    return {"question": user.security_question}

@app.post("/api/auth/forgot-password/verify")
def forgot_verify(body: ForgotV, db: Session = Depends(get_db)):
    import secrets as _sec, hashlib as _h
    from models import User
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not user.security_answer_hash:
        raise HTTPException(404, "Username not found.")
    ah = _h.pbkdf2_hmac("sha256", body.answer.strip().lower().encode(), user.username.encode(), 10_000).hex()
    if ah != user.security_answer_hash:
        raise HTTPException(400, "Incorrect answer.")
    import secrets
    token = secrets.token_urlsafe(32)
    _reset_tokens[token] = user.username
    return {"reset_token": token}

@app.post("/api/auth/forgot-password/reset")
def forgot_reset(body: ForgotR, db: Session = Depends(get_db)):
    import hashlib as _h, secrets as _sec
    from models import User
    username = _reset_tokens.get(body.reset_token)
    if not username:
        raise HTTPException(400, "Invalid or expired token.")
    user = db.query(User).filter(User.username == username).first()
    salt = _sec.token_hex(16)
    dk = _h.pbkdf2_hmac("sha256", body.new_password.encode(), salt.encode(), 100_000)
    user.password_hash = salt + "$" + dk.hex()
    db.commit()
    del _reset_tokens[body.reset_token]
    return {"message": "Password reset successfully."}


@app.get("/api/audit/verify")
def verify_audit(
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db)
):
    chain_data = bc.verify_chain()
    company_datasets = db.query(Dataset.id).filter(Dataset.company == caller.company).all()
    company_dataset_ids = {d[0] for d in company_datasets}
    
    if "chain" in chain_data:
        filtered_chain = []
        for block in chain_data["chain"]:
            if block.get("index") == 0 or block.get("dataset_id") in company_dataset_ids:
                filtered_chain.append(block)
        
        chain_data["chain"] = filtered_chain
        chain_data["total_blocks"] = len(filtered_chain) 
        
    return chain_data


@app.get("/api/audit/{dataset_id}")
def get_audit(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    _get_owned_dataset(dataset_id, caller, db)
    chain = bc.get_chain(dataset_id=dataset_id)
    return {"dataset_id": dataset_id, "blocks": chain, "count": len(chain)}


# ── NEW: Compliance reporting ───────────────────────────────────────────────
@app.get("/api/compliance-report/{dataset_id}")
def get_compliance_report(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    dataset = _get_owned_dataset(dataset_id, caller, db)

    chain = bc.get_chain(dataset_id=dataset_id)
    verify = bc.verify_chain()

    anon_summary = [
        {
            "column": b["payload"].get("column"),
            "pii_type": b["pii_type"],
            "technique": b["anonymisation_method"],
            "rows_changed": b["records_affected"],
        }
        for b in chain if b["action"] == "ANONYMISE"
    ]

    report = compliance.generate_compliance_report(
        dataset_id=dataset_id,
        filename=dataset.filename,
        total_rows=dataset.total_rows,
        total_pii_cells=dataset.pii_detected or 0,
        anonymisation_summary=anon_summary,
        audit_blocks_count=len(chain),
        audit_chain_verified=verify.get("valid", False),
    )
    return report


# ── NEW: Differential privacy analytics ─────────────────────────────────────
@app.get("/api/dp-stats/{dataset_id}")
def get_dp_stats(
    dataset_id: int,
    epsilon: float = 1.0,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db),
):
    dataset = _get_owned_dataset(dataset_id, caller, db)
    if not dataset.anonymised_path:
        raise HTTPException(404, "Anonymised file not ready. Run anonymise first.")

    df = _read_file(dataset.anonymised_path)
    count_result = dp.dp_count(df, epsilon=epsilon)

    return {
        "dataset_id": dataset_id,
        "epsilon": epsilon,
        "row_count": {
            "true_value": count_result.true_value,
            "noisy_value": count_result.noisy_value,
        },
        "mechanism": "Laplace",
        "note": "Differential privacy applied to aggregate statistics only, not to individual PII field values (those are handled separately by mask/hash/encrypt/tokenise).",
    }


# ── NEW: Access control ─────────────────────────────────────────────────────
@app.post("/api/auth/bootstrap-admin-key")
def bootstrap_admin_key(db: Session = Depends(get_db)):
    existing_admin = db.query(auth.ApiKey).filter(auth.ApiKey.role == "admin").first()
    if existing_admin:
        raise HTTPException(400, "An admin key already exists. This endpoint only works once.")

    raw_key = auth.generate_api_key(db, name="admin", role="admin")
    return {
        "message": "Save this key now — it will not be shown again.",
        "api_key": raw_key,
    }


@app.get("/api/admin/ping")
def admin_ping(current_key: auth.ApiKey = Depends(auth.require_api_key)):
    return {
        "message": f"Authenticated as '{current_key.name}' (role: {current_key.role})",
        "last_used_at": current_key.last_used_at.isoformat() if current_key.last_used_at else None,
    }


import os
import pandas as pd
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
# (Keep your existing app, database models, and auth imports here)

@app.get("/api/datasets/{dataset_id}/insights")
def get_dataset_insights(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db)
):
    # 1. Fetch dataset and validate ownership/status
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    if dataset.company != caller.company:
        raise HTTPException(status_code=403, detail="Access denied.")
    if dataset.status != "completed":
        raise HTTPException(status_code=400, detail="Dataset is not fully anonymised yet.")

    # 2. Check if file exists on disk
    if not dataset.anonymised_path or not os.path.exists(dataset.anonymised_path):
        raise HTTPException(status_code=404, detail="Anonymised file not found on disk.")

    try:
        # 3. Read CSV data using pandas
        df = pd.read_csv(dataset.anonymised_path, low_memory=False)
        df = df.fillna("Unknown")

        summary = {
            "total_rows": len(df),
            "total_columns": len(df.columns),
            "summary_text": f"Dataset '{dataset.filename}' contains {len(df)} records and {len(df.columns)} columns securely processed."
        }

        # 4. Generate dynamic chart data for categorical columns
        charts = []
        for col in df.columns:
            if 1 < df[col].nunique() < 15:
                if df[col].astype(str).str.contains(r'\*|MASK', na=False).mean() > 0.5:
                    continue
                value_counts = df[col].value_counts().head(5)
                charts.append({
                    "column": str(col),
                    "labels": [str(x) for x in value_counts.index.tolist()],
                    "values": [int(x) for x in value_counts.values.tolist()]
                })
            if len(charts) >= 3:  # Limit to 3 charts for clean UI
                break

        return {"summary": summary, "charts": charts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing insights: {str(e)}")

# General route comes AFTER the specific sub-route
@app.get("/api/datasets/{dataset_id}")
def get_dataset_detail(
    dataset_id: int,
    caller: auth.ApiKey = Depends(auth.require_api_key),
    db: Session = Depends(get_db)
):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return dataset