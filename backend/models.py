from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = "sqlite:///./piishield.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    original_path = Column(String(500))
    anonymised_path = Column(String(500))
    total_rows = Column(Integer, default=0)
    pii_detected = Column(Integer, default=0)
    status = Column(String(50), default="pending")  # pending, processing, completed, failed
    company = Column(String(255), nullable=False, index=True)  # owning company — every dataset belongs to exactly one company
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, nullable=False)
    column_name = Column(String(255))
    pii_type = Column(String(100))       # NAME, EMAIL, PHONE, ADDRESS, etc.
    detection_method = Column(String(50)) # BERT or REGEX
    count = Column(Integer, default=0)
    sample_value = Column(String(500))   # masked sample for display
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, nullable=False)
    action = Column(String(100))          # UPLOAD, DETECT, ANONYMISE, DOWNLOAD
    pii_type = Column(String(100), nullable=True)
    anonymisation_method = Column(String(100), nullable=True)  # HASH, ENCRYPT, MASK, TOKENISE
    records_affected = Column(Integer, default=0)
    block_hash = Column(String(256))      # simulated blockchain hash
    previous_hash = Column(String(256))
    timestamp = Column(DateTime, default=datetime.utcnow)
    extra_info = Column(JSON, nullable=True)


class TokenMap(Base):
    __tablename__ = "token_map"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(Integer, nullable=False)
    token = Column(String(256), unique=True, index=True)
    original_hash = Column(String(256))   # we never store plain original
    pii_type = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False, index=True)  # e.g. "acme@piishield" or "acme-auditor@piishield"
    password_hash = Column(String(255), nullable=False)
    company = Column(String(255), nullable=False, index=True)  # display name, e.g. "Acme Corp"
    role = Column(String(50), nullable=False)
    security_question = Column(String(500), nullable=True)
    security_answer_hash = Column(String(255), nullable=True)  # "admin", "auditor", or "analyst"
    created_at = Column(DateTime, default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created.")
