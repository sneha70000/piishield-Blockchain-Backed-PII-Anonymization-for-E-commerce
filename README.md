# PIIShield — Blockchain-Backed PII Anonymisation for E-commerce

A privacy-compliant data anonymisation platform built for e-commerce datasets.

## Features
- BERT-based NER + Regex PII detection
- Multiple anonymisation techniques (masking, hashing, tokenization)
- Hyperledger Fabric blockchain audit trail
- Role-based access (Admin, Audit Chain, Analytics)
- Supports CSV, JSON, XLSX datasets

## Tech Stack
- Backend: FastAPI + Python 3.11
- Frontend: HTML, CSS, JavaScript
- AI Model: dslim/bert-base-NER (HuggingFace)
- Blockchain: Hyperledger Fabric 2.5 + Node.js bridge
- Database: SQLite

## Setup
1. Start Docker
2. Run ~/piishield_scripts/start_piishield.sh
3. Open http://localhost:3000/login.html

## College: VCET 2025-26
