"""
blockchain.py (Fabric-backed version)

Drop-in replacement for the original hash-chain-in-a-JSON-file blockchain.py.
Same public function signatures AND same snake_case key names in returned
dicts, so main.py requires NO changes.

Calls go through HTTP to the Node.js bridge service (piishield-bridge/app.js),
which talks to the real Hyperledger Fabric network via the fabric-network SDK.
The bridge/chaincode use camelCase internally (JS convention) — this file
translates those back to the snake_case keys main.py expects.
"""

import os
import requests

BRIDGE_URL = os.getenv("FABRIC_BRIDGE_URL", "http://localhost:4000")
TIMEOUT = 15


def _normalize_block(b):
    """Convert the bridge's camelCase block into the original snake_case shape."""
    return {
        "index": b.get("index"),
        "timestamp": b.get("timestamp"),
        "action": b.get("action"),
        "dataset_id": b.get("datasetId"),
        "pii_type": b.get("piiType"),
        "anonymisation_method": b.get("anonymisationMethod"),
        "records_affected": b.get("recordsAffected"),
        "payload": b.get("payload"),
        "previous_hash": b.get("previousHash"),
        "block_hash": b.get("blockHash"),
    }


def add_block(action, dataset_id, payload, pii_type=None, anonymisation_method=None, records_affected=0):
    resp = requests.post(
        f"{BRIDGE_URL}/block",
        json={
            "action": action,
            "datasetId": dataset_id,
            "piiType": pii_type,
            "anonymisationMethod": anonymisation_method,
            "recordsAffected": records_affected,
            "payload": payload,
        },
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return _normalize_block(resp.json())


def get_chain(dataset_id=None):
    if dataset_id is not None:
        resp = requests.get(f"{BRIDGE_URL}/blocks/dataset/{dataset_id}", timeout=TIMEOUT)
    else:
        resp = requests.get(f"{BRIDGE_URL}/blocks", timeout=TIMEOUT)
    resp.raise_for_status()
    return [_normalize_block(b) for b in resp.json()]


def verify_chain():
    resp = requests.get(f"{BRIDGE_URL}/verify", timeout=TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return {
        "valid": data.get("valid"),
        "broken_at": data.get("brokenAt"),
        "total_blocks": data.get("totalBlocks"),
    }
