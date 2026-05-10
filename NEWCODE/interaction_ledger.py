"""
Persistent Merkleized interaction ledger for SAGA agents.
"""
import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import saga.config
from saga.security.merkle_tree import (
    generate_merkle_proof as merkle_generate_proof,
    generate_merkle_root as merkle_generate_root,
    verify_merkle_proof as merkle_verify_proof,
)


ZERO_HASH = "0" * 64
DEFAULT_BATCH_SIZE = 100


def _default_ledger_dir() -> Path:
    repo_root = Path(saga.config.ROOT_DIR).parent
    return Path(os.getenv("SAGA_LEDGER_DIR", repo_root / "reports" / "security"))


def _canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def digest_payload(payload: Any) -> str:
    if isinstance(payload, bytes):
        payload_bytes = payload
    elif isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    else:
        payload_bytes = _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(payload_bytes).hexdigest()


def compute_interaction_hash(record: Dict[str, Any]) -> str:
    fields = {
        "interaction_id": record["interaction_id"],
        "timestamp": record["timestamp"],
        "source_agent": record["source_agent"],
        "destination_agent": record["destination_agent"],
        "session_id": record["session_id"],
        "payload_digest": record["payload_digest"],
        "previous_hash": record["previous_hash"],
    }
    return hashlib.sha256(_canonical_json(fields).encode("utf-8")).hexdigest()


class InteractionLedger:
    """
    Append-only JSONL interaction ledger with hash-chain and Merkle checkpoints.

    The implementation is intentionally storage-light and file-backed by default
    so it can run in local experiments without MongoDB schema changes. A Mongo
    implementation can use the same public methods.
    """
    _lock = threading.Lock()

    def __init__(
        self,
        ledger_dir: Optional[os.PathLike] = None,
        batch_size: Optional[int] = None,
        ledger_filename: str = "interaction_ledger.jsonl",
        roots_filename: str = "merkle_roots.jsonl",
    ):
        self.ledger_dir = Path(ledger_dir) if ledger_dir is not None else _default_ledger_dir()
        self.batch_size = int(os.getenv("SAGA_LEDGER_BATCH_SIZE", batch_size or DEFAULT_BATCH_SIZE))
        self.ledger_path = self.ledger_dir / ledger_filename
        self.roots_path = self.ledger_dir / roots_filename
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path.touch(exist_ok=True)
        self.roots_path.touch(exist_ok=True)

    def append_interaction(
        self,
        source_agent: str,
        destination_agent: str,
        session_id: str,
        payload: Any,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            previous_hash = self._last_interaction_hash()
            record = {
                "interaction_id": str(uuid.uuid4()),
                "timestamp": timestamp if timestamp is not None else time.time(),
                "source_agent": source_agent,
                "destination_agent": destination_agent,
                "session_id": session_id,
                "payload_digest": digest_payload(payload),
                "previous_hash": previous_hash,
            }
            record["interaction_hash"] = compute_interaction_hash(record)

            with self.ledger_path.open("a", encoding="utf-8") as handle:
                handle.write(_canonical_json(record) + "\n")

            records = self.load_records()
            if len(records) % self.batch_size == 0:
                self._persist_merkle_root(records)
            return record

    def load_records(self) -> List[Dict[str, Any]]:
        records = []
        with self.ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def load_roots(self) -> List[Dict[str, Any]]:
        roots = []
        with self.roots_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    roots.append(json.loads(line))
        return roots

    def build_merkle_tree(self, interaction_hashes: Iterable[str]):
        from saga.security.merkle_tree import build_merkle_tree

        return build_merkle_tree(interaction_hashes)

    def generate_merkle_root(self, interaction_hashes: Optional[Iterable[str]] = None) -> Optional[str]:
        hashes = list(interaction_hashes) if interaction_hashes is not None else [
            record["interaction_hash"] for record in self.load_records()
        ]
        return merkle_generate_root(hashes)

    def generate_merkle_proof(self, interaction_hash: str) -> Dict[str, Any]:
        records = self.load_records()
        hashes = [record["interaction_hash"] for record in records]
        if interaction_hash not in hashes:
            return {"interaction_hash": interaction_hash, "proof": [], "merkle_root": None}

        index = hashes.index(interaction_hash)
        batch_start = (index // self.batch_size) * self.batch_size
        batch_end = min(batch_start + self.batch_size, len(hashes))
        batch_hashes = hashes[batch_start:batch_end]
        return {
            "interaction_hash": interaction_hash,
            "batch_start": batch_start,
            "batch_end": batch_end - 1,
            "merkle_root": merkle_generate_root(batch_hashes),
            "proof": merkle_generate_proof(batch_hashes, interaction_hash),
        }

    def verify_merkle_proof(self, interaction_hash: str, proof: List[dict], merkle_root: str) -> bool:
        return merkle_verify_proof(interaction_hash, proof, merkle_root)

    def verify_ledger_integrity(self) -> Dict[str, Any]:
        records = self.load_records()
        errors = []
        previous_hash = ZERO_HASH

        for index, record in enumerate(records):
            expected_hash = compute_interaction_hash(record)
            if record.get("interaction_hash") != expected_hash:
                errors.append({
                    "type": "hash_mismatch",
                    "index": index,
                    "interaction_id": record.get("interaction_id"),
                })
            if record.get("previous_hash") != previous_hash:
                errors.append({
                    "type": "chain_break",
                    "index": index,
                    "interaction_id": record.get("interaction_id"),
                    "expected_previous_hash": previous_hash,
                    "actual_previous_hash": record.get("previous_hash"),
                })
            previous_hash = record.get("interaction_hash")

        root_errors = self._verify_persisted_roots(records)
        errors.extend(root_errors)
        return {
            "valid": not errors,
            "record_count": len(records),
            "latest_hash": previous_hash if records else ZERO_HASH,
            "merkle_root": self.generate_merkle_root(),
            "errors": errors,
        }

    def _last_interaction_hash(self) -> str:
        last_hash = ZERO_HASH
        with self.ledger_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last_hash = json.loads(line)["interaction_hash"]
        return last_hash

    def _persist_merkle_root(self, records: List[Dict[str, Any]]) -> None:
        batch_start = len(records) - self.batch_size
        batch_end = len(records) - 1
        batch_hashes = [
            record["interaction_hash"]
            for record in records[batch_start:batch_end + 1]
        ]
        root_record = {
            "batch_start": batch_start,
            "batch_end": batch_end,
            "record_count": len(batch_hashes),
            "merkle_root": merkle_generate_root(batch_hashes),
            "created_at": time.time(),
        }
        roots = self.load_roots()
        if roots and roots[-1].get("batch_start") == batch_start:
            return
        with self.roots_path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical_json(root_record) + "\n")

    def _verify_persisted_roots(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        errors = []
        roots = self.load_roots()
        hashes = [record["interaction_hash"] for record in records]
        for root in roots:
            batch_start = root.get("batch_start")
            batch_end = root.get("batch_end")
            if batch_start is None or batch_end is None:
                errors.append({"type": "malformed_merkle_root", "root": root})
                continue
            if batch_end >= len(hashes):
                errors.append({"type": "merkle_root_points_past_ledger", "root": root})
                continue
            batch_hashes = hashes[batch_start:batch_end + 1]
            expected_root = merkle_generate_root(batch_hashes)
            if root.get("merkle_root") != expected_root:
                errors.append({
                    "type": "merkle_root_mismatch",
                    "batch_start": batch_start,
                    "batch_end": batch_end,
                    "expected_merkle_root": expected_root,
                    "actual_merkle_root": root.get("merkle_root"),
                })
        return errors
