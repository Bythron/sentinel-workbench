"""SQLite evidence log with chained digests for accidental-change detection."""

import hashlib
import json
import sqlite3
from pathlib import Path


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class EvidenceStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, previous_hash TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL)")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def append(self, payload: dict) -> int:
        encoded = _canonical(payload)
        with self.db:
            previous = self.db.execute("SELECT digest FROM evidence ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = previous[0] if previous else "0" * 64
            digest = hashlib.sha256((prev_hash + encoded).encode()).hexdigest()
            cursor = self.db.execute("INSERT INTO evidence(previous_hash,digest,payload) VALUES(?,?,?)", (prev_hash, digest, encoded))
        return int(cursor.lastrowid)

    def records(self) -> list[dict]:
        rows = self.db.execute("SELECT id,previous_hash,digest,payload FROM evidence ORDER BY id").fetchall()
        return [{"id": row[0], "previous_hash": row[1], "digest": row[2], "payload": json.loads(row[3])} for row in rows]

    def verify(self) -> bool:
        previous = "0" * 64
        for row in self.records():
            encoded = _canonical(row["payload"])
            expected = hashlib.sha256((previous + encoded).encode()).hexdigest()
            if row["previous_hash"] != previous or row["digest"] != expected:
                return False
            previous = row["digest"]
        return True

