"""Result persistence: JSON Lines (always) and SQLite (optional).

Layout of a run directory::

    runs/<run_id>/
        manifest.json     # clock anchor, host, privileges, probe parameters
        records.jsonl     # one unified Record per line
        records.sqlite    # optional, same rows
        capture.pcap      # optional, from the sniff probe
        report.html / report.json
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from netprobe.core.session import Record

RECORDS_JSONL = "records.jsonl"
RECORDS_SQLITE = "records.sqlite"
MANIFEST = "manifest.json"


class Storage(Protocol):
    def write(self, record: Record) -> None: ...
    def close(self) -> None: ...


class JsonlStorage:
    def __init__(self, path: str | Path, flush_every: int = 64) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        self._flush_every = max(1, flush_every)
        self._pending = 0

    def write(self, record: Record) -> None:
        self._fh.write(json.dumps(record.to_dict(), separators=(",", ":"), sort_keys=True))
        self._fh.write("\n")
        self._pending += 1
        if self._pending >= self._flush_every:
            self._fh.flush()
            self._pending = 0

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()


class SqliteStorage:
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS records (
        ts_monotonic INTEGER NOT NULL,
        ts_wall REAL NOT NULL,
        probe TEXT NOT NULL,
        target TEXT NOT NULL,
        metric TEXT NOT NULL,
        value REAL NOT NULL,
        unit TEXT NOT NULL,
        meta TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_records_ts ON records(ts_monotonic);
    CREATE INDEX IF NOT EXISTS idx_records_pm ON records(probe, metric);
    """

    def __init__(self, path: str | Path, commit_every: int = 500) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Writes are serialized by the Session lock.
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(self._SCHEMA)
        self._commit_every = max(1, commit_every)
        self._pending = 0

    def write(self, record: Record) -> None:
        self._db.execute(
            "INSERT INTO records VALUES (?,?,?,?,?,?,?,?)",
            (
                record.ts_monotonic,
                record.ts_wall,
                record.probe,
                record.target,
                record.metric,
                record.value,
                record.unit,
                json.dumps(record.meta, sort_keys=True),
            ),
        )
        self._pending += 1
        if self._pending >= self._commit_every:
            self._db.commit()
            self._pending = 0

    def close(self) -> None:
        try:
            self._db.commit()
        finally:
            self._db.close()


class MemoryStorage:
    """No-op persistence (records are still kept in the Session)."""

    def write(self, record: Record) -> None:  # noqa: D401
        return None

    def close(self) -> None:
        return None


class MultiStorage:
    def __init__(self, backends: Iterable[Storage]) -> None:
        self.backends = list(backends)

    def write(self, record: Record) -> None:
        for b in self.backends:
            b.write(record)

    def close(self) -> None:
        for b in self.backends:
            b.close()


def open_storage(out_dir: Path | None, sqlite: bool = False) -> Storage:
    if out_dir is None:
        return MemoryStorage()
    backends: list[Storage] = [JsonlStorage(out_dir / RECORDS_JSONL)]
    if sqlite:
        backends.append(SqliteStorage(out_dir / RECORDS_SQLITE))
    return MultiStorage(backends)


def write_manifest(out_dir: Path, manifest: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / MANIFEST
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_manifest(run_dir: str | Path) -> dict:
    path = Path(run_dir) / MANIFEST
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def load_records(path: str | Path) -> list[Record]:
    """Load records from a run directory, a .jsonl file or a .sqlite file."""
    from netprobe.core.session import Record

    p = Path(path)
    if p.is_dir():
        if (p / RECORDS_JSONL).exists():
            p = p / RECORDS_JSONL
        elif (p / RECORDS_SQLITE).exists():
            p = p / RECORDS_SQLITE
        else:
            raise FileNotFoundError(f"no records found in {path}")
    out: list[Record] = []
    if p.suffix == ".sqlite":
        db = sqlite3.connect(p)
        try:
            for row in db.execute(
                "SELECT ts_monotonic, ts_wall, probe, target, metric, value, unit, meta "
                "FROM records ORDER BY ts_monotonic"
            ):
                out.append(Record(*row[:7], meta=json.loads(row[7])))
        finally:
            db.close()
    else:
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(Record.from_dict(json.loads(line)))
    out.sort(key=lambda r: r.ts_monotonic)
    return out
