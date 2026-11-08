"""SQLite state of one node: pinned peers, inbox, outbox and replay protection."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS peers (
    name        TEXT PRIMARY KEY,
    sign_pub    TEXT NOT NULL UNIQUE,
    box_pub     TEXT NOT NULL,
    url         TEXT NOT NULL,
    allow_tasks INTEGER NOT NULL DEFAULT 0,
    added_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    peer        TEXT NOT NULL,
    direction   TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    kind        TEXT NOT NULL,
    body        TEXT NOT NULL,
    in_reply_to TEXT,
    ts          INTEGER NOT NULL,
    read        INTEGER NOT NULL DEFAULT 0,
    -- outbox only: the sealed envelope, delivery state and retry bookkeeping
    envelope    TEXT,
    delivered   INTEGER NOT NULL DEFAULT 0,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT
);
-- ids of control envelopes (pull) already accepted, for replay protection
CREATE TABLE IF NOT EXISTS seen (
    id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS messages_reply ON messages(in_reply_to);
CREATE INDEX IF NOT EXISTS messages_unread ON messages(direction, read);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    # ---- peers -------------------------------------------------------------

    def add_peer(self, name: str, sign_pub: str, box_pub: str, url: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO peers(name, sign_pub, box_pub, url, added_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET sign_pub=excluded.sign_pub, "
                "box_pub=excluded.box_pub, url=excluded.url",
                (name, sign_pub, box_pub, url, time.time()),
            )

    def remove_peer(self, name: str) -> bool:
        with self._lock:
            return self._db.execute("DELETE FROM peers WHERE name=?", (name,)).rowcount > 0

    def set_allow_tasks(self, name: str, allow: bool) -> bool:
        with self._lock:
            cur = self._db.execute(
                "UPDATE peers SET allow_tasks=? WHERE name=?", (int(allow), name)
            )
            return cur.rowcount > 0

    def peers(self) -> list[dict]:
        return [dict(r) for r in self._db.execute("SELECT * FROM peers ORDER BY name")]

    def peer(self, name: str) -> dict | None:
        r = self._db.execute("SELECT * FROM peers WHERE name=?", (name,)).fetchone()
        return dict(r) if r else None

    def peer_by_key(self, sign_pub: str) -> dict | None:
        r = self._db.execute("SELECT * FROM peers WHERE sign_pub=?", (sign_pub,)).fetchone()
        return dict(r) if r else None

    # ---- messages ----------------------------------------------------------

    def save_incoming(self, header: dict, peer: str, body: dict) -> bool:
        """Store an inbound message. False if this id was already seen (replay)."""
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO messages(id, peer, direction, kind, body, in_reply_to, ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (header["id"], peer, "in", header["kind"], json.dumps(body),
                 header["in_reply_to"], header["ts"]),
            )
            return cur.rowcount > 0

    def first_seen(self, msg_id: str, ts: int) -> bool:
        """Record a control envelope id. False if it was already used."""
        with self._lock:
            self._db.execute("DELETE FROM seen WHERE ts < ?", (int(time.time()) - 8 * 86400,))
            cur = self._db.execute("INSERT OR IGNORE INTO seen(id, ts) VALUES (?,?)", (msg_id, ts))
            return cur.rowcount > 0

    def queued_for(self, peer: str, limit: int = 50) -> list[dict]:
        """Undelivered envelopes for a peer that collects its mail by pulling."""
        rows = self._db.execute(
            "SELECT envelope FROM messages WHERE direction='out' AND delivered=0 AND peer=? "
            "ORDER BY ts LIMIT ?",
            (peer, limit),
        )
        return [json.loads(r["envelope"]) for r in rows]

    def ack(self, peer: str, ids: list[str]) -> None:
        with self._lock:
            self._db.executemany(
                "UPDATE messages SET delivered=1, last_error=NULL "
                "WHERE id=? AND peer=? AND direction='out'",
                [(i, peer) for i in ids],
            )

    def queue_outgoing(self, env: dict, peer: str, body: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO messages(id, peer, direction, kind, body, in_reply_to, ts, envelope) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (env["id"], peer, "out", env["kind"], json.dumps(body),
                 env["in_reply_to"], env["ts"], json.dumps(env)),
            )

    def mark_delivered(self, msg_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE messages SET delivered=1, attempts=attempts+1, last_error=NULL WHERE id=?",
                (msg_id,),
            )

    def mark_failed(self, msg_id: str, error: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE messages SET attempts=attempts+1, last_error=? WHERE id=?",
                (error[:500], msg_id),
            )

    def pending_outbox(self, max_attempts: int) -> list[dict]:
        rows = self._db.execute(
            "SELECT m.* FROM messages m JOIN peers p ON p.name = m.peer "
            "WHERE m.direction='out' AND m.delivered=0 AND m.attempts<? AND p.url != '' "
            "ORDER BY m.ts",
            (max_attempts,),
        )
        return [dict(r) for r in rows]

    def undelivered(self) -> list[dict]:
        """Everything not yet delivered, including mail waiting for a pull."""
        rows = self._db.execute(
            "SELECT * FROM messages WHERE direction='out' AND delivered=0 ORDER BY ts")
        return [dict(r) for r in rows]

    def inbox(
        self, unread_only: bool = True, mark_read: bool = True, limit: int = 50
    ) -> list[dict]:
        q = "SELECT * FROM messages WHERE direction='in'"
        if unread_only:
            q += " AND read=0"
        q += " ORDER BY ts LIMIT ?"
        rows = [_public(r) for r in self._db.execute(q, (limit,))]
        if mark_read and rows:
            with self._lock:
                self._db.executemany(
                    "UPDATE messages SET read=1 WHERE id=?", [(r["id"],) for r in rows]
                )
        return rows

    def reply_to(self, msg_id: str) -> dict | None:
        r = self._db.execute(
            "SELECT * FROM messages WHERE direction='in' AND in_reply_to=? ORDER BY ts LIMIT 1",
            (msg_id,),
        ).fetchone()
        if r is None:
            return None
        with self._lock:
            self._db.execute("UPDATE messages SET read=1 WHERE id=?", (r["id"],))
        return _public(r)

    def message(self, msg_id: str) -> dict | None:
        r = self._db.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
        return _public(r) if r else None


def _public(row: sqlite3.Row) -> dict:
    d = dict(row)
    d.pop("envelope", None)
    d["body"] = json.loads(d["body"])
    return d
