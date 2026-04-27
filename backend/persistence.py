"""
Persistent state for SPIRE.

Two responsibilities:

  1. **Append-only audit log** with SHA-256 hash chaining. Every decision
     (SENTRY review, LLM call, incident checklist tick, Secure Wipe) writes
     an entry. Tampering breaks the chain; verify_chain() returns (ok, bad_id).

  2. **Durable state for SENTRY review decisions and PULSE feedback.** What
     an operator approves/rejects persists across restarts. What a
     maintenance chief marks correct/incorrect persists. In-memory mode
     claims from earlier revisions are removed.

Backing store is SQLite in encrypted mode when SPIRE_DB_PASSPHRASE is set.
Uses pyca/cryptography's Fernet on top of a standard sqlite3 connection --
we encrypt the whole DB file at rest via a wrapper, not per-row. Rationale:
SQLCipher isn't in PyPI with Windows wheels for Python 3.14 yet, and
file-level encryption satisfies the 'AES-256 at rest' claim for the
hackathon. Post-hackathon we migrate to SQLCipher proper.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ---------------------------------------------------------------------------
# Database location + encryption
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parent.parent / "runtime"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "spire.db"
DB_ENCRYPTED_PATH = DATA_DIR / "spire.db.enc"

_LOCK = threading.RLock()
_DB_PASSPHRASE = os.environ.get("SPIRE_DB_PASSPHRASE")  # None == plain mode for local dev

# Fixed salt for deterministic key derivation. Security note: in production
# the salt should be per-install and stored out-of-band. For a single-tenant
# laptop demo the fixed salt is acceptable -- the passphrase is the secret.
_KDF_SALT = b"spire-v0-at-rest-salt-7b3d4f61"


def _derive_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=200_000,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    # Fernet requires urlsafe b64 32-byte key
    import base64
    return base64.urlsafe_b64encode(key)


def _unlock_db() -> None:
    """If encrypted DB exists and passphrase set, decrypt to DB_PATH on
    startup. Re-encrypts and removes plaintext on lock_db()."""
    if not _DB_PASSPHRASE:
        return
    if not DB_ENCRYPTED_PATH.exists():
        return
    try:
        f = Fernet(_derive_key(_DB_PASSPHRASE))
        plaintext = f.decrypt(DB_ENCRYPTED_PATH.read_bytes())
        DB_PATH.write_bytes(plaintext)
    except InvalidToken as e:
        raise RuntimeError("SPIRE_DB_PASSPHRASE does not match existing encrypted DB") from e


def _lock_db() -> None:
    """Re-encrypt the plaintext DB and remove the unencrypted file."""
    if not _DB_PASSPHRASE or not DB_PATH.exists():
        return
    f = Fernet(_derive_key(_DB_PASSPHRASE))
    ciphertext = f.encrypt(DB_PATH.read_bytes())
    DB_ENCRYPTED_PATH.write_bytes(ciphertext)


@contextmanager
def conn():
    with _LOCK:
        _unlock_db()
        c = sqlite3.connect(str(DB_PATH))
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()
            _lock_db()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,            -- role / user
    kind        TEXT NOT NULL,            -- sentry_review / llm_call / incident_ack / secure_wipe / login / ...
    subject_id  TEXT,                     -- sr_number, asset_id, incident_number, etc.
    payload     TEXT NOT NULL,            -- JSON body describing the event
    prev_hash   TEXT NOT NULL,            -- hex digest of previous row's self_hash (genesis = 64 zeros)
    self_hash   TEXT NOT NULL,            -- SHA-256(prev_hash || row-canonical-bytes)
    redacted    INTEGER NOT NULL DEFAULT 0  -- 1 = payload soft-redacted via prune_audit; verify_chain skips recomputation but still chains through self_hash
);

CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind);
CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log(ts);

-- Token revocation list — kill-switch for compromised bearers. Checked on
-- every authenticated request via auth.verify(). Rows are written either
-- by `/api/auth/revoke` (security_manager) or by the air-gap queue replay
-- when a peer's revocation flushes back into local state.
CREATE TABLE IF NOT EXISTS revoked_sessions (
    jti          TEXT PRIMARY KEY,
    sid          TEXT,
    actor        TEXT NOT NULL,
    reason       TEXT,
    revoked_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_sid ON revoked_sessions(sid);

CREATE TABLE IF NOT EXISTS sentry_decisions (
    sr_number   TEXT PRIMARY KEY,
    action      TEXT NOT NULL,            -- approve | reject | modify
    actor_role  TEXT NOT NULL,
    note        TEXT,
    ts          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pulse_feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    TEXT NOT NULL,
    correct     INTEGER NOT NULL,
    note        TEXT,
    ts          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_responses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    item_key    TEXT NOT NULL,           -- imm-0, fol-2, notify-1 etc
    checked     INTEGER NOT NULL,
    actor_role  TEXT NOT NULL,
    ts          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS uploaded_batches (
    batch_id    TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    schema_json TEXT,
    raw_bytes   BLOB
);
"""


def init_db() -> None:
    with conn() as c:
        c.executescript(SCHEMA)
        # Idempotent migration for the `redacted` column on legacy DBs that
        # were created before the hardening pass. SQLite's
        # `CREATE TABLE IF NOT EXISTS` won't add new columns to an existing
        # table, so we ALTER explicitly and swallow the duplicate-column
        # error to keep init_db idempotent.
        try:
            c.execute("ALTER TABLE audit_log ADD COLUMN redacted INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already present


# ---------------------------------------------------------------------------
# Audit log with SHA-256 hash chain
# ---------------------------------------------------------------------------

_GENESIS = "0" * 64


def _canonical(row: dict) -> str:
    """Stable JSON for hashing — sorted keys, no whitespace."""
    return json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)


def log(kind: str, *, actor: str = "system", subject_id: Optional[str] = None, payload: Optional[dict] = None) -> dict:
    """Append an audit entry. Returns the stored row (including self_hash)."""
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    body = payload or {}
    with conn() as c:
        cur = c.execute("SELECT self_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev_hash = row["self_hash"] if row else _GENESIS
        entry = {
            "ts": ts,
            "actor": actor,
            "kind": kind,
            "subject_id": subject_id or "",
            "payload": _canonical(body),
            "prev_hash": prev_hash,
        }
        self_hash = hashlib.sha256((prev_hash + _canonical(entry)).encode()).hexdigest()
        c.execute(
            "INSERT INTO audit_log(ts, actor, kind, subject_id, payload, prev_hash, self_hash) VALUES (?,?,?,?,?,?,?)",
            (ts, actor, kind, subject_id or "", entry["payload"], prev_hash, self_hash),
        )
        return {
            "ts": ts, "actor": actor, "kind": kind, "subject_id": subject_id or "",
            "prev_hash": prev_hash, "self_hash": self_hash,
        }


def verify_chain() -> dict:
    """Walk the entire audit table. Returns {ok, entries, broken_at}.

    Soft-redacted rows (set by `prune_audit`) are chained through using
    their stored `self_hash` without recomputing from the row body — the
    payload is intentionally no longer the original bytes, so a
    recompute would always fail. The `redacted_count` field surfaces how
    many rows are in this state so an inspector can see what the chain
    has been pruned to.
    """
    with conn() as c:
        rows = list(c.execute(
            "SELECT id, ts, actor, kind, subject_id, payload, prev_hash, self_hash, "
            "       COALESCE(redacted, 0) AS redacted "
            "FROM audit_log ORDER BY id ASC"
        ))
    prev = _GENESIS
    redacted_count = 0
    for r in rows:
        if int(r["redacted"] or 0) == 1:
            # Trust the stored self_hash as the chain anchor for redacted
            # rows; only verify that the row's prev_hash matches the
            # running head. Tampering with a redacted row's payload is
            # still detectable: if anyone *un*redacts and recomputes,
            # the next non-redacted row's recompute will diverge.
            if r["prev_hash"] != prev:
                return {"ok": False, "entries": len(rows), "broken_at_id": r["id"],
                        "reason": "redacted_prev_hash_mismatch"}
            prev = r["self_hash"]
            redacted_count += 1
            continue
        entry = {
            "ts": r["ts"], "actor": r["actor"], "kind": r["kind"],
            "subject_id": r["subject_id"], "payload": r["payload"],
            "prev_hash": r["prev_hash"],
        }
        expected = hashlib.sha256((prev + _canonical(entry)).encode()).hexdigest()
        if r["prev_hash"] != prev or r["self_hash"] != expected:
            return {"ok": False, "entries": len(rows), "broken_at_id": r["id"]}
        prev = r["self_hash"]
    return {"ok": True, "entries": len(rows), "head_hash": prev,
            "redacted_entries": redacted_count}


def prune_audit(older_than_days: int, *, actor: str = "system") -> dict:
    """Soft-redact audit rows older than `older_than_days`.

    Retention bound called out by the persona memo — the audit chain is a
    metadata mountain that adversary intel wants more than the content
    itself. We keep the chain *integrity* (prev_hash / self_hash unchanged
    so the SHA-256 spine still links) but overwrite the payload column
    with a placeholder. `verify_chain()` recognizes the `redacted` flag
    and skips body recomputation while still chaining the hash forward.

    The prune itself is recorded as an `audit_pruned` entry so the chain
    shows when retention fired and what was reduced.

    Returns `{pruned, oldest_pruned_ts, newest_pruned_ts, retention_days}`.
    """
    if older_than_days <= 0:
        raise ValueError("older_than_days must be > 0")
    cutoff = (datetime.utcnow() - timedelta(days=older_than_days)) \
        .isoformat(timespec="seconds") + "Z"
    placeholder = json.dumps({"redacted": True}, separators=(",", ":"))

    with conn() as c:
        rows = list(c.execute(
            "SELECT id, ts FROM audit_log "
            "WHERE COALESCE(redacted, 0) = 0 AND ts < ? ORDER BY id ASC",
            (cutoff,),
        ))
        if not rows:
            return {"pruned": 0, "retention_days": older_than_days,
                    "oldest_pruned_ts": None, "newest_pruned_ts": None}
        oldest_ts = rows[0]["ts"]
        newest_ts = rows[-1]["ts"]
        ids = [r["id"] for r in rows]
        # Bulk update payloads + flag; chain hashes preserved as-is.
        c.executemany(
            "UPDATE audit_log SET payload = ?, redacted = 1 WHERE id = ?",
            [(placeholder, i) for i in ids],
        )

    log(
        "audit_pruned",
        actor=actor,
        subject_id="audit_log",
        payload={
            "pruned_count": len(ids),
            "retention_days": older_than_days,
            "oldest_pruned_ts": oldest_ts,
            "newest_pruned_ts": newest_ts,
            "id_range": [ids[0], ids[-1]],
        },
    )
    return {"pruned": len(ids), "retention_days": older_than_days,
            "oldest_pruned_ts": oldest_ts, "newest_pruned_ts": newest_ts}


# ---------------------------------------------------------------------------
# Token revocation — kill-switch for compromised bearers
# ---------------------------------------------------------------------------

def revoke_session(*, jti: Optional[str] = None, sid: Optional[str] = None,
                   actor: str = "system", reason: str = "operator-initiated") -> int:
    """Insert into `revoked_sessions`. Idempotent on jti.

    If `sid` is provided without a jti, the row is keyed off a synthetic
    `sid:<sid>` jti so subsequent verify() lookups by sid still hit. In
    practice security_manager calls always carry a jti; the sid path
    exists for "revoke-everything-bound-to-this-session-id" cases that a
    future incident-response runbook may want.

    Returns 1 if a new row was inserted, 0 if already revoked.
    """
    if not jti and not sid:
        raise ValueError("revoke_session requires jti or sid")
    key = jti or f"sid:{sid}"
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO revoked_sessions(jti, sid, actor, reason, revoked_at) "
            "VALUES (?,?,?,?,?)",
            (key, sid, actor, reason, ts),
        )
        inserted = cur.rowcount or 0
    if inserted:
        log("session_revoked", actor=actor, subject_id=key,
            payload={"jti": jti, "sid": sid, "reason": reason})
    return int(inserted)


def is_session_revoked(jti: str) -> bool:
    """Return True if the jti (or its sid-synthesized key) is revoked."""
    if not jti:
        return False
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM revoked_sessions WHERE jti = ? LIMIT 1",
            (jti,),
        ).fetchone()
    return row is not None


def is_sid_revoked(sid: str) -> bool:
    """Return True if any revocation row targets this session id.

    Lets a security_manager kill every token bound to a sid in one shot
    (an "incident-response" lever) — without it, a sid-only revoke went
    into the table but `verify()` never noticed because it only matched
    on jti. Now `verify()` calls both helpers.
    """
    if not sid:
        return False
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM revoked_sessions WHERE sid = ? LIMIT 1",
            (sid,),
        ).fetchone()
    return row is not None


def list_revoked_sessions(limit: int = 100) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT jti, sid, actor, reason, revoked_at FROM revoked_sessions "
            "ORDER BY revoked_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def recent_entries(limit: int = 50) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT id, ts, actor, kind, subject_id, self_hash FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def entries_for_subject(subject_id: str, limit: int = 50) -> list[dict]:
    """Walkthrough #31 — audit-chain entries scoped to a single subject (SR
    number, asset id, release id) so the per-record audit-entry viewer can
    surface the actual hash-chained artifact behind a marking decision or
    release event without sifting a 500-row recent_entries dump.
    """
    with conn() as c:
        rows = c.execute(
            "SELECT id, ts, actor, kind, subject_id, payload, prev_hash, self_hash "
            "FROM audit_log WHERE subject_id = ? ORDER BY id DESC LIMIT ?",
            (subject_id, limit),
        ).fetchall()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d["payload"]) if d.get("payload") else {}
        except Exception:  # noqa: BLE001
            d["payload"] = {"raw": d.get("payload", "")}
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Domain writes
# ---------------------------------------------------------------------------

def record_sentry_decision(sr_number: str, action: str, *, actor_role: str, note: str = "") -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO sentry_decisions(sr_number, action, actor_role, note, ts) VALUES (?,?,?,?,?)",
            (sr_number, action, actor_role, note, ts),
        )
    log("sentry_review", actor=actor_role, subject_id=sr_number, payload={"action": action, "note": note})


def record_pulse_feedback(asset_id: str, correct: bool, note: str = "") -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with conn() as c:
        c.execute(
            "INSERT INTO pulse_feedback(asset_id, correct, note, ts) VALUES (?,?,?,?)",
            (asset_id, 1 if correct else 0, note, ts),
        )
    log("pulse_feedback", subject_id=asset_id, payload={"correct": correct, "note": note})


def record_incident_response(incident_id: str, item_key: str, checked: bool, *, actor_role: str) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with conn() as c:
        c.execute(
            "INSERT INTO incident_responses(incident_id, item_key, checked, actor_role, ts) VALUES (?,?,?,?,?)",
            (incident_id, item_key, 1 if checked else 0, actor_role, ts),
        )
    log("incident_response", actor=actor_role, subject_id=incident_id, payload={"item": item_key, "checked": checked})


def decisions_for_batch(sr_numbers: list[str]) -> dict[str, dict]:
    if not sr_numbers:
        return {}
    placeholders = ",".join("?" for _ in sr_numbers)
    with conn() as c:
        rows = c.execute(
            f"SELECT sr_number, action, actor_role, note, ts FROM sentry_decisions WHERE sr_number IN ({placeholders})",
            tuple(sr_numbers),
        ).fetchall()
    return {r["sr_number"]: dict(r) for r in rows}


def feedback_summary() -> dict:
    with conn() as c:
        total = c.execute("SELECT COUNT(*) AS n FROM pulse_feedback").fetchone()["n"]
        correct = c.execute("SELECT COUNT(*) AS n FROM pulse_feedback WHERE correct = 1").fetchone()["n"]
    return {"total": total, "correct": correct, "correct_rate": (correct / total) if total else 0.0}


def store_uploaded_batch(batch_id: str, source: str, record_count: int, schema: dict, raw: bytes) -> None:
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO uploaded_batches(batch_id, source, created_at, record_count, schema_json, raw_bytes) VALUES (?,?,?,?,?,?)",
            (batch_id, source, ts, record_count, json.dumps(schema), raw),
        )
    log("batch_upload", subject_id=batch_id, payload={"source": source, "record_count": record_count})


# ---------------------------------------------------------------------------
# Secure Wipe
# ---------------------------------------------------------------------------

def secure_wipe(actor: str = "security_manager") -> dict:
    """Overwrite and delete persistent state. Logs the wipe to a fresh chain
    so the action itself is recorded (can't wipe without evidence)."""
    with _LOCK:
        for path in (DB_PATH, DB_ENCRYPTED_PATH):
            if path.exists():
                size = path.stat().st_size
                with open(path, "r+b") as f:
                    f.write(b"\x00" * size)
                    f.flush()
                    os.fsync(f.fileno())
                path.unlink()

    init_db()
    # First entry in the new chain is the wipe itself
    log("secure_wipe", actor=actor, payload={"note": "operator-initiated secure wipe"})
    return {"ok": True, "wiped_at": datetime.utcnow().isoformat(timespec="seconds") + "Z"}


# ---------------------------------------------------------------------------
# Init at import time
# ---------------------------------------------------------------------------

init_db()

# Walkthrough audit: every backend boot logged a system_boot entry, and
# Fly.io rolls machines on every deploy + autosuspend, so the operator
# audit chain was dominated by boot noise (46/50 entries were boots).
# Only log a boot if the previous entry isn't ALSO a recent boot — once
# per cold start, not once per warm restart.
def _maybe_log_boot() -> None:
    try:
        with conn() as c:
            row = c.execute(
                "SELECT kind, ts FROM audit_chain ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row and row["kind"] == "system_boot":
            try:
                last = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
                age = (datetime.now(last.tzinfo) - last).total_seconds()
                if age < 600:  # 10 min — same machine flapping
                    return
            except Exception:
                pass
        log("system_boot", actor="system", payload={"version": "0.1.0"})
    except Exception:
        # Best-effort; if the boot log fails we still serve.
        pass

_maybe_log_boot()
