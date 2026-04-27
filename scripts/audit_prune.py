#!/usr/bin/env python3
"""Operator helper: soft-redact audit rows older than the retention bound.

The audit chain accumulates one row per sensitive operation. Over months
of forward-deployed operation that's a metadata mountain — exactly the
data an adversary wants if they ever capture the disk. This script
implements the retention half of the at-rest story (the encryption half
already lives in `backend.persistence` via `SPIRE_DB_PASSPHRASE`).

The prune is *soft-redaction*: payloads are overwritten with a
placeholder, but the SHA-256 hash chain stays intact (verify_chain()
treats redacted rows as opaque anchors and continues chaining through
their stored self_hash). The prune itself is recorded as an
`audit_pruned` entry so an inspector can see when retention fired.

Usage:
    python scripts/audit_prune.py              # uses SPIRE_AUDIT_RETENTION_DAYS or 90
    python scripts/audit_prune.py --days 30
    python scripts/audit_prune.py --dry-run    # report what would be pruned
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Audit prune is a maintenance op, not a serving path — demo mode is fine
# and we don't want to require an operator to remember the secret to run
# the script.
os.environ.setdefault("SPIRE_DEMO_MODE", "1")

from backend.persistence import init_db, prune_audit, conn  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int,
                        default=int(os.environ.get("SPIRE_AUDIT_RETENTION_DAYS", "90")),
                        help="Soft-redact audit rows older than N days (default: env SPIRE_AUDIT_RETENTION_DAYS or 90).")
    parser.add_argument("--actor", default="audit_prune.py",
                        help="Actor recorded in the audit_pruned entry.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would be pruned without writing.")
    args = parser.parse_args()

    init_db()

    if args.dry_run:
        from datetime import datetime, timedelta
        cutoff = (datetime.utcnow() - timedelta(days=args.days)) \
            .isoformat(timespec="seconds") + "Z"
        with conn() as c:
            count = c.execute(
                "SELECT COUNT(*) AS n FROM audit_log "
                "WHERE COALESCE(redacted, 0) = 0 AND ts < ?",
                (cutoff,),
            ).fetchone()["n"]
        print(f"DRY-RUN: would soft-redact {count} rows older than {cutoff}.")
        return 0

    out = prune_audit(args.days, actor=args.actor)
    print(f"Pruned {out['pruned']} rows older than {args.days} days "
          f"(oldest={out['oldest_pruned_ts']} newest={out['newest_pruned_ts']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
