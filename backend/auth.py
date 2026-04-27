"""
Session-bound authentication.

Replaces the spoofable `?role=...` URL parameter with a server-minted,
HMAC-signed bearer token. The token is the *only* trusted source for the
caller's effective role on every sensitive endpoint; it is also the actor
recorded in the audit chain.

Token format (URL-safe base64, three dot-separated parts):

    <header>.<payload>.<signature>

  header   = b64(json({"alg":"HS256","typ":"spire-session"}))
  payload  = b64(json({
                "role": "<role>",            # gate string
                "unit": "<unit>" | null,     # bearer-claimed unit (CAC-derived in prod)
                "billet": "<billet>" | null,
                "attested_by": "DEMO_MODE" | "<idp>",
                "attested_at": <unix>,       # when the attestation was minted upstream
                "iat": <unix>,
                "exp": <unix>,
                "sid": "<rand>",             # session id (for human-friendly correlation)
                "jti": "<rand>",             # token id (the revocation handle)
            }))
  signature = b64(HMAC-SHA256(secret, header + "." + payload))

The signing secret comes from `SPIRE_SESSION_SECRET`. Outside demo mode
(`SPIRE_DEMO_MODE` not set) this env var is REQUIRED; the process refuses
to start without it. Demo mode falls back to a process-local random secret
so a developer can run the dropdown-driven persona switcher without
provisioning anything.

The open `POST /api/auth/session` endpoint — which mints a token for any
client-supplied role — is also gated behind demo mode. In production the
mint path must be replaced by an IdP-backed adapter (CAC / Keycloak /
SAML) that derives `role`, `unit`, and `billet` from a verified upstream
identity assertion. The `Principal` envelope and `current_principal`
dependency are stable across that swap so route code does not change.

Revocation: every token carries a `jti`. `verify()` checks the
`revoked_sessions` table on every request. The `/revoke` endpoint
(security_manager only) writes to that table and notifies any registered
sinks — `routes.system` registers a sink that pushes the revocation onto
the air-gap queue so the kill-switch propagates on next sync.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from typing import Any, Callable, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from .scoping import REVOKE_ROLES, require_role


# ---- Mode + secret material -----------------------------------------------

def _truthy(v: Optional[str]) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


SPIRE_DEMO_MODE: bool = _truthy(os.environ.get("SPIRE_DEMO_MODE"))

_DEFAULT_TTL_SECONDS = 8 * 60 * 60  # 8h — covers a long shift without re-mint.
_ALG_HEADER = {"alg": "HS256", "typ": "spire-session"}

# Roles known to the system. Any mint request for a role outside this set is
# rejected at the door so a client can't fabricate a privileged-sounding
# string and have it pass the bearer check downstream.
KNOWN_ROLES = frozenset({
    "maintenance_chief",
    "g4",
    "mef_commander",
    "data_custodian",
    "security_manager",
})


def _load_secret() -> bytes:
    raw = os.environ.get("SPIRE_SESSION_SECRET", "").strip()
    if raw:
        if len(raw) < 16:
            print("[SPIRE] WARN: SPIRE_SESSION_SECRET is shorter than 16 bytes — generate a longer secret.")
        return raw.encode("utf-8")
    if not SPIRE_DEMO_MODE:
        # Refuse to boot. The persona memo treated the ephemeral fallback as a
        # silent footgun (per-process secrets break multi-replica + air-gap
        # sync). Outside demo, the operator must commit to a real secret.
        sys.stderr.write(
            "\n[SPIRE] FATAL: SPIRE_SESSION_SECRET is required outside demo mode.\n"
            "  - Set SPIRE_SESSION_SECRET to at least 32 random bytes (e.g. "
            "`python -c 'import secrets; print(secrets.token_urlsafe(48))'`).\n"
            "  - Or, for local development only, export SPIRE_DEMO_MODE=1.\n"
        )
        raise SystemExit(2)
    rand = secrets.token_urlsafe(48)
    print("[SPIRE] DEMO MODE — ephemeral session secret generated. Tokens will not survive restart.")
    return rand.encode("utf-8")


_SECRET = _load_secret()


# ---- Encoding helpers ------------------------------------------------------

def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(header_b64: str, payload_b64: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(_SECRET, msg, hashlib.sha256).digest()
    return _b64u_encode(sig)


# ---- Principal envelope ----------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Principal:
    """The structured identity a verified bearer carries.

    `role` is the only field used for gate decisions today. The other
    fields are populated in demo mode with safe defaults; in production
    they will be derived from the upstream IdP assertion (CAC subject /
    Keycloak claims). Route code can already read them — scoping logic
    that intersects bearer-claimed `unit` with the role's allowed_units
    can be added in `scoping.py` without changing call sites.
    """
    role: str
    unit: Optional[str] = None
    billet: Optional[str] = None
    attested_by: str = "DEMO_MODE"
    attested_at: int = 0
    iat: int = 0
    exp: int = 0
    sid: str = ""
    jti: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ---- Mint / verify ---------------------------------------------------------

def mint(
    role: str,
    *,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    unit: Optional[str] = None,
    billet: Optional[str] = None,
    attested_by: str = "DEMO_MODE",
) -> dict:
    """Mint a signed session token for `role`.

    Returns `{token, role, expires_at, session_id, jti, principal}`.
    Raises 400 if role unknown.
    """
    if role not in KNOWN_ROLES:
        raise HTTPException(
            status_code=400,
            detail={"error": "UnknownRole", "role_seen": role,
                    "roles_allowed": sorted(KNOWN_ROLES)},
        )
    now = int(time.time())
    exp = now + max(60, int(ttl_seconds))
    sid = secrets.token_urlsafe(12)
    jti = secrets.token_urlsafe(16)

    header_b64 = _b64u_encode(json.dumps(_ALG_HEADER, separators=(",", ":")).encode())
    payload = {
        "role": role,
        "unit": unit,
        "billet": billet,
        "attested_by": attested_by,
        "attested_at": now,
        "iat": now,
        "exp": exp,
        "sid": sid,
        "jti": jti,
    }
    payload_b64 = _b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig_b64 = _sign(header_b64, payload_b64)
    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    return {
        "token": token,
        "role": role,
        "expires_at": exp,
        "session_id": sid,
        "jti": jti,
        "principal": payload,
    }


def _check_revoked(jti: str, sid: str = "") -> bool:
    """Return True if the jti or sid is in the revocation table.

    Lazily imports persistence so module load order stays clean. The
    persistence layer raises HTTPException(503, RevocationCheckFailed)
    on transient errors via the caller in `verify()` — we re-raise so
    auth fails CLOSED rather than admitting a token whose revocation
    state is unknown. (Earlier this fell open on persistence error,
    which the security review correctly flagged.)
    """
    if not jti and not sid:
        return False
    from .persistence import is_session_revoked, is_sid_revoked
    if jti and is_session_revoked(jti):
        return True
    if sid and is_sid_revoked(sid):
        return True
    return False


def verify(token: str) -> dict:
    """Validate signature + expiry + revocation. Returns decoded payload. Raises 401."""
    if not token or token.count(".") != 2:
        raise HTTPException(status_code=401, detail={"error": "MalformedToken"})
    header_b64, payload_b64, sig_b64 = token.split(".")
    if not header_b64 or not payload_b64 or not sig_b64:
        raise HTTPException(status_code=401, detail={"error": "MalformedToken"})
    expected = _sign(header_b64, payload_b64)
    # Constant-time compare so a forger can't probe byte-by-byte.
    if not hmac.compare_digest(expected, sig_b64):
        raise HTTPException(status_code=401, detail={"error": "BadSignature"})
    try:
        payload = json.loads(_b64u_decode(payload_b64))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=401, detail={"error": "MalformedPayload",
                                                     "reason": str(e)})
    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail={"error": "MalformedPayload",
                                                     "reason": "non-object"})
    role = payload.get("role")
    exp = int(payload.get("exp", 0) or 0)
    if role not in KNOWN_ROLES:
        raise HTTPException(status_code=401, detail={"error": "UnknownRole",
                                                     "role_seen": role})
    if exp < int(time.time()):
        raise HTTPException(status_code=401, detail={"error": "TokenExpired",
                                                     "expired_at": exp})
    jti = payload.get("jti", "")
    sid = payload.get("sid", "")
    try:
        revoked = _check_revoked(jti, sid)
    except Exception as e:  # noqa: BLE001
        # Fail CLOSED on persistence errors. A token whose revocation
        # state we can't verify is treated as revoked — the alternative
        # (admit the token) lets a compromised bearer outlive the kill
        # switch whenever the DB hiccups. 503 (rather than 401) signals
        # the operator that this is infra, not credentials.
        print(f"[SPIRE] revocation check error (failing closed): {e}")
        raise HTTPException(status_code=503, detail={"error": "RevocationCheckFailed"})
    if revoked:
        raise HTTPException(status_code=401, detail={"error": "TokenRevoked",
                                                     "jti": jti, "sid": sid})
    return payload


# ---- FastAPI dependencies --------------------------------------------------

def _extract_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def current_principal(authorization: Optional[str] = Header(default=None)) -> Principal:
    """Required dependency: returns the verified Principal or raises 401."""
    token = _extract_token(authorization)
    if not token:
        raise HTTPException(status_code=401, detail={"error": "MissingBearer"})
    payload = verify(token)
    return Principal(
        role=payload["role"],
        unit=payload.get("unit"),
        billet=payload.get("billet"),
        attested_by=payload.get("attested_by", "DEMO_MODE"),
        attested_at=int(payload.get("attested_at", payload.get("iat", 0)) or 0),
        iat=int(payload.get("iat", 0) or 0),
        exp=int(payload.get("exp", 0) or 0),
        sid=payload.get("sid", "") or "",
        jti=payload.get("jti", "") or "",
    )


def current_role(authorization: Optional[str] = Header(default=None)) -> str:
    """Required dependency: returns the role from the bearer or raises 401.

    Backward-compat shim for routes that only need the role string. New
    code should depend on `current_principal` so it has access to the
    structured envelope (jti for revocation, unit/billet for finer scoping).
    """
    return current_principal(authorization).role


def current_role_optional(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    """Optional dependency: returns role if a valid bearer is present, else
    None. Used by read endpoints whose default behavior (no role = no
    scoping filter) is acceptable for now but should still record the
    effective actor when one is supplied.
    """
    token = _extract_token(authorization)
    if not token:
        return None
    try:
        return verify(token)["role"]
    except HTTPException:
        # Don't leak that the bearer was malformed for an optional dep —
        # treat it as anonymous and let the route's own gating decide.
        return None


# ---- Revocation sinks (kill-switch propagation) ---------------------------

# Other modules (notably `routes.system`) register a callable here so a
# revocation event can be mirrored to whatever sync surface they own — the
# air-gap queue today, a peer-replica gossip channel later. Sinks must not
# raise; the main path treats sink failure as best-effort.

RevocationSink = Callable[[dict], None]
_REVOCATION_SINKS: list[RevocationSink] = []


def register_revocation_sink(fn: RevocationSink) -> None:
    _REVOCATION_SINKS.append(fn)


def _notify_revocation_sinks(event: dict) -> None:
    for sink in _REVOCATION_SINKS:
        try:
            sink(event)
        except Exception as e:  # noqa: BLE001
            print(f"[SPIRE] revocation sink {getattr(sink, '__name__', sink)} failed: {e}")


# ---- Router ---------------------------------------------------------------

router = APIRouter()


class MintRequest(BaseModel):
    # In a CAC / Keycloak deployment this body would carry the upstream
    # identity assertion (SAML / OIDC id_token / X.509 thumb-print), and
    # `role` / `unit` / `billet` would be derived from the verified claims.
    # The persona-switch demo accepts a role directly so the dropdown
    # still works locally — this path is gated behind SPIRE_DEMO_MODE.
    role: str = Field(..., description="Role to mint a session for.")
    ttl_seconds: Optional[int] = Field(None, description="Override TTL.")
    unit: Optional[str] = Field(None, description="Optional unit claim (demo/test only).")
    billet: Optional[str] = Field(None, description="Optional billet claim (demo/test only).")


class MintResponse(BaseModel):
    token: str
    role: str
    expires_at: int
    session_id: str
    jti: str
    principal: dict


@router.post("/session", response_model=MintResponse)
def mint_session(req: MintRequest) -> MintResponse:
    if not SPIRE_DEMO_MODE:
        # The open mint endpoint is the persona-dropdown back door. The
        # persona memo flagged this as a bigger door than the one we
        # closed — outside demo it must refuse and force the IdP path.
        raise HTTPException(
            status_code=503,
            detail={
                "error": "DemoModeRequired",
                "message": (
                    "The unauthenticated mint endpoint is disabled outside demo "
                    "mode. Production deployments must mint via the CAC/Keycloak "
                    "adapter. Set SPIRE_DEMO_MODE=1 to enable for development."
                ),
            },
        )
    out = mint(
        req.role,
        ttl_seconds=req.ttl_seconds or _DEFAULT_TTL_SECONDS,
        unit=req.unit,
        billet=req.billet,
        attested_by="DEMO_MODE",
    )
    return MintResponse(**out)


@router.get("/whoami")
def whoami(principal: Principal = Depends(current_principal)) -> dict:
    return principal.to_dict()


class RevokeRequest(BaseModel):
    jti: Optional[str] = Field(None, description="Token id to revoke.")
    session_id: Optional[str] = Field(None, description="Session id to revoke (revokes any token bound to this sid).")
    reason: Optional[str] = Field("operator-initiated", description="Free-text reason recorded in the audit chain.")


@router.post("/revoke")
def revoke(
    req: RevokeRequest,
    principal: Principal = Depends(current_principal),
) -> dict:
    """Revoke a session by jti or sid. Security_manager only.

    Writes to the local `revoked_sessions` table and notifies any sink
    registered by other modules (the air-gap queue sink in `routes.system`
    pushes the event onto the queue so the kill-switch propagates on next
    sync).
    """
    require_role(principal.role, REVOKE_ROLES, "auth.revoke")
    jti = (req.jti or "").strip() or None
    sid = (req.session_id or "").strip() or None
    if not jti and not sid:
        raise HTTPException(
            status_code=400,
            detail={"error": "MissingTarget",
                    "message": "Provide `jti` or `session_id`."},
        )
    from .persistence import revoke_session as _persist_revoke
    n = _persist_revoke(
        jti=jti,
        sid=sid,
        actor=principal.role,
        reason=req.reason or "operator-initiated",
    )
    _notify_revocation_sinks({
        "jti": jti,
        "session_id": sid,
        "actor": principal.role,
        "reason": req.reason or "operator-initiated",
    })
    return {"ok": True, "revoked": n, "jti": jti, "session_id": sid}


@router.get("/revoked")
def list_revoked(
    principal: Principal = Depends(current_principal),
    limit: int = 100,
) -> dict:
    """Read-only inspection of the revocation list. Security_manager only."""
    require_role(principal.role, REVOKE_ROLES, "auth.revoke.list")
    from .persistence import list_revoked_sessions
    return {"revoked": list_revoked_sessions(limit=limit)}
