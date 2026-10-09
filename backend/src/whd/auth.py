"""Token + signed-session-cookie authentication (spec 4.6).

* A 256-bit access token is generated on first run in <config_dir>/token (0600).
  The server logs the *path*, never the token.
* POST /api/v1/auth/login exchanges the token for an HttpOnly SameSite=Strict
  cookie: "<expiry>.<nonce>.<hmac>" signed with <config_dir>/session.key, so
  sessions survive a server restart.
* Mutating requests authenticated by cookie must carry `X-WHD-Request: 1`
  (CSRF defence in depth on top of SameSite=Strict). Bearer-token requests
  (CLI/curl) are not ambient credentials and are exempt.
* WebSockets: cookie or ?token= plus a same-origin Origin check.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path

from fastapi import HTTPException, Request, WebSocket

COOKIE = "whd_session"
SESSION_TTL_S = 12 * 3600
CSRF_HEADER = "x-whd-request"


def _read_or_create(path: Path, nbytes: int) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        st = path.stat()
        if st.st_mode & 0o077:
            os.chmod(path, 0o600)
        return path.read_text().strip()
    val = secrets.token_hex(nbytes)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(val + "\n")
    return val


class Auth:
    def __init__(self, config_dir: Path) -> None:
        self.token_path = config_dir / "token"
        self.token = _read_or_create(self.token_path, 32)
        self._key = bytes.fromhex(_read_or_create(config_dir / "session.key", 32))
        self._revoked: set[str] = set()
        self._fail: dict[str, list[float]] = defaultdict(list)

    # ---------------------------------------------------------------- sessions
    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def new_session(self) -> str:
        payload = f"{int(time.time()) + SESSION_TTL_S}.{secrets.token_hex(8)}"
        return f"{payload}.{self._sign(payload)}"

    def valid_session(self, cookie: str | None) -> bool:
        if not cookie or cookie in self._revoked:
            return False
        parts = cookie.split(".")
        if len(parts) != 3:
            return False
        payload = f"{parts[0]}.{parts[1]}"
        if not hmac.compare_digest(self._sign(payload), parts[2]):
            return False
        try:
            return int(parts[0]) > time.time()
        except ValueError:
            return False

    def revoke(self, cookie: str | None) -> None:
        if cookie:
            self._revoked.add(cookie)

    def check_token(self, token: str, client: str) -> bool:
        now = time.time()
        fails = [t for t in self._fail[client] if now - t < 300]
        self._fail[client] = fails
        if len(fails) >= 10:
            raise HTTPException(429, "too many failed login attempts; wait 5 minutes")
        ok = hmac.compare_digest(token.strip().encode(), self.token.encode())
        if not ok:
            fails.append(now)
        return ok

    # ---------------------------------------------------------------- deps
    def _bearer(self, header: str | None) -> bool:
        if header and header.lower().startswith("bearer "):
            return hmac.compare_digest(header[7:].strip().encode(), self.token.encode())
        return False

    def require(self, request: Request) -> str:
        if self._bearer(request.headers.get("authorization")):
            return "token"
        if self.valid_session(request.cookies.get(COOKIE)):
            if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != "1":
                raise HTTPException(403, f"missing {CSRF_HEADER} header")
            return "session"
        raise HTTPException(401, "authentication required")

    def check_ws(self, ws: WebSocket) -> bool:
        origin = ws.headers.get("origin")
        host = ws.headers.get("host")
        if origin is not None and host is not None:
            o = origin.split("://", 1)[-1]
            if o != host:
                return False
        if self.valid_session(ws.cookies.get(COOKIE)):
            return True
        tok = ws.query_params.get("token")
        return bool(tok) and hmac.compare_digest(tok.encode(), self.token.encode())  # type: ignore[union-attr]
