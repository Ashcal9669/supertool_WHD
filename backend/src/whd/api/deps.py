from __future__ import annotations

from fastapi import Depends, Request

from whd.state import AppState


def get_state(request: Request) -> AppState:
    st: AppState = request.app.state.whd
    return st


def require_auth(request: Request, st: AppState = Depends(get_state)) -> str:  # noqa: B008
    return st.auth.require(request)
