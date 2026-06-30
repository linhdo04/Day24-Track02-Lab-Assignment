"""Casbin role-based access control and FastAPI dependencies."""

from functools import wraps
from pathlib import Path
from typing import Optional

import casbin
from fastapi import Header, HTTPException, status

MOCK_USERS = {
    "token-alice": {"username": "alice", "role": "admin"},
    "token-bob": {"username": "bob", "role": "ml_engineer"},
    "token-carol": {"username": "carol", "role": "data_analyst"},
    "token-dave": {"username": "dave", "role": "intern"},
}

ACCESS_DIR = Path(__file__).resolve().parent
enforcer = casbin.Enforcer(str(ACCESS_DIR / "model.conf"), str(ACCESS_DIR / "policy.csv"))


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """Authenticate a mock bearer token used by the lab API."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = MOCK_USERS.get(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user.copy()


def require_permission(resource: str, action: str):
    """Require a Casbin permission for an async FastAPI route."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")
            if not current_user:
                raise HTTPException(status_code=401, detail="Missing authenticated user")
            role = current_user["role"]
            if not enforcer.enforce(role, resource, action):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' cannot '{action}' on '{resource}'",
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
