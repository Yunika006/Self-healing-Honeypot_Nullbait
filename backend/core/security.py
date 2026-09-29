"""
basic JWT auth for protecting the dashboard's REST/websocket access.
note: this protects the MANAGEMENT plane (dashboard, api), not the
honeypot services themselves — those are intentionally open, since
attracting and capturing attackers is the entire point of a honeypot.
"""

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from core.config import settings

bearer_scheme = HTTPBearer()


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


async def require_auth(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> str:
    """
    dependency to protect routes. add `user: str = Depends(require_auth)`
    to any endpoint that should require a valid token.
    """
    return verify_token(credentials.credentials)
