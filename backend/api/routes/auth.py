from fastapi import APIRouter, HTTPException, status, Request
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import settings
from core.security import create_access_token

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"])
limiter = Limiter(key_func=get_remote_address)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/api/auth/login", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login(request: Request, payload: LoginRequest):
    if payload.username != settings.DASHBOARD_USERNAME:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not settings.DASHBOARD_PASSWORD_HASH or not pwd_context.verify(
        payload.password, settings.DASHBOARD_PASSWORD_HASH
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(subject=payload.username)
    return LoginResponse(access_token=token)
