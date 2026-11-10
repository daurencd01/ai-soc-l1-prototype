import hashlib
import hmac
import os
from datetime import timedelta
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import settings
from .db import get_db
from .models import Audit, User, utcnow

bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, digest = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def token_for(user: User) -> str:
    now = utcnow()
    return jwt.encode({"sub": user.id, "tenant_id": user.tenant_id, "role": user.role,
                       "iat": now, "exp": now + timedelta(hours=8)}, settings().jwt_secret, algorithm="HS256")


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(401, "Требуется вход")
    try:
        claims = jwt.decode(credentials.credentials, settings().jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Недействительный токен")
    user = db.scalar(select(User).where(User.id == claims.get("sub"), User.tenant_id == claims.get("tenant_id"), User.active.is_(True)))
    if not user or user.role != claims.get("role"):
        raise HTTPException(401, "Пользователь недоступен")
    return user


def admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Требуется роль admin")
    return user


def audit(db: Session, tenant_id: str, actor: str, operation: str, subject_type: str, subject_id: str, detail: dict | None = None) -> None:
    db.add(Audit(tenant_id=tenant_id, actor=actor, operation=operation, subject_type=subject_type,
                 subject_id=subject_id, detail=detail or {}))
