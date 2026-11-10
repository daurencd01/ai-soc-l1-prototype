"""Public entrypoints enforce size and guessing limits before ingesting data."""

import hashlib
import hmac

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.config import settings
from app.db import Base, get_db
from app.models import Tenant, User
from app.request_limits import LoginRateLimiter
from app.security import hash_password, validate_connected_passwords


def test_connected_passwords_reject_short_and_placeholder_values():
    for value in ("x", "demo-password-123456", " change-this-password-123 "):
        try:
            validate_connected_passwords("CONNECTED", value, "")
        except RuntimeError:
            pass
        else:
            raise AssertionError("CONNECTED accepted an unsafe admin password")
    validate_connected_passwords("CONNECTED", "long-unique-admin-password", "long-unique-analyst-password")
    validate_connected_passwords("DEMO", "", "")


def test_webhook_rejects_large_and_non_object_bodies():
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="webhook-limit", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.commit()
        tenant_id = tenant.id

    def override_db():
        with Session(engine) as db:
            yield db

    main_module.app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(main_module.app)
        secret = hmac.new(settings().webhook_secret.encode(), tenant_id.encode(), hashlib.sha256).hexdigest()
        path = f"/api/ingest/webhook/{tenant_id}/{secret}"
        assert client.post(path, content=b"x" * 1_000_001).status_code == 413
        assert client.post(path, json=[1, 2, 3]).status_code == 422
    finally:
        main_module.app.dependency_overrides.clear()
        engine.dispose()


def test_login_blocks_after_ten_failed_guesses(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant = Tenant(name="login-limit", deployment_mode="DEMO", automation_level="observe")
        db.add(tenant)
        db.flush()
        db.add(User(tenant_id=tenant.id, username="limited-admin",
                    password_hash=hash_password("valid-password-1234"), role="admin"))
        db.commit()

    def override_db():
        with Session(engine) as db:
            yield db

    monkeypatch.setattr(main_module, "login_limiter", LoginRateLimiter())
    main_module.app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(main_module.app)
        assert client.post("/api/auth/login", json={
            "username": "x" * 101, "password": "valid-password-1234"}).status_code == 422
        assert client.post("/api/auth/login", json={
            "username": "limited-admin", "password": "x" * 1025}).status_code == 422
        for _ in range(10):
            assert client.post("/api/auth/login", json={
                "username": "limited-admin", "password": "wrong-password"}).status_code == 401
        denied = client.post("/api/auth/login", json={
            "username": "limited-admin", "password": "valid-password-1234"})
        assert denied.status_code == 429
        assert denied.headers["Retry-After"] == "300"
    finally:
        main_module.app.dependency_overrides.clear()
        engine.dispose()
