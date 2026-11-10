"""Run the isolated SOC preview without Docker (SQLite and Celery eager mode).

This is a loopback-only development helper, not a production deployment.
"""

import os
import sys
from pathlib import Path

import uvicorn


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / ".qa"
DATA.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "backend"))

os.environ["MODE"] = "DEMO"
os.environ["DATABASE_URL"] = f"sqlite:///{(DATA / 'soc.sqlite').as_posix()}"
os.environ["JWT_SECRET"] = "local-demo-only-jwt-secret-32-characters-minimum"
os.environ["WEBHOOK_SECRET"] = "local-demo-only-webhook-secret-32-characters-minimum"

from app.db import Base, engine  # noqa: E402
from app.tasks import celery_app  # noqa: E402
import app.models  # noqa: E402,F401

Base.metadata.create_all(engine)
celery_app.conf.update(task_always_eager=True, task_eager_propagates=True)

from app.main import app  # noqa: E402


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")
