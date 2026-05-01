import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import text

from app.auth import hash_password
from app.config import settings
from app.database import Base, engine
from app.database import SessionLocal
from app.models import User
from app.middleware import RequestContextMiddleware
from app.routes.auth import router as auth_router
from app.routes.security import router as security_router
from app.services.threat_intel import run_threat_intel_update, start_threat_intel_scheduler
from app.sqlite_store import init_sqlite_db

app = FastAPI(title="AI Security Monitoring Tool", version="1.0.0")

app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://chatgpt.com",
        "https://chat.openai.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(security_router)


@app.on_event("startup")
def on_startup():
    max_attempts = 20
    for attempt in range(1, max_attempts + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            break
        except Exception:
            if attempt == max_attempts:
                raise
            time.sleep(2)

    Base.metadata.create_all(bind=engine)
    init_sqlite_db()
    if settings.threat_intel_enabled:
        run_threat_intel_update()
        start_threat_intel_scheduler()
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == settings.bootstrap_admin_email).first()
        if not existing:
            db.add(
                User(
                    email=settings.bootstrap_admin_email,
                    hashed_password=hash_password(settings.bootstrap_admin_password),
                    role="admin",
                )
            )
            db.commit()
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


Instrumentator().instrument(app).expose(app)
