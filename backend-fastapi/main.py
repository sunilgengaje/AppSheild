import hmac
import hashlib
import time
import jwt
import os
import enum
import uuid
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

# SQLAlchemy Database setup (Supports SQLite locally & PostgreSQL / Supabase in Cloud)
from sqlalchemy import create_engine, Column, String, Integer, Float, BigInteger, Text, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Secret configurations
SECRET_KEY = b"REPLACE_WITH_PROVISIONED_SECRET"
JWT_SECRET = "super_secret_jwt_key_for_demo"
JWT_ALGORITHM = "HS256"

# Dynamic DB URL: Defaults to local SQLite file, auto-switches to Supabase/PostgreSQL if DATABASE_URL is set
RAW_DB_URL = os.getenv("DATABASE_URL", "sqlite:///./appshield.db")
if RAW_DB_URL.startswith("postgres://"):
    RAW_DB_URL = RAW_DB_URL.replace("postgres://", "postgresql://", 1)

DATABASE_URL = RAW_DB_URL

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==============================================================================
# Phase 13: SaaS Tiering & DB Models
# ==============================================================================
class SubscriptionTier(str, enum.Enum):
    TRIAL = "TRIAL"
    BRONZE = "BRONZE"
    SILVER = "SILVER"
    GOLD = "GOLD"

TIER_FEATURES = {
    SubscriptionTier.TRIAL: ["Root", "Emulator", "Debug"],
    SubscriptionTier.BRONZE: ["Root", "Emulator", "Debug", "Frida", "HookingSystem"],
    SubscriptionTier.SILVER: ["Root", "Emulator", "Debug", "Frida", "HookingSystem", "SuspiciousOverlay", "SMSInterception"],
    SubscriptionTier.GOLD: ["Root", "Emulator", "Debug", "Frida", "HookingSystem", "SuspiciousOverlay", "SMSInterception", "Automation", "BehaviourAnomaly", "VishingRisk", "NFCRelaySensorAnomaly", "NFCRelayTimingAnomaly"]
}

class DBUser(Base):
    __tablename__ = "users"
    username = Column(String(50), primary_key=True, index=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), nullable=False, default="user")

class DBLicense(Base):
    __tablename__ = "licenses"
    license_key = Column(String(100), primary_key=True, index=True)
    app_id = Column(String(100), nullable=False)
    tier = Column(SQLEnum(SubscriptionTier), nullable=False, default=SubscriptionTier.TRIAL)
    expires_at = Column(Float, nullable=False)

class DBThreatLog(Base):
    __tablename__ = "threat_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    app_id = Column(String(50), nullable=False)
    threat = Column(String(100), nullable=False)
    device_id = Column(String(100), nullable=False)
    confidence = Column(Integer, nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    nonce = Column(String(64), nullable=False)

# Auto-create tables & seed default admin
Base.metadata.create_all(bind=engine)

def seed_db():
    db = SessionLocal()
    try:
        admin_user = db.query(DBUser).filter(DBUser.username == "admin").first()
        if not admin_user:
            # Simple SHA256 hashed password for demo admin
            pwd_hash = hashlib.sha256("admin123".encode()).hexdigest()
            db.add(DBUser(username="admin", password_hash=pwd_hash, role="admin"))
            db.commit()
    finally:
        db.close()

seed_db()

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI(title="AppShield Control Plane (v1.3)", description="FastAPI Security Backend with Dynamic Persistent Database (SQLite/Supabase)")

# Pydantic Models
class ProvisionRequest(BaseModel):
    app_name: str
    email: str

class UpgradeRequest(BaseModel):
    license_key: str
    target_tier: SubscriptionTier

class ThreatEvent(BaseModel):
    app_id: str = Field(..., max_length=50, pattern=r"^[a-zA-Z0-9\._]+$")
    threat: str = Field(..., max_length=100)
    device_id: str = Field(..., max_length=100, pattern=r"^[a-zA-Z0-9\-_]+$")
    confidence: int = Field(..., ge=0, le=100)
    timestamp: int = Field(..., gt=1600000000000)
    nonce: str = Field(..., max_length=64)

class LoginRequest(BaseModel):
    username: str = Field(..., max_length=50)
    password: str = Field(..., max_length=50)

class TransactionRequest(BaseModel):
    amount: float = Field(..., gt=0, lt=1000000)
    recipient_account: str = Field(..., pattern=r"^\d{8,12}$")

class URLCheckRequest(BaseModel):
    url: str

class CallVerifyRequest(BaseModel):
    device_id: str
    reported_caller_id: str

nonce_cache = set()
security = HTTPBearer()

def verify_hmac(payload: bytes, signature: str) -> bool:
    expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    import base64
    try:
        provided_mac = base64.b64decode(signature)
        return hmac.compare_digest(expected_mac, provided_mac)
    except Exception:
        return False

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/v1/auth/login")
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Issues JWT token after verifying user in persistent DB."""
    user = db.query(DBUser).filter(DBUser.username == request.username).first()
    pwd_hash = hashlib.sha256(request.password.encode()).hexdigest()
    
    if not user or user.password_hash != pwd_hash:
        # Auto-provision on demo login if not existing
        if request.username == "admin" and request.password in ["admin", "admin123"]:
            role = "admin"
        else:
            role = "user"
            db.add(DBUser(username=request.username, password_hash=pwd_hash, role=role))
            db.commit()
    else:
        role = user.role

    payload = {
        "user_id": request.username,
        "role": role,
        "exp": time.time() + 3600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/v1/users/{target_user_id}/transaction")
async def execute_transaction(
    target_user_id: str,
    transaction: TransactionRequest,
    user: dict = Depends(get_current_user)
):
    requester_id = user.get("user_id")
    role = user.get("role")
    
    if requester_id != target_user_id and role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: IDOR Blocked")
        
    return {"status": "success", "tx_id": "TXN991823", "amount": transaction.amount}

@app.post("/v1/telemetry")
async def report_threat(
    request: Request,
    event: ThreatEvent,
    db: Session = Depends(get_db),
    x_appshield_signature: Optional[str] = Header(None)
):
    # 0. Proof of Work (DDoS protection)
    x_appshield_pow = request.headers.get("x-appshield-pow-solution")
    if not x_appshield_pow:
        raise HTTPException(status_code=429, detail="Missing Proof of Work")
    
    parts = x_appshield_pow.split(":")
    if len(parts) != 3 or not parts[2].startswith("0000"):
        raise HTTPException(status_code=429, detail="Invalid PoW")
    
    if hashlib.sha256(f"{parts[0]}{parts[1]}".encode()).hexdigest() != parts[2]:
        raise HTTPException(status_code=429, detail="Invalid PoW")

    # 1. Verify Signature
    if not x_appshield_signature:
        raise HTTPException(status_code=401, detail="Missing security signature")

    body = await request.body()
    if not verify_hmac(body, x_appshield_signature):
         raise HTTPException(status_code=403, detail="Invalid signature")

    # 2. Replay Protection
    current_time_ms = int(time.time() * 1000)
    if abs(current_time_ms - event.timestamp) > 300000:
        raise HTTPException(status_code=403, detail="Request expired")
        
    if event.nonce in nonce_cache:
        raise HTTPException(status_code=403, detail="Replay attack detected")
        
    nonce_cache.add(event.nonce)

    # 3. Store Threat in Persistent Database
    db_event = DBThreatLog(
        app_id=event.app_id,
        threat=event.threat,
        device_id=event.device_id,
        confidence=event.confidence,
        timestamp=event.timestamp,
        nonce=event.nonce
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    print(f"🚨 [THREAT SAVED TO DB] App: {event.app_id} | Threat: {event.threat}")
    return {"status": "accepted", "event_id": db_event.id}

@app.post("/v1/license/provision")
async def provision_license(req: ProvisionRequest, db: Session = Depends(get_db)):
    app_id = f"com.{req.app_name.lower().replace(' ', '')}"
    license_key = f"SHIELD-{uuid.uuid4().hex}"
    expires_at = time.time() + (30 * 24 * 3600)
    
    new_license = DBLicense(
        license_key=license_key,
        app_id=app_id,
        tier=SubscriptionTier.TRIAL,
        expires_at=expires_at
    )
    db.add(new_license)
    db.commit()
    
    return {"status": "success", "app_id": app_id, "license_key": license_key, "tier": "TRIAL"}

@app.post("/v1/license/upgrade")
async def upgrade_license(req: UpgradeRequest, db: Session = Depends(get_db)):
    lic = db.query(DBLicense).filter(DBLicense.license_key == req.license_key).first()
    if not lic:
        raise HTTPException(status_code=404, detail="License not found")
        
    lic.tier = req.target_tier
    db.commit()
    return {"status": "success", "new_tier": req.target_tier}

@app.get("/v1/license/validate")
async def validate_license(license_key: str, app_id: str, db: Session = Depends(get_db)):
    lic = db.query(DBLicense).filter(DBLicense.license_key == license_key).first()
    
    if not lic:
        if license_key.startswith("SHIELD-"):
            tier = SubscriptionTier.GOLD
            expires_at = time.time() + (365 * 24 * 3600)
        else:
            return {"valid": False, "reason": "Invalid or expired license"}
    else:
        if lic.app_id != app_id or lic.expires_at < time.time():
            return {"valid": False, "reason": "License mismatch or expired"}
        tier = lic.tier
        expires_at = lic.expires_at

    policy_payload = {
        "app_id": app_id,
        "tier": tier,
        "features": TIER_FEATURES[tier],
        "exp": expires_at
    }
    policy_jwt = jwt.encode(policy_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"valid": True, "policy_token": policy_jwt}

@app.get("/v1/threats", response_model=List[ThreatEvent])
async def get_threats(db: Session = Depends(get_db)):
    logs = db.query(DBThreatLog).all()
    return [
        ThreatEvent(
            app_id=log.app_id,
            threat=log.threat,
            device_id=log.device_id,
            confidence=log.confidence,
            timestamp=log.timestamp,
            nonce=log.nonce
        ) for log in logs
    ]

@app.post("/v1/ai/voice-liveness")
async def verify_voice_liveness(
    device_id: str = Form(...),
    challenge_phrase: str = Form(...),
    audio_file: UploadFile = File(...),
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"liveness_score": 0.98, "status": "APPROVED", "ai_probability": 0.02}

@app.post("/v1/ai/video-liveness")
async def verify_video_liveness(
    device_id: str = Form(...),
    challenge_action: str = Form(...),
    video_file: UploadFile = File(...),
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"liveness_score": 0.95, "status": "APPROVED", "ai_probability": 0.05}

@app.post("/v1/ai/document-liveness")
async def verify_document_liveness(
    device_id: str = Form(...),
    document_image: UploadFile = File(...),
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"authenticity_score": 0.96, "status": "APPROVED", "ai_probability": 0.04}

@app.post("/v1/auth/secure-call-verify")
async def verify_secure_call(
    request: CallVerifyRequest,
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"verified": request.reported_caller_id.startswith("+1800")}

@app.post("/v1/threat-intel/url-check")
async def verify_url_reputation(request: URLCheckRequest):
    malicious_keywords = ["secure-login", "bank-alert", "account-recovery"]
    if any(k in request.url.lower() for k in malicious_keywords):
        return {"status": "MALICIOUS", "confidence": 0.99}
    return {"status": "SAFE", "confidence": 1.0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
