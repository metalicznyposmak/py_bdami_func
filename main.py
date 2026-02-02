import os
import datetime
import pyodbc
import jwt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="PY_BDAMI_API", root_path="/api")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()

def get_conn():
    server = os.environ["SQL_SERVER"]
    database = os.environ["SQL_DATABASE"]
    user = os.environ["SQL_USER"]
    password = os.environ["SQL_PASSWORD"]

    print("SQL_SERVER =", server)
    print("SQL_DATABASE =", database)
    print("SQL_USER =", user)


    conn_str = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    f"SERVER={server};"
    f"DATABASE={database};"
    f"UID={user};"
    f"PWD={password};"
    "Encrypt=Yes;"
    "TrustServerCertificate=No;"
    )
    return pyodbc.connect(conn_str)

def create_token(user_id: int, username: str) -> str:
    secret = os.environ["JWT_SECRET"]
    issuer = os.getenv("JWT_ISSUER", "pyapi")
    audience = os.getenv("JWT_AUDIENCE", "flutter")

    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "name": username,
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(hours=12)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_token(creds: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = creds.credentials
    secret = os.environ["JWT_SECRET"]
    issuer = os.getenv("JWT_ISSUER", "pyapi")
    audience = os.getenv("JWT_AUDIENCE", "flutter")

    try:
        return jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, audience=audience)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

class LoginReq(BaseModel):
    username: str
    password: str

class RegisterReq(BaseModel):
    username: str
    password: str

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/register")
def register(req: RegisterReq):
    pw_bytes = req.password.encode("utf-8")
    print("REGISTER password bytes:", len(pw_bytes))
    if len(pw_bytes) > 72:
        raise HTTPException(status_code=400, detail=f"Password too long: {len(pw_bytes)} bytes (max 72)")

    username = req.username.strip()
    if len(username) < 3 or len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Username/password too short")

    password_hash = pwd_context.hash(req.password)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM dbo.Users WHERE Username = ?", username)
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="User already exists")

        cur.execute(
            "INSERT INTO dbo.Users (Username, PasswordHash) VALUES (?, ?)",
            username, password_hash
        )
        conn.commit()

    return {"created": True}

@app.post("/login")
def login(req: LoginReq):
    pw_bytes = req.password.encode("utf-8")
    print("LOGIN password bytes:", len(pw_bytes))
    if len(pw_bytes) > 72:
        raise HTTPException(status_code=400, detail=f"Password too long: {len(pw_bytes)} bytes (max 72)")

    username = req.username.strip()

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT Id, PasswordHash, IsActive FROM dbo.Users WHERE Username = ?",
            username
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Bad credentials")

    user_id, password_hash, is_active = row[0], row[1], row[2]
    if not is_active:
        raise HTTPException(status_code=403, detail="User disabled")

    if not pwd_context.verify(req.password, password_hash):
        raise HTTPException(status_code=401, detail="Bad credentials")

    return {"access_token": create_token(user_id, username), "token_type": "bearer"}

@app.get("/me")
def me(payload=Depends(verify_token)):
    return {"user_id": payload["sub"], "username": payload.get("name")}
