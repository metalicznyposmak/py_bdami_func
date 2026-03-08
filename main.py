import os
import datetime
import pyodbc
import jwt
import bcrypt
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from typing import Optional, List

load_dotenv()

app = FastAPI(title="PY_BDAMI_API", root_path="/api")

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

def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # invalid/unknown hash format
        raise HTTPException(status_code=400, detail="Stored password hash invalid")

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

class ChangeUsernameReq(BaseModel):
    new_username: str

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

    try:
        password_hash = hash_password(req.password)
    except ValueError:
        raise HTTPException(status_code=400, detail="Password too long: truncate to 72 bytes")

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

    ok = verify_password(req.password, password_hash)

    if not ok:
        raise HTTPException(status_code=401, detail="Bad credentials")

    return {"access_token": create_token(user_id, username), "token_type": "bearer"}

@app.get("/me")
def me(payload=Depends(verify_token)):
    return {"user_id": payload["sub"], "username": payload.get("name")}

@app.put("/me/username")
def change_username(req: ChangeUsernameReq, payload=Depends(verify_token)):
    user_id = int(payload["sub"])
    new_username = req.new_username.strip()

    if len(new_username) < 3:
        raise HTTPException(status_code=400, detail="Username too short")

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM dbo.Users WHERE Username = ? AND Id <> ?", new_username, user_id)
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="Username already taken")

        cur.execute("UPDATE dbo.Users SET Username = ? WHERE Id = ?", new_username, user_id)
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        conn.commit()

    return {
        "updated": True,
        "username": new_username,
        "access_token": create_token(user_id, new_username),
        "token_type": "bearer",
    }

class CategoryOut(BaseModel):
    id: int
    name: str

class ProductOut(BaseModel):
    id: int
    categoryId: int
    name: str
    description: str
    price: float
    imageUrl: Optional[str] = None
    isActive: bool

class CartItemOut(BaseModel):
    productId: int
    name: str
    quantity: int
    unitPrice: float
    lineTotal: float

class CartOut(BaseModel):
    cartId: int
    status: str
    items: List[CartItemOut]
    total: float

class CartAddReq(BaseModel):
    productId: int
    quantity: int = Field(..., ge=1, le=999)

class CartSetReq(BaseModel):
    productId: int
    quantity: int = Field(..., ge=1, le=999)

def get_or_create_active_cart_id(user_id: int) -> int:
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT TOP 1 id FROM dbo.Carts WHERE userId = ? AND status = 'active' ORDER BY createdAt DESC",
            user_id
        )
        row = cur.fetchone()  
        if row:
            return int(row[0])
        
        cur.execute(
            "INSERT INTO dbo.Carts (userId, status) VALUES (?, 'active')",
            user_id
        )
        conn.commit()

        cur.execute(
            "SELECT TOP 1 id FROM dbo.Carts WHERE userId = ? AND status = 'active' ORDER BY createdAt DESC",
            user_id
        )
        row2 = cur.fetchone()
        return int(row2[0])
    
@app.get("/categories", response_model=list[CategoryOut])
def list_categories():
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM dbo.Categories ORDER BY name ASC")
        rows = cur.fetchall()

    return [{"id": r[0], "name": r[1]} for r in rows]


@app.get("/products", response_model=list[ProductOut])
def list_products(categoryId: int | None = None, onlyActive: bool = True):
    sql = """
        SELECT id, categoryId, name, description, price, imageUrl, isActive
        FROM dbo.Products
    """
    params = []

    where = []
    if categoryId is not None:
        where.append("categoryId = ?")
        params.append(categoryId)
    if onlyActive:
        where.append("isActive = 1")

    if where:
        sql += " WHERE " + " AND ".join(where)

    sql += " ORDER BY name ASC"

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()

    return [
        {
            "id": int(r[0]),
            "categoryId": int(r[1]),
            "name": r[2],
            "description": r[3],
            "price": float(r[4]),
            "imageUrl": r[5],
            "isActive": bool(r[6]),
        }
        for r in rows
    ]


@app.get("/products/{product_id}", response_model=ProductOut)
def get_product(product_id: int):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT id, categoryId, name, description, price, imageUrl, isActive
               FROM dbo.Products
               WHERE id = ?""",
            product_id
        )
        r = cur.fetchone()

    if not r:
        raise HTTPException(status_code=404, detail="Product not found")

    return {
        "id": int(r[0]),
        "categoryId": int(r[1]),
        "name": r[2],
        "description": r[3],
        "price": float(r[4]),
        "imageUrl": r[5],
        "isActive": bool(r[6]),
    }

@app.get("/cart", response_model=CartOut)
def get_cart(payload=Depends(verify_token)):
    user_id = int(payload["sub"])
    cart_id = get_or_create_active_cart_id(user_id)

    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute("SELECT id, status FROM dbo.Carts WHERE id = ?", cart_id)
        cart_row = cur.fetchone()
        if not cart_row:
            raise HTTPException(status_code=404, detail="Cart not found")

        cur.execute(
            """
            SELECT ci.productId, p.name, ci.quantity, ci.unitPrice
            FROM dbo.CartItems ci
            JOIN dbo.Products p ON p.id = ci.productId
            WHERE ci.cartId = ?
            ORDER BY p.name ASC
            """,
            cart_id
        )
        rows = cur.fetchall()

    items = []
    total = 0.0
    for r in rows:
        product_id = int(r[0])
        name = r[1]
        qty = int(r[2])
        unit_price = float(r[3])
        line_total = unit_price * qty
        total += line_total
        items.append({
            "productId": product_id,
            "name": name,
            "quantity": qty,
            "unitPrice": unit_price,
            "lineTotal": line_total
        })

    return {
        "cartId": int(cart_row[0]),
        "status": cart_row[1],
        "items": items,
        "total": total
    }

@app.post("/cart/items/add", response_model=CartOut)
def cart_add_item(req: CartAddReq, payload=Depends(verify_token)):
    user_id = int(payload["sub"])
    cart_id = get_or_create_active_cart_id(user_id)

    with get_conn() as conn:
        cur = conn.cursor()

        cur.execute(
            "SELECT price, isActive FROM dbo.Products WHERE id = ?",
            req.productId
        )
        p = cur.fetchone()
        if not p:
            raise HTTPException(status_code=404, detail="Product not found")
        if not bool(p[1]):
            raise HTTPException(status_code=400, detail="Product is inactive")

        price = float(p[0])

        cur.execute(
            "SELECT quantity FROM dbo.CartItems WHERE cartId = ? AND productId = ?",
            cart_id, req.productId
        )
        row = cur.fetchone()
        if row:
            new_qty = int(row[0]) + int(req.quantity)
            cur.execute(
                "UPDATE dbo.CartItems SET quantity = ? WHERE cartId = ? AND productId = ?",
                new_qty, cart_id, req.productId
            )
        else:
            cur.execute(
                """
                INSERT INTO dbo.CartItems (cartId, productId, quantity, unitPrice)
                VALUES (?, ?, ?, ?)
                """,
                cart_id, req.productId, req.quantity, price
            )

        conn.commit()

    return get_cart(payload)

@app.post("/cart/items/set", response_model=CartOut)
def cart_set_quantity(req: CartSetReq, payload=Depends(verify_token)):
    user_id = int(payload["sub"])
    cart_id = get_or_create_active_cart_id(user_id)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE dbo.CartItems SET quantity = ? WHERE cartId = ? AND productId = ?",
            req.quantity, cart_id, req.productId
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Item not found in cart")
        conn.commit()

    return get_cart(payload)

@app.delete("/cart/items/{product_id}", response_model=CartOut)
def cart_remove_item(product_id: int, payload=Depends(verify_token)):
    user_id = int(payload["sub"])
    cart_id = get_or_create_active_cart_id(user_id)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM dbo.CartItems WHERE cartId = ? AND productId = ?",
            cart_id, product_id
        )
        conn.commit()

    return get_cart(payload)


