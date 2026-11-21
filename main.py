import os
import secrets
import hashlib
import smtplib
import urllib.request
import urllib.error
import json
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
import psycopg
from psycopg.rows import dict_row

app = FastAPI(title="TRONVEX Backend API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL", "")
PASSWORD_SALT = os.getenv("PASSWORD_SALT", "tronvex_change_this_salt")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")

TOKENS_TO_USER: dict[str, dict] = {}


def get_conn():
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured.")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


class SendCodeRequest(BaseModel):
    email: EmailStr


class VerifySignupRequest(BaseModel):
    full_name: str = Field(min_length=2)
    email: EmailStr
    password: str = Field(min_length=6)
    code: str = Field(min_length=6, max_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)


class CreateDepositRequest(BaseModel):
    network: str
    method: str
    amount: float = Field(ge=5.0)


class CreateWithdrawRequest(BaseModel):
    network: str
    method: str
    amount: float = Field(ge=5.0)
    address: str = Field(min_length=6)


class CreateInvestmentRequest(BaseModel):
    plan: str
    amount: float = Field(ge=5.0)


class DepositWebhookPayload(BaseModel):
    order_id: str
    tx_hash: str
    amount: float
    status: str


def hash_val(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()


def send_via_resend(to_email: str, code: str, from_email: str) -> bool:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        return False

    payload = {
        "from": from_email,
        "to": [to_email],
        "subject": "TRONVEX 6-Digit Verification Code",
        "text": f"Your verification code is: {code}\nValid for 10 minutes.",
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "TRONVEX-API/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="ignore")
        print(f"[RESEND HTTP ERROR] {to_email}: {exc.code} {err_body}")
        return False
    except Exception as exc:
        print(f"[RESEND ERROR] {to_email}: {exc}")
        return False


def send_otp_email(to_email: str, code: str) -> str:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    from_email = os.getenv("FROM_EMAIL", "").strip() or smtp_user or "onboarding@resend.dev"

    if os.getenv("RESEND_API_KEY", "").strip():
        if send_via_resend(to_email, code, from_email):
            return "resend"
        print(f"[OTP FALLBACK] {to_email}: {code}")
        return "log_fallback"

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = EmailMessage()
            msg["Subject"] = "TRONVEX 6-Digit Verification Code"
            msg["From"] = from_email
            msg["To"] = to_email
            msg.set_content(f"Your verification code is: {code}\nValid for 10 minutes.")
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            return "smtp"
        except Exception as exc:
            print(f"[SMTP ERROR] {to_email}: {exc} | [OTP FALLBACK] {to_email}: {code}")
            return "log_fallback"

    print(f"[OTP DEV] {to_email}: {code}")
    return "dev_log"


def get_auth_user(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    token = authorization.replace("Bearer ", "", 1).strip()
    session = TOKENS_TO_USER.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session. Please log in again.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
            user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user


@app.get("/")
def health_check():
    return {"status": "ok", "service": "TRONVEX API"}


@app.post("/api/auth/send-code")
def send_code(payload: SendCodeRequest):
    email = payload.email.lower().strip()
    code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO email_verifications (email, code_hash, expires_at, used)
                VALUES (%s, %s, %s, false)
                """,
                (email, hash_val(code), expires_at),
            )
        conn.commit()

    delivery = send_otp_email(email, code)
    return {"message": "Verification code sent.", "delivery": delivery}


@app.post("/api/auth/verify-signup")
def verify_signup(payload: VerifySignupRequest):
    email = payload.email.lower().strip()
    code_hash = hash_val(payload.code.strip())
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM email_verifications
                WHERE email = %s AND used = false
                ORDER BY id DESC LIMIT 1
                """,
                (email,),
            )
            otp_row = cur.fetchone()

            if not otp_row:
                raise HTTPException(status_code=400, detail="Request a verification code first.")
            if now > otp_row["expires_at"]:
                raise HTTPException(status_code=400, detail="Verification code expired.")
            if otp_row["code_hash"] != code_hash:
                raise HTTPException(status_code=400, detail="Invalid verification code.")

            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Email already registered.")

            while True:
                user_code = f"TRX-{secrets.token_hex(3).upper()}"
                cur.execute("SELECT id FROM users WHERE user_code = %s", (user_code,))
                if not cur.fetchone():
                    break

            prefix = "".join(ch for ch in email.split("@")[0] if ch.isalnum()).upper()[:6] or "USER"
            ref_code = f"{prefix}{secrets.randbelow(9000) + 1000}"

            cur.execute(
                """
                INSERT INTO users (user_code, full_name, email, password_hash, ref_code)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    user_code,
                    payload.full_name.strip(),
                    email,
                    hash_val(payload.password + PASSWORD_SALT),
                    ref_code,
                ),
            )
            user = cur.fetchone()
            cur.execute("UPDATE email_verifications SET used = true WHERE id = %s", (otp_row["id"],))
        conn.commit()

    token = secrets.token_urlsafe(32)
    TOKENS_TO_USER[token] = {"user_id": user["id"]}

    return {
        "token": token,
        "user_code": user["user_code"],
        "full_name": user["full_name"],
        "email": user["email"],
        "ref_code": user["ref_code"],
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest):
    email = payload.email.lower().strip()
    pw_hash = hash_val(payload.password + PASSWORD_SALT)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s", (email, pw_hash))
            user = cur.fetchone()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = secrets.token_urlsafe(32)
    TOKENS_TO_USER[token] = {"user_id": user["id"]}

    return {
        "token": token,
        "user_code": user["user_code"],
        "full_name": user["full_name"],
        "email": user["email"],
        "ref_code": user["ref_code"],
    }


@app.get("/api/account/summary")
def account_summary(authorization: str | None = Header(default=None)):
    user = get_auth_user(authorization)
    return {
        "user_code": user["user_code"],
        "full_name": user["full_name"],
        "ref_code": user["ref_code"],
        "available_balance": float(user["available_balance"]),
        "locked_balance": float(user["locked_balance"]),
        "total_profit": float(user["total_profit"]),
        "total_invested": float(user["total_invested"]),
        "completed_cycles": user["completed_cycles"],
        "active_investments": user["active_investments"],
    }


@app.get("/api/transactions")
def list_transactions(authorization: str | None = Header(default=None)):
    user = get_auth_user(authorization)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, tx_type AS type, title, method, network,
                       amount::float AS amount, fee::float AS fee, status,
                       tx_hash AS "txHash", address,
                       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS date
                FROM transactions
                WHERE user_id = %s
                ORDER BY id DESC
                """,
                (user["id"],),
            )
            rows = cur.fetchall()
    return {"transactions": rows}


@app.post("/api/deposits/create")
def create_deposit(payload: CreateDepositRequest, authorization: str | None = Header(default=None)):
    user = get_auth_user(authorization)
    order_id = f"ORD-{secrets.token_hex(5).upper()}"

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO deposits (user_id, order_id, network, method, amount, fee, status)
                VALUES (%s, %s, %s, %s, %s, 0.00, 'pending')
                """,
                (user["id"], order_id, payload.network, payload.method, payload.amount),
            )
            cur.execute(
                """
                INSERT INTO transactions (user_id, tx_type, title, method, network, amount, fee, status, tx_hash, address)
                VALUES (%s, 'deposit', %s, %s, %s, %s, 0.00, 'pending', 'Awaiting confirmation...', %s)
                """,
                (
                    user["id"],
                    f"{payload.method} Deposit",
                    payload.method,
                    payload.network,
                    payload.amount,
                    payload.network,
                ),
            )
        conn.commit()

    return {"order_id": order_id, "status": "pending", "amount": round(payload.amount, 2)}


@app.post("/api/webhooks/deposit")
def deposit_webhook(payload: DepositWebhookPayload, x_webhook_secret: str | None = Header(default=None)):
    if WEBHOOK_SECRET and x_webhook_secret != WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Invalid webhook secret.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM deposits WHERE order_id = %s", (payload.order_id,))
            dep = cur.fetchone()
            if not dep:
                raise HTTPException(status_code=404, detail="Deposit order not found.")

            if dep["status"] == "completed":
                return {"message": "Already credited.", "status": "completed"}

            cur.execute("SELECT id FROM deposits WHERE tx_hash = %s AND status = 'completed'", (payload.tx_hash,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Duplicate tx_hash.")

            if payload.status.lower() not in ("paid", "completed") or payload.amount < 5.0:
                cur.execute(
                    "UPDATE deposits SET status = 'rejected', tx_hash = %s WHERE id = %s",
                    (payload.tx_hash, dep["id"]),
                )
                cur.execute(
                    """
                    UPDATE transactions
                    SET status = 'rejected', tx_hash = %s
                    WHERE id = (
                        SELECT id FROM transactions
                        WHERE user_id = %s AND tx_type = 'deposit' AND status = 'pending'
                        ORDER BY id DESC LIMIT 1
                    )
                    """,
                    (payload.tx_hash, dep["user_id"]),
                )
                conn.commit()
                return {"message": "Deposit rejected.", "status": "rejected"}

            cur.execute(
                """
                UPDATE deposits
                SET status = 'completed', tx_hash = %s, amount = %s, verified_at = now()
                WHERE id = %s
                """,
                (payload.tx_hash, payload.amount, dep["id"]),
            )
            cur.execute(
                """
                UPDATE users
                SET available_balance = available_balance + %s
                WHERE id = %s
                RETURNING available_balance::float AS available_balance, user_code
                """,
                (payload.amount, dep["user_id"]),
            )
            updated_user = cur.fetchone()
            cur.execute(
                """
                UPDATE transactions
                SET status = 'completed', amount = %s, tx_hash = %s
                WHERE id = (
                    SELECT id FROM transactions
                    WHERE user_id = %s AND tx_type = 'deposit' AND status = 'pending'
                    ORDER BY id DESC LIMIT 1
                )
                """,
                (payload.amount, payload.tx_hash, dep["user_id"]),
            )
        conn.commit()

    return {
        "message": "Credited automatically.",
        "user_code": updated_user["user_code"],
        "available_balance": updated_user["available_balance"],
    }


@app.post("/api/withdrawals/create")
def create_withdrawal(payload: CreateWithdrawRequest, authorization: str | None = Header(default=None)):
    user = get_auth_user(authorization)
    if float(user["available_balance"]) < payload.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET available_balance = available_balance - %s
                WHERE id = %s
                RETURNING available_balance::float AS available_balance
                """,
                (payload.amount, user["id"]),
            )
            updated = cur.fetchone()
            cur.execute(
                """
                INSERT INTO transactions (user_id, tx_type, title, method, network, amount, fee, status, tx_hash, address)
                VALUES (%s, 'withdraw', %s, %s, %s, %s, 0.00, 'pending', 'Queued...', %s)
                """,
                (
                    user["id"],
                    f"{payload.method} Withdrawal",
                    payload.method,
                    payload.network,
                    payload.amount,
                    payload.address,
                ),
            )
        conn.commit()

    return {"available_balance": updated["available_balance"]}


@app.post("/api/investments/create")
def create_investment(payload: CreateInvestmentRequest, authorization: str | None = Header(default=None)):
    user = get_auth_user(authorization)
    if float(user["available_balance"]) < payload.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance.")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET available_balance = available_balance - %s,
                    locked_balance = locked_balance + %s,
                    total_invested = total_invested + %s,
                    active_investments = active_investments + 1
                WHERE id = %s
                RETURNING available_balance::float AS available_balance, locked_balance::float AS locked_balance
                """,
                (payload.amount, payload.amount, payload.amount, user["id"]),
            )
            updated = cur.fetchone()
            cur.execute(
                """
                INSERT INTO transactions (user_id, tx_type, title, method, network, amount, fee, status, tx_hash, address)
                VALUES (%s, 'invest', %s, 'USDT', 'BEP20', %s, 0.00, 'completed', 'Active 5-Day Cycle', 'Locked Vault')
                """,
                (user["id"], f"Investment — {payload.plan} Plan", payload.amount),
            )
        conn.commit()

    return {
        "available_balance": updated["available_balance"],
        "locked_balance": updated["locked_balance"],
    }
