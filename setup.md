# HR Attrition API — Setup Guide

## Prerequisites

- Python 3.10+
- MySQL 8.0+ running locally or remotely
- A Gmail account with **App Passwords** enabled (for SMTP)

---

## 1. Clone and enter the project 

```bash
git clone <repo-url>
cd "HR attrition"
```

---

## 2. Create and activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

---

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Configure environment variables

Copy the example below into a file named `.env` at the project root and fill in the blanks.

```env
# ── Database ────────────────────────────────────────────
DATABASE_URL=mysql+pymysql://<user>:<password>@localhost:3306/hr_attrition

# ── JWT ─────────────────────────────────────────────────
SECRET_KEY=replace-this-with-a-long-random-string
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# ── Email (Gmail App Password) ───────────────────────────
# 1. Go to https://myaccount.google.com/apppasswords
# 2. Create an app password for "Mail"
# 3. Paste the 16-character password below (no spaces)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_gmail@gmail.com
SMTP_PASSWORD=your_16_char_app_password

# ── Frontend ─────────────────────────────────────────────
# Base URL of the frontend app — included in the welcome email link
FRONTEND_BASE_URL=http://localhost:3000
```

> **How to get a Gmail App Password**
> 1. Enable 2-Step Verification on your Google account.
> 2. Go to **Google Account → Security → App Passwords**.
> 3. Select app: **Mail**, device: **Other**, name it `HR Portal`.
> 4. Copy the generated 16-character password into `SMTP_PASSWORD`.

---

## 5. Create the MySQL database

```sql
CREATE DATABASE hr_attrition CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

---

## 6. Seed the default admin account

```bash
python seed.py
```

Output on first run:

```
✓ Admin user created successfully
  Email    : admin@hrportal.com
  Password : Admin@1234
  Role     : admin
```

> Change the admin password immediately after first login in a production environment.

---

## 7. Start the development server

```bash
uvicorn app.main:app --reload

or 

venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

The API is now available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

> **If you ever see a "Fatal error in launcher" after renaming or moving the project folder:**  
> The venv `.exe` launchers embed the Python path at creation time. Fix it by running:  
> `venv\Scripts\python.exe -m pip install --force-reinstall uvicorn`  
> This regenerates the launcher pointing to the correct path. After that, `uvicorn` works normally again.

---

## 8. Database migrations (after model changes)

SQLAlchemy's `create_all` handles table creation automatically on startup.  
For existing databases where you added new columns, run a one-off ALTER or use Alembic:

```bash
# Quick approach Drop Database 
DROP DATABASE hr_attrition;
# And Create a New One
CREATE DATABASE hr_attrition CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

```

---

## API Flow

### Admin logs in

```
POST /auth/admin/login
{ "email": "admin@hrportal.com", "password": "Admin@1234" }
→ { "access_token": "...", "refresh_token": "...", "token_type": "bearer" }
```

> In Swagger UI (`/docs`) the token is captured automatically from the response —
> no Authorize button needed. All subsequent requests are authenticated transparently.

### Admin creates a new user

```
POST /users
Authorization: Bearer <admin_access_token>
{
  "name": "Jane Smith",
  "email": "jane@company.com",
  "role": "hr_manager"   ← one of: hr_manager | hr_business_partner | hr_analyst | department_manager
}
→ User created + welcome email sent (contains default password)
```

### User logs in

```
POST /auth/user/login
{ "email": "jane@company.com", "password": "<default-password-from-email>" }
→ { "access_token": "...", "refresh_token": "...", "token_type": "bearer" }
```

### User forgets password

```
# Step 1 — request OTP
POST /auth/forgot-password
{ "email": "jane@company.com" }
→ { "message": "If this email is registered, an OTP has been sent" }

# Step 2 — verify OTP, get reset token
POST /auth/forgot-password/verify-otp
{ "email": "jane@company.com", "otp": "847201" }
→ { "reset_token": "<uuid>", "message": "OTP verified..." }

# Step 3 — set new password
POST /auth/reset-password
{ "token": "<uuid>", "new_password": "NewPass1!", "confirm_password": "NewPass1!" }
→ { "message": "Password reset successfully" }
```

### Refresh access token

```
POST /auth/refresh-token
{ "refresh_token": "..." }
→ { "access_token": "...", "token_type": "bearer" }
```

### Logout

```
POST /auth/logout
Authorization: Bearer <access_token>
→ { "message": "Logged out successfully" }
```

### Get own profile

```
GET /auth/me
Authorization: Bearer <access_token>
→ { "id": 2, "name": "Jony bhai", "email": "...", "role": "hr_manager", ... }
```

---

## Project Structure

```
HR attrition/
├── app/
│   ├── config.py        ← Environment settings (pydantic-settings)
│   ├── database.py      ← SQLAlchemy engine, session, Base
│   ├── dependencies.py  ← FastAPI Depends helpers (auth guards)
│   ├── main.py          ← App entry point, router registration
│   ├── models.py        ← ORM models (User, UserRole)
│   ├── schemas.py       ← Pydantic request/response schemas
│   ├── security.py      ← Password hashing, JWT, OTP, email helpers
│   ├── static/
│   │   └── swagger_token.js ← Auto token capture for Swagger UI (no Authorize button needed)
│   ├── core/
│   │   └── oauth.py       ← Google & Microsoft token verification helpers
│   └── routers/
│       ├── admin_auth.py  ← POST /auth/admin/login  [Admin]
│       ├── auth.py        ← /auth/* endpoints       [Auth] + [OAuth]
│       └── users.py       ← /users/* endpoints      [Admin]
├── seed.py              ← Creates default admin account
├── requirements.txt
├── .env                 ← Local secrets (never commit this)
└── setup.md             ← This file
```

## Available Roles

| Role | Value | Description |
|------|-------|-------------|
| Admin | `admin` | Full system access — platform administrator |
| HR Manager | `hr_manager` | HR department lead |
| HR Business Partner | `hr_business_partner` | Strategic HR liaison per business unit |
| HR Analyst | `hr_analyst` | Data / reporting access (default for new users) |
| Department Manager | `department_manager` | Line manager — view own department data only |
