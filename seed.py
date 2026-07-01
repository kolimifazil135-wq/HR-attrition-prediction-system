# Run this script once before starting the app to create the default admin account.
# Usage: python seed.py

from app.database import Base, SessionLocal, engine
from app.models import User, UserRole
from app.security import hash_password

# ── Default Admin Credentials ─────────────────────────────
# Use these details to log in at POST /auth/login
ADMIN_NAME     = "Super Admin"
ADMIN_EMAIL    = "admin@hrportal.com"
ADMIN_PASSWORD = "Admin@1234"
# ─────────────────────────────────────────────────────────

def seed():
    # Create all tables if they don't exist yet
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == ADMIN_EMAIL).first()
        if existing:
            print(f"[SKIP] Admin already exists: {ADMIN_EMAIL}")
            return

        admin = User(
            name=ADMIN_NAME,
            email=ADMIN_EMAIL,
            hashed_password=hash_password(ADMIN_PASSWORD),
            role=UserRole.admin,
            is_active=True,
            signup_completed=True,
        )
        db.add(admin)
        db.commit()
        print("[OK] Admin user created successfully")
        print(f"  Email    : {ADMIN_EMAIL}")
        print(f"  Password : {ADMIN_PASSWORD}")
        print(f"  Role     : admin")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
