# Run this script once before starting the app to create the default admin account.
# Usage: python seed.py
#
# Role System (3 roles):
#   admin    — Full system access. Platform administrator. This is the seeded account.
#   hr       — HR department personnel. Assigned by admin after user creation.
#   employee — Standard / line user. Default role for all new accounts and OAuth sign-ups.
#
# After seeding, use POST /users (admin only) to create additional users with the
# desired role (admin | hr | employee).

from app.database import Base, SessionLocal, engine
from app.models import User, UserRole
from app.security import hash_password

# ── Default Admin Credentials ─────────────────────────────
# Use these details to log in at POST /auth/admin/login
ADMIN_NAME     = "Super Admin"
ADMIN_EMAIL    = "admin@hrportal.com"
ADMIN_PASSWORD = "Admin@1234"
# ─────────────────────────────────────────────────────────


def seed():
    # Create all tables if they don't exist yet (uses updated 3-role ENUM from models.py)
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
        print(f"  Role     : {UserRole.admin.value}")
        print()
        print("[INFO] Available roles for user creation via POST /users:")
        for role in UserRole:
            print(f"  - {role.value}")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
