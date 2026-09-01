import os
import sys
import bcrypt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import DBUser, CANDIDATE_URLS

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 reset_admin_password.py <username> <new_password>")
        print("Example: python3 reset_admin_password.py admin MyNewSecretPwd123!")
        sys.exit(1)

    username = sys.argv[1]
    new_password = sys.argv[2]

    engine = None
    for url in CANDIDATE_URLS:
        try:
            eng = create_engine(url, connect_args={"connect_timeout": 5})
            with eng.connect() as conn:
                engine = eng
                print(f"✅ Connected to DB: {url.split('@')[-1]}")
                break
        except Exception as e:
            continue

    if not engine:
        print("❌ Failed to connect to DB.")
        sys.exit(1)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        user = db.query(DBUser).filter(DBUser.username == username).first()
        if not user:
            print(f"❌ User '{username}' not found in DB.")
            sys.exit(1)

        # Hash password directly using bcrypt library
        pwd_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password_hash = pwd_hash
        db.commit()
        print(f"🎉 Password for user '{username}' updated successfully in Supabase DB!")
    finally:
        db.close()

if __name__ == "__main__":
    main()
