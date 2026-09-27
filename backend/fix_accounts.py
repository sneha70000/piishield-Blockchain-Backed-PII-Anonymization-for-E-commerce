import hashlib
from models import get_db, User

db = next(get_db())
broken_users = db.query(User).filter(
    (User.security_question == None) | (User.security_question == "")
).all()

if not broken_users:
    print("No broken accounts found. Everything is already fixed!")
else:
    for user in broken_users:
        user.security_question = "What is your default recovery key?"
        answer = "admin123"
        user.security_answer_hash = hashlib.pbkdf2_hmac(
            "sha256", 
            answer.encode(), 
            user.username.encode(), 
            10_000
        ).hex()
        print(f"Fixed account: {user.username}")

    db.commit()
    print("All old accounts updated successfully.")
