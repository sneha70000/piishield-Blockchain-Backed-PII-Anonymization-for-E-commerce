import hashlib
import secrets
from models import get_db, User

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${dk.hex()}"

def hash_answer(answer: str, username: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", answer.strip().lower().encode(), username.encode(), 10_000).hex()

account_data = {
    "google@piishield": {"pwd": "Bhakthi@345", "q": "What is your pet's name?", "a": "meow"},
    "google-auditor@piishield": {"pwd": "Bhakthi@123", "q": "In which city were you born?", "a": "kupetti"},
    "google-analyst@piishield": {"pwd": "Bhakthi@234", "q": "What is your nickname?", "a": "baski"},
    "flipkart@piishield": {"pwd": "Sneha@345", "q": "What is your pet's name?", "a": "chinni"},
    "flipkart-auditor@piishield": {"pwd": "Sneha@123", "q": "In which city were you born?", "a": "kadaba"},
    "flipkart-analyst@piishield": {"pwd": "Sneha@234", "q": "What is your nickname?", "a": "minchu"},
    "demofirm@piishield": {"pwd": "Shama@345", "q": "What is your pet's name?", "a": "fluffy"},
    "demofirm-auditor@piishield": {"pwd": "Shama@123", "q": "In which city were you born?", "a": "kudla"},
    "demofirm-analyst@piishield": {"pwd": "Shama@234", "q": "What is your nickname?", "a": "shamu"},
    "amazon@piishield": {"pwd": "Raksha@345", "q": "What is your pet's name?", "a": "Brownie"},
    "amazon-auditor@piishield": {"pwd": "Raksha@123", "q": "In which city were you born?", "a": "kalladka"},
    "amazon-analyst@piishield": {"pwd": "Raksha@234", "q": "What is your nickname?", "a": "donti"},
}

db = next(get_db())

for username, data in account_data.items():
    user = db.query(User).filter(User.username == username).first()
    if user:
        user.password_hash = hash_password(data["pwd"])
        user.security_question = data["q"]
        user.security_answer_hash = hash_answer(data["a"], username)
        print(f"Successfully updated: {username}")
    else:
        print(f"Warning: Account {username} not found.")

db.commit()
print("All specified accounts have been set to your exact passwords and answers.")
