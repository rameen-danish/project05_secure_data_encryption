import streamlit as st
import time
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ====== CONFIGURATION ======
DATA_FILE = "data.json"
USER_FILE = "users.json"
SALT = b"my_secret_salt"  # Ideally should be random and stored securely
LOCKOUT_SECONDS = 30

# ====== ENCRYPTION SETUP ======
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# ====== PERSISTENT STORAGE ======
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f)

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users():
    with open(USER_FILE, "w") as f:
        json.dump(st.session_state.users, f)

# ====== HASHING FUNCTIONS ======
def hash_passkey(passkey, salt=SALT):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ✅ Correct usage
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode())).decode()

# ====== ENCRYPTION FUNCTIONS ======
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    if st.session_state.get("lockout_time"):
        elapsed = time.time() - st.session_state.lockout_time
        if elapsed < LOCKOUT_SECONDS:
            st.warning(f"🔒 Please wait {int(LOCKOUT_SECONDS - elapsed)} seconds before trying again.")
            return None

    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_time = time.time()
    return None

# ====== INIT ======
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = load_data()
if 'users' not in st.session_state:
    st.session_state.users = load_users()
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None

# ====== UI ======
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login", "Register"]
choice = st.sidebar.selectbox("Navigation", menu)

# ==== HOME PAGE ====
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely **store** and **retrieve** encrypted data using unique passkeys.")
    if st.session_state.current_user:
        st.success(f"🔓 Logged in as: {st.session_state.current_user}")
        if st.button("Logout"):
            st.session_state.current_user = None
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            save_users()
            save_data()
            st.success("✅ Logged out successfully!")
            st.rerun()

# ==== REGISTER PAGE ====
elif choice == "Register":
    st.subheader("📝 Register New Account")
    new_username = st.text_input("Choose a username:")
    new_password = st.text_input("Choose a password:", type="password")

    if st.button("Register"):
        if not new_username or not new_password:
            st.error("⚠️ All fields are required.")
        elif new_username in st.session_state.users:
            st.error("❌ Username already exists.")
        else:
            st.session_state.users[new_username] = hash_passkey(new_password)
            save_users()
            st.success("✅ Registered successfully. You can now login.")

# ==== LOGIN PAGE ====
elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.button("Login"):
        if username in st.session_state.users and st.session_state.users[username] == hash_passkey(password):
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
            st.success(f"✅ Welcome, {username}!")
            save_users()
        
        else:
            st.error("❌ Invalid username or password.")

# ==== STORE DATA PAGE ====
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    if not st.session_state.current_user:
        st.warning("🔐 Please login to store data.")
    else:
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                hashed_pass = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                st.session_state.stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_pass,
                    "owner": st.session_state.current_user,
                }
                save_data()
                st.success("✅ Data stored securely.")
            # ::contentReference[oaicite:8]{index=8}
# ==== RETRIEVE DATA PAGE ====
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Encrypted Data")

    if not st.session_state.current_user:
        st.warning("🔐 Please login to retrieve data.")
    else:
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted)
                else:
                    attempts_left = max(0, 3 - st.session_state.failed_attempts)
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
            else:
                st.error("⚠️ Both fields are required.")
 
