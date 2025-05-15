# app.py

import streamlit as st
from cryptography.fernet import Fernet
import hashlib


# Generate and save Fernet key once per session (for encryption/decryption)
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

# Create Fernet object for encryption operations
fernet = Fernet(st.session_state.fernet_key)

# In-memory dictionary to store data
# Format: {data_key: {"encrypted_text": ..., "passkey_hash": ...}}
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# Track number of failed attempts for passkey validation
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Track if user is authorized (logged in)
if "logged_in" not in st.session_state:
    st.session_state.logged_in = True  # Start with logged in status


# Helper Functions


def hash_passkey(passkey: str) -> str:
    """
    Returns SHA-256 hashed passkey as hex string.
    Used to securely store and compare passkeys without storing them in plaintext.
    """
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(plaintext: str) -> str:
    """
    Encrypt the plaintext string using Fernet symmetric encryption.
    Returns a base64 encoded ciphertext string.
    """
    return fernet.encrypt(plaintext.encode()).decode()

def decrypt_data(ciphertext: str) -> str:
    """
    Decrypt the base64 encoded ciphertext using Fernet symmetric encryption.
    Returns the original plaintext string.
    """
    return fernet.decrypt(ciphertext.encode()).decode()

# Page: Login (Reauthorization)

def login_page():
    st.title("Login - Reauthorization Required")

    # Simple password prompt for login (demo password: "admin")
    password = st.text_input("Enter admin password:", type="password")

    if st.button("Login"):
        if password == "admin":
            # Reset failed attempts and allow access
            st.session_state.logged_in = True
            st.session_state.failed_attempts = 0
            st.success("Login successful! You may continue.")
        else:
            st.error("Incorrect password. Please try again.")

# Page: Insert Data (Store Encrypted)

def insert_data():
    st.title("Store New Data")

    # User inputs
    data_key = st.text_input("Enter unique key for your data (e.g., user1_data):")
    data_text = st.text_area("Enter data/text to encrypt and store:")
    passkey = st.text_input("Enter passkey to secure this data:", type="password")

    if st.button("Store Data"):
        if not data_key or not data_text or not passkey:
            st.error("All fields are required!")
            return
        
        # Hash the passkey and encrypt the data
        passkey_hashed = hash_passkey(passkey)
        encrypted_text = encrypt_data(data_text)

        # Save in session_state dictionary
        st.session_state.stored_data[data_key] = {
            "encrypted_text": encrypted_text,
            "passkey_hash": passkey_hashed
        }

        st.success(f"Data stored securely under key: '{data_key}'")

# Page: Retrieve Data (Decrypt)

def retrieve_data():
    st.title("Retrieve Data")

    # User inputs
    data_key = st.text_input("Enter your data key to retrieve:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Retrieve"):
        if not data_key or not passkey:
            st.error("Both fields are required!")
            return
        
        # Fetch the stored entry for the key
        entry = st.session_state.stored_data.get(data_key)

        if not entry:
            st.error("No data found for this key.")
            return
        
        # Validate passkey by comparing hashes
        if hash_passkey(passkey) == entry["passkey_hash"]:
            try:
                # Decrypt and display the data
                decrypted_text = decrypt_data(entry["encrypted_text"])
                st.success(f"Decrypted data:\n\n{decrypted_text}")

                # Reset failed attempts on success
                st.session_state.failed_attempts = 0
            except Exception:
                st.error("Decryption error. Data may be corrupted.")
        else:
            # Increase failed attempts counter
            st.session_state.failed_attempts += 1
            st.error(f"Incorrect passkey. Attempts: {st.session_state.failed_attempts}/3")

            # If 3 failed attempts, force login
            if st.session_state.failed_attempts >= 3:
                st.warning("Too many failed attempts. Please reauthorize.")
                st.session_state.logged_in = False
                st.session_state.failed_attempts = 0

# Main App Navigation

def main():
    st.sidebar.title("Secure Data Encryption System")

    # If not logged in, show login page first
    if not st.session_state.logged_in:
        login_page()
        return

    # Page selection via sidebar radio buttons
    page = st.sidebar.radio("Select Page:", ["Home", "Insert Data", "Retrieve Data"])

    if page == "Home":
        st.title("Welcome to Secure Data Encryption System")
        st.write(
            "Use the sidebar to:\n"
            "- Store new encrypted data securely\n"
            "- Retrieve and decrypt stored data"
        )
    elif page == "Insert Data":
        insert_data()
    elif page == "Retrieve Data":
        retrieve_data()

# Entry point
if __name__ == "__main__":
    main()
