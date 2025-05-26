"""
Authorization module for Lab 2, WhisperChain+
This module handles user registration, login, keypair generation, password verificaation.
Authors: Meher Kalra (meher.kalra.25@dartmouth.edu), Atharv Agashe (atharv.v.agashe.25@dartmouth.edu)
"""

import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Path to the data directory
DATA_DIR = "data"

# Create the data directory if it doesn't exist
Path(DATA_DIR).mkdir(exist_ok=True)

# Path to the users file
USER_FILE = Path(DATA_DIR) / "users.json"

# Helper function that loads user info
def load_users():
    # If the users file doesn't exist, return an empty dictionary
    if not USER_FILE.exists():
        return {}
    
    # Open the users file and load the user info
    with open(USER_FILE, "r") as f:
        # Try to load the user info
        try:
            return json.load(f)
        # If the file is not valid JSON, return an empty dictionary
        except json.JSONDecodeError:
            return {}

# Helper function that saves user info
def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

# Password hashing 
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Password verification by comparing the stored hash to the hashed password attempt
def verify_password(stored_hash, password_attempt):
    return stored_hash == hash_password(password_attempt)

# Helper function that checks if a user is an admin
def is_admin(user_data):
    return user_data.get("role") == "admin"

# Helper function that checks if a user is pending
def is_pending(user_data):
    return user_data.get("role") == "pending"

# Key pair generation
def generate_key_pair():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate a public key from the private key
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Return the private and public keys as strings
    return private_bytes.decode('utf-8'), public_bytes.decode('utf-8')

# User registration
def register_user(username, password):
    # Load the users
    users = load_users()

    # If the username already exists, return False and the error message
    if username in users:
        return False, "Username already exists."
    
    # If the user is the first user, they are an admin. Otherwise, they are pending
    if len(users) == 0:
        role = "admin" 
    else:
        role = "pending"

    # Add the user to the users dictionary
    users[username] = {
        "password": hash_password(password),
        "role": role
    }

    # Save the users
    save_users(users)   

    # Generate a key pair for the new user
    private_key, public_key = generate_key_pair()

    # Create the private keys directory if it doesn't exist
    privkey_dir = Path(DATA_DIR) / "private_keys"
    privkey_dir.mkdir(exist_ok=True)

    # Save the private key
    with open(privkey_dir / f"{username}.pem", "w") as f:
        f.write(private_key)

    # Store public key in the central public keys file
    pubkey_file = Path(DATA_DIR) / "public_keys.json"

    # If the public keys file doesn't exist, create it
    if pubkey_file.exists():
        with open(pubkey_file, "r") as f:
            pubkeys = json.load(f)
    else:
        pubkeys = {}

    # Add the public key to the public keys dictionary
    pubkeys[username] = public_key

    # Save the public keys  
    with open(pubkey_file, "w") as f:
        json.dump(pubkeys, f, indent=4)

    # Return True and the success message
    return True, f"User registered as '{role}' and key pair generated."

# Login function
def login_user(username, password):
    # Load the users
    users = load_users()

    # If the user doesn't exist, return False and the error message
    if username not in users:
        return False, "User does not exist."
    
    # If the password is incorrect, return False and the error message
    if not verify_password(users[username]["password"], password):
        return False, "Incorrect password."
    
    # If the user exists and the password is correct, return True and the user's data
    return True, {"username": username, "role": users[username]["role"]}

# Role assignment for admin only
def assign_role(admin_user_data, target_username, new_role):
    # If the user is not an admin, return False and the error message
    if not is_admin(admin_user_data):
        return False, "Only admins can assign roles."

    # Load the users
    users = load_users()

    # If the target user doesn't exist, return False and the error message
    if target_username not in users:
        return False, "Target user does not exist."

    # If the new role is invalid, return False and the error message
    if new_role not in ['user', 'moderator']:
        return False, "Invalid role. Must be user or moderator."

    # If the new role is valid, and the target user exists, assign the new role to the target user
    users[target_username]['role'] = new_role

    # Save the new user roles
    save_users(users)

    # Return True and the success message
    return True, f"Assigned role '{new_role}' to user '{target_username}'."
