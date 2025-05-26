"""
Token management for Lab 2, WhisperChain+
This file handles token creation, verification, and management for anonymous message sending.
Authors: Meher Kalra (meher.kalra.25@dartmouth.edu), Atharv Agashe (atharv.v.agashe.25@dartmouth.edu)
"""

import time
import hashlib
import base64
import json
from pathlib import Path
import random
import string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Import storage utilities
from utils.storage import load_data, save_data, log_action

# Constants
DATA_DIR = Path("data")                 # Path to the data directory
TOKENS_FILE = DATA_DIR / "tokens.json"  # Path to the tokens file
PUBLIC_KEYS_FILE = DATA_DIR / "public_keys.json"  # Path to public keys file
PRIVATE_KEYS_DIR = DATA_DIR / "private_keys"  # Path to private keys directory
ROUND_DURATION = 600                    # 10 minutes in seconds


def encrypt_token(token: str, username: str) -> tuple[bool, str, str]:
    """
    Encrypt a token using the user's public key.
    
    Args:
        token (str): The token to encrypt
        username (str): The username whose public key to use
        
    Returns:
        tuple: (success, encrypted_token, message)
        - success (bool): True if encryption was successful
        - encrypted_token (str): The encrypted token in base64 format
        - message (str): Success or error message
    """
    try:
        # Load public keys
        with open(PUBLIC_KEYS_FILE, 'r') as f:
            public_keys = json.load(f)
            
        # If the user is not registered, return False and the error message
        if username not in public_keys:
            return False, None, "User's public key not found."
            
        # Load user's public key
        public_key = serialization.load_pem_public_key(
            public_keys[username].encode()
        )
        
        # Encrypt the token using the user's public key
        encrypted_token = public_key.encrypt(
            token.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convert to base64 for storage
        encrypted_b64 = base64.b64encode(encrypted_token).decode('utf-8')
        
        # Return True and the encrypted token and the success message
        return True, encrypted_b64, "Token encrypted successfully."
        
    # If any exception is thrown, return False and the error message    
    except Exception as e:
        return False, None, f"Token encryption failed: {str(e)}"


def generate_token(username: str) -> tuple[str, str]:
    """
    Generate a new token for a user.
    
    Args:
        username (str): The username to generate a token for
        
    Returns:
        tuple: (encrypted_token, message)
        - encrypted_token (str): The encrypted token or None if generation failed
        - message (str): Success or error message
    """
    try:
        # Load tokens
        tokens_data = load_data(TOKENS_FILE)
        
        # Check any of the user's tokens have been frozen
        for token in tokens_data.get("tokens", []):
            # If the token is for the user and is frozen, return None and the error message
            if token["username"] == username and token.get("frozen"):
                return None, "Your account has been suspended due to inappropriate content."
            
        # Check if user already has a token for the current round
        for token in tokens_data.get("tokens", []):
            # If the token is for the user and is for the current round, return None and the error message
            if token["username"] == username and token["round"] == get_current_round():
                return None, "You have already generated a token for the current round."
        
        # If the user does not have a token for the current round and their account is not frozen, we can generate a new token
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=32)) # Generate random token of length 32
        
        # Hash the token
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        
        # Get current round
        current_round = get_current_round()
        
        # Encrypt token with user's public key
        success, encrypted_token, msg = encrypt_token(token, username)

        # If the encryption fails, return None and the error message
        if not success:
            return None, f"Failed to encrypt token: {msg}"
        
        # Create token entry
        token_entry = {
            "username": username,
            "token_hash": token_hash,
            "encrypted_token": encrypted_token,
            "round": current_round,
            "used": False,
            "frozen": False
        }
        
        # If the tokens list does not exist, create it
        if "tokens" not in tokens_data:
            tokens_data["tokens"] = []

        # Add token to tokens list
        tokens_data["tokens"].append(token_entry)
        
        # Save updated tokens
        save_data(TOKENS_FILE, tokens_data)
        
        # Return the encrypted token and the success message
        return encrypted_token, "Token generated successfully."
        
    # If any exception is thrown, return None and the error message
    except Exception as e:
        return None, f"Token generation failed: {str(e)}"


def verify_token(token_hash: str, username: str):
    """
    Verify if a token is valid. If it is return True and mark it as used.
    The provided token should be encrypted with the user's private key.
    Using PEM format for public/private keys.

    Args:
        encrypted_token (str): The encrypted token to verify
        public_key_pem (str): The user's public key in PEM format
        
    Returns:
        tuple: (success, message)
        - success (bool): True if token is valid, False otherwise
        - message (str): Success or error message
    """
    try:
        # Load all existing token hashes from the tokens file
        token_data = load_data(TOKENS_FILE)
        
        # Find the provided token's hash in tokens list
        for i, token_entry in enumerate(token_data.get("tokens", [])):
            if token_entry["token_hash"] == token_hash:
                # If the token is found, check if it has already been used
                if token_entry["used"]:
                    return False, "Token has already been used."
                
                # If the token is unused, check that it is for the current round
                current_round = get_current_round()
                if token_entry["round"] != current_round:
                    return False, "Token is not valid for the current round."
                
                # Check that the token is for the user
                if token_entry["username"] != username:
                    return False, "Token is not valid for the user."
                
                # If the token is for the current round and unused, it is valid
                # Mark token as used and save the timestamp
                token_data["tokens"][i]["used"] = True
                token_data["tokens"][i]["used_at"] = int(time.time())
                
                # Save updated tokens
                save_data(TOKENS_FILE, token_data)
                
                # Log token usage without revealing the username
                # Log the token hash instead, since it has been used already it can't be used again
                log_action("sender", "token_used", {
                    "round": current_round,
                    "token_hash": token_hash,
                    "timestamp": token_data["tokens"][i]["used_at"]
                })
                
                # Return True and success message
                return True, "Token successfully verified."
        
        # If the token is not found, it is invalid
        return False, "Invalid token."
        
    # If there is an error, return False and error message
    except Exception as e:
        return False, f"Token verification failed: {str(e)}"


def get_current_round():
    """
    Get the current round number. Rounds last for 10 minutes.
    
    Returns:
        int: Current round number
    """
    # Get current timestamp
    current_time = int(time.time())
    
    # Calculate round number (each round is 10 minutes)
    return 1 + (current_time // ROUND_DURATION)


def get_current_token(username: str) -> tuple[str, str]:
    """
    Get the user's current round token and decrypt it using their private key.
    
    Args:
        username (str): The username to get the token for
        
    Returns:
        tuple: (decrypted_token, message)
        - decrypted_token (str): The decrypted token or None if failed
        - message (str): Success or error message
    """
    try:
        # Load tokens data
        token_data = load_data(TOKENS_FILE)
        
        # Get current round
        current_round = get_current_round()
        
        # Find the user's unused token for current round
        for token_entry in token_data.get("tokens", []):
            # If the token is for the user, for the current round, and is unused, we can decrypt it
            if (token_entry["username"] == username and 
                token_entry["round"] == current_round and 
                not token_entry["used"]):
                
                # Load user's private key
                private_key_path = PRIVATE_KEYS_DIR / f"{username}.pem"

                # If the private key does not exist, return None and the error message
                if not private_key_path.exists():
                    return None, "Private key not found."
                    
                # Load the private key
                with open(private_key_path, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None  # No password protection for now
                    )
                
                # Decrypt the token
                encrypted_token = base64.b64decode(token_entry["encrypted_token"])
                decrypted_token = private_key.decrypt(
                    encrypted_token,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8')
                
                # Return the decrypted token and the success message
                return decrypted_token, "Token retrieved successfully."
                
        # If no valid token is found, return None and the error message
        return None, "No valid token found for current round."
        
    # If any exception is thrown, return None and the error message
    except Exception as e:
        return None, f"Failed to retrieve token: {str(e)}" 