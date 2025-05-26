"""
Message handling for Lab 2, WhisperChain+
This file handles message encryption, storage, and retrieval.
Authors: Meher Kalra (meher.kalra.25@dartmouth.edu), Atharv Agashe (atharv.v.agashe.25@dartmouth.edu)
"""

import hashlib
import json
import base64
import random
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from utils.storage import load_data, save_data, log_action
import time
from crypto.tokens import get_current_round, verify_token

# Constants
DATA_DIR = Path("data")
MESSAGES_FILE = DATA_DIR / "messages.json"
PUBLIC_KEYS_FILE = DATA_DIR / "public_keys.json"
TOKENS_FILE = DATA_DIR / "tokens.json"
PRIVATE_KEYS_DIR = DATA_DIR / "private_keys"
USERS_FILE = DATA_DIR / "users.json"

def encrypt_message(message: str, recipient_username: str) -> tuple[bool, str, str]:
    """
    Encrypt a message using the recipient's public key.
    
    Args:
        message (str): The message to encrypt
        recipient_username (str): The username of the recipient
        
    Returns:
        tuple: (success, encrypted_message, message)
        - success (bool): True if encryption was successful
        - encrypted_message (str): The encrypted message in base64 format
        - message (str): Success or error message
    """
    try:
        # Load public keys
        with open(PUBLIC_KEYS_FILE, 'r') as f:
            public_keys = json.load(f)
            
        # Make sure recipient is registered
        if recipient_username not in public_keys:
            return False, None, "Recipient not found."
            
        # Load recipient's public key from public keys file
        public_key = serialization.load_pem_public_key(
            public_keys[recipient_username].encode()
        )
        
        # Encrypt the message
        # Using OAEP padding for encryption as it is recommended by the cryptography library for asymmetric encryption
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode the encrypted message to base64
        encrypted_b64 = base64.b64encode(encrypted_message).decode('utf-8')
        
        # Return True, the encrypted message and the success message
        return True, encrypted_b64, "Message encrypted successfully."
        
    # If any exception is thrown, return False, None for the encrypted message and the error message
    except Exception as e:
        return False, None, f"Encryption failed: {str(e)}"

def store_message(recipient_username: str, encrypted_message: str, token_hash: str) -> tuple[bool, str]:
    """
    Store an encrypted message in the messages file.
    
    Args:
        recipient_username (str): The username of the recipient
        encrypted_message (str): The encrypted message in base64 format
        token_hash (str): The token hash used to send the message
        
    Returns:
        tuple: (success, message)
        - success (bool): True if storage was successful
        - message (str): Success or error message
    """
    try:
        # Load the messages data (to which we will append the new message)
        messages_data = load_data(MESSAGES_FILE)
        
        # Initialize messages list if it doesn't exist (first time storing messages)
        if "messages" not in messages_data:
            messages_data["messages"] = []
            
        # Create message entry
        # The message entry contains the recipient, the encrypted message, the token hash, and the timestamp
        # This is all the information needed for the recipient to read the message and for corroborating against the audit log later
        message_entry = {
            "recipient": recipient_username,
            "encrypted_message": encrypted_message,
            "token_hash": token_hash,
            "timestamp": int(time.time())
        }
        
        # Add message to messages list
        messages_data["messages"].append(message_entry)
        
        # Save updated messages data to the messages file
        save_data(MESSAGES_FILE, messages_data)
        
        # Log message sending with the token hash and the timestamp
        # Don't include the encrypted message or recipient username in the audit log for privacy/storage reasons
        # We can look up this information if needed using the token hash
        log_action("recipient", "message_received", {
            "token_hash": token_hash,
            "timestamp": message_entry["timestamp"]
        })
        
        # Return True and the success message
        return True, "Message sent successfully."
        
    # If any exception is thrown, return False and the error message
    except Exception as e:
        return False, f"Failed to store message: {str(e)}"

def send_message(sender_username: str, recipient_username: str, message: str, decrypted_token: str) -> tuple[bool, str]:
    """
    Send an encrypted message to a recipient.
    
    Args:
        sender_username (str): The username of the sender
        recipient_username (str): The username of the recipient
        message (str): The message to send
        decrypted_token (str): The encrypted token used to send the message
        
    Returns:
        tuple: (success, message)
        - success (bool): True if sending was successful
        - message (str): Success or error message
    """
    # First verify the encrypted token by hashing it and checking against the sender's username
    token_hash = hashlib.sha256(decrypted_token.encode('utf-8')).hexdigest()
    success, msg = verify_token(token_hash, sender_username)

    # If the token is not valid, return False and the error message
    if not success:
        return False, msg
        
    # Then encrypt the message
    success, encrypted_message, msg = encrypt_message(message, recipient_username)

    # If the encryption fails, return False and the error message
    if not success:
        return False, msg

    # Finally store the encrypted message and the token hash under the recipient's username
    return store_message(recipient_username, encrypted_message, token_hash)

def decrypt_message(encrypted_message: str, username: str) -> tuple[bool, str, str]:
    """
    Decrypt a message using the recipient's private key.
    
    Args:
        encrypted_message (str): The encrypted message in base64 format
        username (str): The username of the recipient
        
    Returns:
        tuple: (success, decrypted_message, message)
        - success (bool): True if decryption was successful
        - decrypted_message (str): The decrypted message or None if failed
        - message (str): Success or error message
    """
    try:
        # Load user's private key
        private_key_path = PRIVATE_KEYS_DIR / f"{username}.pem"

        # If the private key does not exist, return False and the error message
        if not private_key_path.exists():
            return False, None, "Private key not found."
            
        # Load the private key using the cryptography library
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None  # No password protection for now
            )
        
        # Decrypt the message using the private key
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted_message = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')
        
        # Return True, the decrypted message and the success message
        return True, decrypted_message, "Message decrypted successfully."
        
    # If any exception is thrown, return False, None for the decrypted message and the error message
    except Exception as e:
        return False, None, f"Decryption failed: {str(e)}"

def get_messages(username: str) -> tuple[bool, list, str]:
    """
    Get all messages for a recipient and decrypt them.
    
    Args:
        username (str): The username of the recipient
        
    Returns:
        tuple: (success, messages, message)
        - success (bool): True if retrieval was successful
        - messages (list): List of decrypted messages with metadata
        - message (str): Success or error message
    """
    try:
        # Load the messages data
        messages_data = load_data(MESSAGES_FILE)
        
        # Filter messages for this user
        recipient_messages = []
        for msg in messages_data.get("messages", []):

            # If the message is for this user, decrypt it using the user's private key
            if msg["recipient"] == username:

                # Decrypt the message
                success, decrypted_content, msg_text = decrypt_message(
                    msg["encrypted_message"], 
                    username
                )
                
                # If decryption succeeds, add the decrypted message to the list
                if success:
                    recipient_messages.append({
                        "content": decrypted_content,
                        "timestamp": msg["timestamp"],
                        "token_hash": msg["token_hash"]
                    })
                else:
                    # If decryption fails, include the error
                    recipient_messages.append({
                        "content": f"[Error: {msg_text}]",
                        "timestamp": msg["timestamp"],
                        "token_hash": msg["token_hash"]
                    })
        
        # Sort messages by timestamp (newest first)
        recipient_messages.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Return True, the list of decrypted messages and the success message   
        return True, recipient_messages, "Messages retrieved successfully."
        
    # If any exception is thrown, return False and an empty list for the messages and the error message
    except Exception as e:
        return False, [], f"Failed to retrieve messages: {str(e)}"

def flag_message(message: list, username: str) -> tuple[bool, str]:
    """
    Flag a message for moderation.
    
    Args:
        message_id (str): The token hash of the message to flag
        username (str): The username of the user flagging the message
        
    Returns:
        tuple: (success, message)
        - success (bool): True if flagging was successful
        - message (str): Success or error message
    """
    try:
        # Load the users data
        users_data = load_data(USERS_FILE)

        # Get all moderators
        moderators = [u for u, info in users_data.items() if info["role"] == "moderator"]
        
        # If there are no moderators, return False and the error message
        if not moderators:
            return False, "No moderators available."
            
        # Select random moderator
        moderator = random.choice(moderators)

        # Encrypt message for moderator
        success, encrypted_for_mod, msg_text = encrypt_message(
            message["content"],
            moderator
        )
        
        # If the encryption fails, return False and the error message
        if not success:
            return False, f"Failed to encrypt for moderator: {msg_text}"
        
        # Store the encrypted message for the moderator
        store_message(moderator, encrypted_for_mod, message["token_hash"])
        
        # Log the flagging
        log_action("recipient", "message_flagged", {
            "message_id": message["token_hash"],
        })
        
        # Return True and the success message
        return True, "Message flagged successfully."
            
    except Exception as e:
        return False, f"Failed to flag message: {str(e)}"

def get_flagged_messages(moderator_username: str) -> tuple[bool, list, str]:
    """
    Get all flagged messages for a moderator. This is just a wrapper around get_messages for the moderator.
    
    Args:
        moderator_username (str): The username of the moderator
        
    Returns:
        tuple: (success, messages, message)
        - success (bool): True if retrieval was successful
        - messages (list): List of flagged messages
        - message (str): Success or error message
    """
    # Get all messages for the moderator
    return get_messages(moderator_username)

def freeze_token(token_hash: str, moderator_username: str) -> tuple[bool, str]:
    """
    Freeze a token to prevent future use.
    
    Args:
        token_hash (str): The hash of the token to freeze
        moderator_username (str): The username of the moderator freezing the token
        
    Returns:
        tuple: (success, message)
        - success (bool): True if freezing was successful
        - message (str): Success or error message
    """
    try:
        # Load tokens
        tokens_data = load_data(TOKENS_FILE)
        
        # Find the token
        token_found = False
        for token in tokens_data.get("tokens", []):

            # If the token is found, mark it as frozen
            if token["token_hash"] == token_hash:
                token_found = True
                
                # Mark token as frozen and record the moderator who froze it and the timestamp
                token["frozen"] = True
                token["frozen_by"] = moderator_username
                token["frozen_at"] = int(time.time())
                
                # Save updated tokens
                save_data(TOKENS_FILE, tokens_data)
                
                # Log the freezing
                log_action("moderator", "token_frozen", {
                    "token_hash": token_hash,
                })
                
                # Return True and the success message
                return True, "Token frozen successfully."
                
        # If the token is not found, return False and the error message
        if not token_found:
            return False, "Token not found."
            
    # If any exception is thrown, return False and the error message
    except Exception as e:
        return False, f"Failed to freeze token: {str(e)}" 