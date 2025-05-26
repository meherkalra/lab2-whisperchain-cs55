"""
Storage utilities for Lab 2, WhisperChain+
This module handles json file creation (messages, user, audit, tokens, keys) and management.
Authors: Meher Kalra (meher.kalra.25@dartmouth.edu), Atharv Agashe (atharv.v.agashe.25@dartmouth.edu)
"""

import json
from pathlib import Path
import time

# Constants
DATA_DIR = Path("data")                         # Path to the data directory
USERS_FILE = DATA_DIR / "users.json"            # Path to the users file
MESSAGES_FILE = DATA_DIR / "messages.json"      # Path to the messages file
TOKENS_FILE = DATA_DIR / "tokens.json"          # Path to the tokens file
AUDIT_LOG_FILE = DATA_DIR / "audit_log.json"    # Path to the audit log file

def ensure_data_files_exist():
    """
    Ensure all required data files exist.
    If they don't exist, create them with default structure.
    """

    # Create data directory if it doesn't exist
    DATA_DIR.mkdir(exist_ok=True)
    
    # Create users.json if it doesn't exist
    if not USERS_FILE.exists():
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    
    # Create messages.json if it doesn't exist
    if not MESSAGES_FILE.exists():
        with open(MESSAGES_FILE, 'w') as f:
            json.dump({
                "messages": []
            }, f)
    
    # Create tokens.json if it doesn't exist
    if not TOKENS_FILE.exists():
        with open(TOKENS_FILE, 'w') as f:
            json.dump({
                "tokens": []
            }, f)
    
    # Create audit_log.json if it doesn't exist
    if not AUDIT_LOG_FILE.exists():
        with open(AUDIT_LOG_FILE, 'w') as f:
            json.dump({
                "logs": []
            }, f)


def load_data(file_path):
    """
    Load data from a JSON file.

    Args:
        file_path (Path): Path to the JSON file
        
    Returns:
        dict: Loaded data or empty dict if file doesn't exist or is invalid
    """

    # Check if file exists
    if not file_path.exists():
        return {}
    
    # Load data from file
    with open(file_path, 'r') as f:
        try:
            # Return the loaded data
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_data(file_path, data):
    """
    Save data to a JSON file.

    Args:
    file_path (Path): Path to the JSON file
        data (dict): Data to save
    """

    # Save the data to the file
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)


def log_action(role, action, details=None):    
    """
    Log a user action to the audit log.

    Args:
        role (str): The username of the actor
        action (str): The action performed
        details (dict, optional): Additional details about the action
    """

    # Load existing audit log
    audit_data = load_data(AUDIT_LOG_FILE)
    
    # Create logs list if it doesn't exist
    if "logs" not in audit_data:
        audit_data["logs"] = []
    
    # Create log entry (all log entries have a timestamp, role, action, and any additional details)
    log_entry = {
        "timestamp": int(time.time()),
        "role": role,
        "action": action,
        "details": details or {}
    }
    
    # Add log entry to logs list
    audit_data["logs"].append(log_entry)
    
    # Save updated audit log
    save_data(AUDIT_LOG_FILE, audit_data)
