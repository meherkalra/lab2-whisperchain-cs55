"""
Client interaction on the command line for Lab 2, WhisperChain+
This module handles the command line interface, providing menus and input
logic for different user roles (user, moderator, admin) and connecting to
authentication, message, and token utilities.
Authors: Meher Kalra (meher.kalra.25@dartmouth.edu), Atharv Agashe (atharv.v.agashe.25@dartmouth.edu)
"""

import os
import getpass
import sys
from datetime import datetime
from utils.auth import (register_user, login_user, is_pending, load_users, assign_role)
from utils.storage import ensure_data_files_exist
from crypto.tokens import generate_token, verify_token, get_current_token
from crypto.messages import send_message, get_messages, flag_message, get_flagged_messages, freeze_token

# Menu options for different user roles
SENDER_MENU = """
USER MENU
1. Request new token
2. Send anonymous message
3. View my messages
4. Logout
"""

MODERATOR_MENU = """
MODERATOR MENU
1. View flagged messages
2. Logout
"""

ADMIN_MENU = """
ADMIN MENU
1. Assign role to a user
2. View all users and roles
3. Logout
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print("=" * 32)
    print("          WHISPERCHAIN+")
    print("=" * 32)
    print()

# displays the first thing that the user sees 
def login_menu():
    while True:
        print_header()
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == '1':
            login()
        elif choice == '2':
            register()
        elif choice == '3':
            print("Thank you for using WhisperChain+. Goodbye!")
            sys.exit(0)
        else:
            input("Invalid choice. Press Enter to continue...")

# function to register a new user
def register():
    print_header()
    print("REGISTER NEW USER\n")
    
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    
    if password != confirm_password:
        input("Passwords do not match. Press Enter to continue...")
        return

    success, message = register_user(username, password)
    if success:
        input(message + " Key pair generated. Press Enter to continue...")
    else:
        input("Registration failed: " + message + " Press Enter to continue...")

# function to login an existing user. It checks for username and passwords
# if it succeeds, the program prompts the role menu
def login():
    print_header()
    print("USER LOGIN\n")
    
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    success, user_data = login_user(username, password)

    if not success:
        input(f"Login failed: {user_data}. Press Enter to continue...")
        return

    if is_pending(user_data):
        input("Your account is pending. Please wait for an admin to assign your role. Press Enter to continue...")
        return

    role_menu(user_data)

# Routes logged-in users to their role-specific menu
def role_menu(user_data):
    role = user_data.get("role")
    if role == 'user':
        sender_menu(user_data)
    elif role == 'moderator':
        moderator_menu(user_data)
    elif role == 'admin':
        admin_menu(user_data)
    else:
        input("Unknown role. Press Enter to continue...")

# Allows senders to request tokens, send messages, view and flag messages
def sender_menu(user_data):
    username = user_data['username']
    
    while True:
        print_header()
        print(f"Logged in as: {username} (Sender)")
        print(SENDER_MENU)
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            encrypted_token, message = generate_token(username)
            print(message)
            if encrypted_token:
                print(f"Your encrypted token: {encrypted_token}")
            input("Press Enter to continue...")
        elif choice == '2':
            print_header()
            print("SEND ANONYMOUS MESSAGE\n")
            
            # Get current round's token
            token, msg = get_current_token(username)
            if not token:
                print(f"Error: {msg}")
                input("Press Enter to continue...")
                continue
            
            # Get recipient username
            recipient = input("Enter recipient username: ").strip()
            
            # Get message content
            message = input("Enter your message: ").strip()
            
                
            # Send the message
            success, msg = send_message(username, recipient, message, token)
            print(msg)
            input("Press Enter to continue...")
        elif choice == '3':
            print_header()
            print("YOUR MESSAGES\n")
            
            # Get messages
            success, messages, msg = get_messages(username)
            if not success:
                print(f"Error: {msg}")
                input("Press Enter to continue...")
                continue
                
            if not messages:
                print("No messages found.")
            else:
                for i, msg in enumerate(messages, 1):
                    timestamp = datetime.fromtimestamp(msg["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"\nMessage {i}:")
                    print(f"Time: {timestamp}")
                    print(f"Content: {msg['content']}")
                    print(f"Token Hash: {msg['token_hash']}")
                    print("-" * 40)
                    
                # Add flagging option
                print("\nTo flag a message as inappropriate, enter its number (or press Enter to continue):")
                flag_choice = input().strip()
                
                if flag_choice.isdigit() and 1 <= int(flag_choice) <= len(messages):
                    msg_to_flag = messages[int(flag_choice) - 1]
                    success, msg = flag_message(msg_to_flag, username)
                    print(msg)
                    
            input("\nPress Enter to continue...")
        elif choice == '4':
            print("Logging out...")
            break
        else:
            input("Invalid choice. Press Enter to continue...")

# Moderators can view flagged messages and freeze tokens to prevent further misuse.
def moderator_menu(user_data):
    username = user_data['username']
    
    while True:
        print_header()
        print(f"Logged in as: {username} (Moderator)")
        print(MODERATOR_MENU)
        
        choice = input("Enter your choice (1-2): ")
        
        if choice == '1':
            print_header()
            print("FLAGGED MESSAGES\n")
            
            # Get flagged messages
            success, messages, msg = get_flagged_messages(username)
            if not success:
                print(f"Error: {msg}")
                input("Press Enter to continue...")
                continue
                
            if not messages:
                print("No flagged messages found.")
            else:
                for i, msg in enumerate(messages, 1):
                    flag_time = datetime.fromtimestamp(msg["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
                    
                    print(f"\nFlagged Message {i}:")
                    print(f"Content: {msg['content']}")
                    print(f"Flagged at: {flag_time}")
                    print(f"Token Hash: {msg['token_hash']}")
                    print("-" * 40)
                    
                # token freezing option
                print("\nTo freeze a token (prevent future messages), enter its message number (or press Enter to continue):")
                freeze_choice = input().strip()
                
                if freeze_choice.isdigit() and 1 <= int(freeze_choice) <= len(messages):
                    msg_to_freeze = messages[int(freeze_choice) - 1]
                    success, msg = freeze_token(msg_to_freeze["token_hash"], username)
                    print(msg)
                    
            input("\nPress Enter to continue...")
        elif choice == '2':
            print("Logging out...")
            break
        else:
            input("Invalid choice. Press Enter to continue...")

# Admins can assign roles to users and view all current users and their roles.
def admin_menu(user_data):
    username = user_data['username']

    while True:
        print_header()
        print(f"Logged in as: {username} (Admin)")
        print(ADMIN_MENU)

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            target = input("Enter the username to assign a role to: ").strip()
            role = input("Enter the role (user / moderator): ").strip().lower()
            success, msg = assign_role(user_data, target, role)
            print(msg)
            input("Press Enter to continue...")
        
        elif choice == '2':
            users = load_users()
            print("\nCurrent Users and Roles:")
            for u, info in users.items():
                print(f"{u}: {info['role']}")
            input("Press Enter to continue...")
        
        elif choice == '3':
            print("Logging out...")
            break
        
        else:
            input("Invalid option. Press Enter to continue...")

def main():
    ensure_data_files_exist()
    login_menu()

if __name__ == "__main__":
    main()
