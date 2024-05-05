#!/usr/bin/env python3

import time
import os
from cryptography.fernet import Fernet
import sys
import keyboard
import subprocess
import platform
import sqlite3
import pyfiglet
import bcrypt
import getpass
import sys
import shutil


def get_password(prompt):
    print(prompt, end='', flush=True)
    password = ''
    while True:
        char = sys.stdin.read(1)
        if char == '\r' or char == '\n':
            print()
            return password
        elif char == '\x03':  # Ctrl+C
            raise KeyboardInterrupt
        elif char == '\x7f':  # Backspace/Delete
            if password:
                password = password[:-1]
                sys.stdout.write('\b \b')
        else:
            password += char
            sys.stdout.write('*')
            sys.stdout.flush()

def getpass_asterisk(prompt):
    if platform.system() == 'Windows':
        import msvcrt
        print(prompt, end='', flush=True)
        password = ''
        while True:
            char = msvcrt.getch().decode('utf-8')
            if char == '\r' or char == '\n':
                print()
                break
            elif char == '\b' and password:
                password = password[:-1]
                print('\b \b', end='', flush=True)
            else:
                password += char
                print('*', end='', flush=True)
    else:
        import termios
        import tty
        print(prompt, end='', flush=True)
        password = ''
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                char = sys.stdin.read(1)
                if char == '\r' or char == '\n':
                    print()
                    break
                elif char == '\b' and password:
                    password = password[:-1]
                    print('\b \b', end='', flush=True)
                else:
                    password += char
                    print('*', end='', flush=True)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return password


def show_loading_animation(loadTxt, duration):
    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        animation = "|/-\\"
        for char in animation:
            print(f"\r{loadTxt } {char}", end="")
            sys.stdout.flush()
            time.sleep(0.1)

    # Clear the line after the loading animation
    print("\r" + " " * 20 + "\r")

print("""

██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗   ██╗███╗   ██╗
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██║  ╚██╗ ██╔╝████╗  ██║
██║   ██║███████║██║   ██║██║     ██║   ██║   ╚████╔╝ ██╔██╗ ██║
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║    ╚██╔╝  ██║╚██╗██║
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██║   ██║ ╚████║
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝   ╚═╝  ╚═══╝   V1.13
                Fernet Cryptographic Vault
                ©Frissco Creative Labs 2024
""")

show_loading_animation("Starting Vaultlyn...",2)

current_directory = os.path.dirname(__file__)
config_dir = 'CONFIG'
config_dir_path = os.path.join(current_directory, config_dir)
vault_dir = 'VAULT'
vault_dir_path = os.path.join(current_directory, vault_dir)
if not os.path.exists(config_dir_path):
    os.makedirs(config_dir_path)
    if os.path.exists(vault_dir_path):
        shutil.rmtree(vault_dir_path)
    if not os.path.exists(vault_dir_path):
        os.makedirs(vault_dir_path)

    conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
            (name TEXT, email TEXT, password TEXT, vault_path TEXT)''')
    conn.commit()

    print("User config not found.. Create a new User.")
    name = input("Enter your name: ")
    show_loading_animation("Loading..",1)
    email = input("Enter your email: ")
    show_loading_animation("Loading..", 1)
    password = getpass_asterisk("Enter your password: ")
    show_loading_animation("Loading..", 2)
    vault_path_inp = input("Enter a path to use it as Vault: ")
    show_loading_animation("Adding desired path...", 2)

    if '\\' in vault_path_inp:
        vault_path_inp_crct = vault_path_inp.replace('\\', '/')
    else:
        vault_path_inp_crct = vault_path_inp
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (name, email, password, vault_path) VALUES (?, ?, ?, ?)",
              # Store the hashed password as a string
              (name, email, hashed_password.decode(), vault_path_inp_crct))
    conn.commit()
    print("User config saved successfully!")
    conn.close()
    print("Before getting started, We wanted to inform some rules about this program...")
    input("Press ENTER to continue...")
    print("1. Don't forget your password. If you do so, your files will be erased completely to reset the program.")
    input("Press ENTER to continue...")
    print("2. Prevent Encrypting files multiple times. If you have encrypted a folder and added a new file to the folder, Kindly decrypt the existing files and encrypt it once again.")
    print("This will prevent data loss...")
    input("Press ENTER to continue...")
    print("3. Don't loose the 'decryptkey.key' file. If you did, you cannot decrypt your files.")
    input("Press ENTER to continue...")
    print("With that cleared, Welcome to Vaultlyn!")
    input("Press ENTER to continue...")

conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
c = conn.cursor()
verify_pass = getpass_asterisk("Enter your password: ")

c.execute("SELECT email FROM users")
result = c.fetchone()
if result:
    email = result[0]
    c.execute("SELECT password FROM users WHERE email = ?", (email,))
    stored_hashed_password = c.fetchone()

    if stored_hashed_password and bcrypt.checkpw(verify_pass.encode(), stored_hashed_password[0].encode()):
        print("Authentication Successful!")
        conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
        c = conn.cursor()
        c.execute("SELECT name FROM users")
        result = c.fetchone()

        if result:
            name = result[0]
            welcome_message = f"Welcome, {name}!"
            print(welcome_message)
        else:
            print("User config not found..")
        
        while True:
            print("""
::::::::::::::::::::: Select an Option :::::::::::::::::::::
+----------------------------------------------------------+
|                     1. Encrypt Data.                     |
|                     2. Decrypt Data.                     |
|                     3. Open Vault.                       |
|                     4. Change Vault.                     |
|                     5. Locate Decryption Key.            |
|                     6. Close Vaultlyn.                   |
|                     7. Change password.                  |
|                     8. What is Vaultlyn?                 |
|                     9. About Vaultlyn.                   |
+----------------------------------------------------------+
    """)
            mainMenu = input("Choose an option: ")

            if mainMenu == '1':
                def encrypt_folder(vault_folder):
                    files = []
                    for file in os.listdir(vault_folder):
                        if file == "decryptkey.key":
                            continue
                        if os.path.isfile(os.path.join(vault_folder, file)):
                            files.append(file)
                    print(files)

                    initialInput = input(
                        'Do you want to encrypt all the files in this directory? (Y/N): ')
                    if initialInput == 'y' or initialInput == 'Y':
                        key = Fernet.generate_key()

                        with open("decryptkey.key", "wb") as thekey:
                            thekey.write(key)

                        for file in files:
                            file_path = os.path.join(vault_folder, file)
                            with open(file_path, "rb") as thefile:
                                contents = thefile.read()
                            content_encrypted = Fernet(key).encrypt(contents)
                            with open(file_path, "wb") as thefile:
                                thefile.write(content_encrypted)

                        show_loading_animation("Encrypting data...",2)
                        print("The folder is now encrypted...")
                conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
                c = conn.cursor()
                c.execute('SELECT vault_path FROM users')
                result = c.fetchone()

                if result:
                    vault_path = result[0]
                    vault_folder = vault_path
                encrypt_folder(vault_folder)
            elif mainMenu == '2':
                decrypt_confirmation = input("Do you want to decrypt your files? (Y/N): ")
                if decrypt_confirmation == 'y' or decrypt_confirmation == 'Y':
                    def decrypt_folder(decrypt_dir):
                        files=[]
                        for file in os.listdir(decrypt_dir):
                            if file == "decryptkey.key":
                                continue
                            if os.path.isfile(os.path.join(decrypt_dir, file)):
                                files.append(file)
                        print(files)

                        with open(os.path.join("decryptkey.key"), "rb") as key_file:
                            secretkey = key_file.read()
                        for file in files:
                            file_path = os.path.join(decrypt_dir, file)
                            with open(file_path, "rb") as thefile:
                                contents = thefile.read()
                            contents_decrypted = Fernet(secretkey).decrypt(contents)
                            with open(file_path, "wb") as thefile:
                                thefile.write(contents_decrypted)
                        show_loading_animation("Decrypting data...", 2)
                        print("Decryption Successful...")
                        os.remove("decryptkey.key")
                    conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
                    c = conn.cursor()
                    c.execute('SELECT vault_path FROM users')
                    result = c.fetchone()

                    if os.path.exists("decryptkey.key"):
                        if result:
                            vault_path = result[0]
                            decrypt_dir = vault_path
                        decrypt_folder(decrypt_dir)
                    else:
                        print("No Files are encrypted...")
                        input("Pres ENTER to continue...")
                else:
                    pass
            elif mainMenu == '3':
                conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
                c = conn.cursor()
                c.execute('SELECT vault_path FROM users')
                result = c.fetchone()

                if result:
                    vault_path = result[0]
                    if os.path.exists(vault_path):
                        if platform.system() == 'Windows':
                            os.startfile(vault_path)
                        elif platform.system() == 'Darwin':
                            os.system('open' + vault_path)
                        else:
                            os.system('xdg-open' + vault_path)
                    else:
                        print("Vault path does not exist.")
                else:
                    print("No user found in the database.")
                conn.close()
            elif mainMenu == '4':
                conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
                c = conn.cursor()

                if os.path.exists("decryptkey.key"):
                    print("You already have a folder encrypted. Decrypt that folder to change to a new Vault.")
                    input("Press ENTER to continue...")
                else:
                    new_vault_path = input("Enter the new path to your vault: ")
                    c.execute("UPDATE users SET vault_path = ?", (new_vault_path,))
                    print("New vault has been successfully added!")
                    show_loading_animation("Please Wait", 2)
                conn.commit()
                conn.close()
            elif mainMenu == '5':
                os.startfile(current_directory)
            elif mainMenu == '6':
                show_loading_animation("Vaultlyn closing...", 1)
                print("Bye! See you later!")
                exit()

            elif mainMenu == '7':
                def change_password():
                    conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
                    c = conn.cursor()
                    current_password = getpass_asterisk("Enter your current password: ")
                    new_password = getpass_asterisk("Enter your new password: ")
                    show_loading_animation("Updating Password configuration...", 3)

                    c.execute("SELECT password FROM users WHERE email = ?", (email,))
                    stored_hashed_password = c.fetchone()

                    if stored_hashed_password and bcrypt.checkpw(current_password.encode(), stored_hashed_password[0].encode()):
                        hashed_new_password = bcrypt.hashpw(
                            new_password.encode(), bcrypt.gensalt())
                        c.execute("UPDATE users SET password = ? WHERE email = ?",
                                (hashed_new_password.decode(), email))
                        conn.commit()
                        conn.close()
                        print("Password changed successfully!")
                    else:
                        conn.close()
                        print("Incorrect password. Password change failed.")
                change_password()
            elif mainMenu == '8':
                print("""
                      Vaultlyn is a File encryption vault which is used for locking files on a computer locally by encrypting it.
                      This program uses 'Fernet Encryption' to lock the files. When a file is locked using
                      Vaultlyn, it can be only unlocked with the dedicated decryption key which was generated
                      while locking the files. THIS TYPE OF ENCRYPTION CANNOT BE MANIPULATED WITHOUT THE DECRYPTION KEY.
                      Vaultlyn is an open source program, made by Sidharth Prabhu from Frissco Creative Labs.
                      ©Frissco Creative Labs 2024
""")
                input("Press ENTER to continue...")
            elif mainMenu == '9':
                print("""
                     __      __         _ _   _             
                     \ \    / /        | | | | |            
                      \ \  / /_ _ _   _| | |_| |_   _ _ __  
                       \ \/ / _` | | | | | __| | | | | '_ \ 
                        \  / (_| | |_| | | |_| | |_| | | | |
                         \/ \__,_|\__,_|_|\__|_|\__, |_| |_|
                                                 __/ |      
                                                |___/       
                                 Version 1.13
                         ©Frissco Creative Labs 2024
                         Developed by Sidharth Prabhu
""")
                input("Press ENTER to continue...")
            else:
                print("Please select a valid option...")


    else:
        print("Unauthorised Access.")
