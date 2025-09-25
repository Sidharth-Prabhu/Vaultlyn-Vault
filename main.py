import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import shutil
import getpass
import bcrypt
import pyfiglet
import sqlite3
import platform
import subprocess
import keyboard
import sys
from cryptography.fernet import Fernet, InvalidToken
import os
import time
#!/usr/bin/env python3


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
            print(f"\r{loadTxt} {char}", end="")
            sys.stdout.flush()
            time.sleep(0.1)

    # Clear the line after the loading animation
    print("\r" + " " * 20 + "\r")


print("""

██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗   ██╗███╗   ██║
██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██║  ╚██╗ ██╔╝████╗  ██║
██║   ██║███████║██║   ██║██║     ██║   ██║   ╚████╔╝ ██╔██╗ ██║
╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██║    ╚██╔╝  ██║╚██╗██║
 ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██║   ██║ ╚████║
  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝   ╚═╝  ╚═══╝   V1.15
                Fernet Cryptographic Vault
                ©Frissco Creative Labs 2025
""")

show_loading_animation("Starting Vaultlyn...", 2)

current_directory = os.path.dirname(__file__)
config_dir = 'CONFIG'
config_dir_path = os.path.join(current_directory, config_dir)
if not os.path.exists(config_dir_path):
    os.makedirs(config_dir_path)

    conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
            (name TEXT, email TEXT, password TEXT, self_destruct_enabled INTEGER DEFAULT 0, failed_attempts INTEGER DEFAULT 0)''')

    c.execute('''CREATE TABLE IF NOT EXISTS vaults
            (id INTEGER PRIMARY KEY, name TEXT, path TEXT, salt BLOB, enc_key BLOB, recovery_salt BLOB, recovery_enc_key BLOB)''')
    conn.commit()

    print("User config not found.. Create a new User.")
    name = input("Enter your name: ")
    show_loading_animation("Loading..", 1)
    email = input("Enter your email: ")
    show_loading_animation("Loading..", 1)
    password = getpass_asterisk("Enter your password: ")
    show_loading_animation("Loading..", 2)

    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                  (name, email, hashed_password.decode()))
    elif platform.system() == 'Linux':
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                  (name, email, hashed_password.decode()))
    conn.commit()
    print("User config saved successfully!")
    conn.close()
    print("Before getting started, We wanted to inform some rules about this program...")
    input("Press ENTER to continue...")
    print("1. Don't forget your passwords. If you do so, use the recovery option, but keep recovery passphrases safe.")
    input("Press ENTER to continue...")
    print("2. Vaultlyn now prevents multiple encryptions by skipping already encrypted files.")
    input("Press ENTER to continue...")
    print("3. Each vault has its own passphrase for security.")
    input("Press ENTER to continue...")
    print("With that cleared, Welcome to Vaultlyn!")
    input("Press ENTER to continue...")

conn = sqlite3.connect(f'{config_dir_path}/user_info.db')
c = conn.cursor()
c.execute("SELECT failed_attempts, self_destruct_enabled FROM users")
result = c.fetchone()
failed_attempts = result[0] if result else 0
self_destruct_enabled = result[1] if result else 0

c.execute("SELECT email FROM users")
result = c.fetchone()
if result:
    email = result[0]
    c.execute("SELECT password FROM users WHERE email = ?", (email,))
    stored_hashed_password = c.fetchone()
    if stored_hashed_password:
        stored_hashed_password = stored_hashed_password[0]
    else:
        stored_hashed_password = None

    login_success = False
    while not login_success:
        verify_pass = getpass_asterisk("Enter your password: ")
        if stored_hashed_password and bcrypt.checkpw(verify_pass.encode(), stored_hashed_password.encode()):
            login_success = True
            failed_attempts = 0
            c.execute("UPDATE users SET failed_attempts = 0")
            conn.commit()
            print("Authentication Successful!")
            c.execute("SELECT name FROM users")
            result = c.fetchone()
            if result:
                name = result[0]
                welcome_message = f"Welcome, {name}!"
                print(welcome_message)
            else:
                print("User config not found..")
        else:
            failed_attempts += 1
            c.execute("UPDATE users SET failed_attempts = ?",
                      (failed_attempts,))
            conn.commit()
            if self_destruct_enabled and failed_attempts >= 5:
                c.execute("SELECT path FROM vaults")
                paths = c.fetchall()
                for row in paths:
                    path = row[0]
                    if os.path.exists(path):
                        shutil.rmtree(path)
                c.execute("DELETE FROM vaults")
                conn.commit()
                print("Self-destruction activated. All vault data deleted.")
                conn.close()
                exit()
            else:
                print("Unauthorised Access. Try again.")

    # Check if any vaults exist
    c.execute("SELECT COUNT(*) FROM vaults")
    vault_count = c.fetchone()[0]
    if vault_count == 0:
        print("No vaults found. Let's create your first vault.")

        def add_vault():
            vault_name = input("Enter vault name: ")
            vault_path_inp = input("Enter vault path: ")
            if '\\' in vault_path_inp:
                vault_path_inp_crct = vault_path_inp.replace('\\', '/')
            else:
                vault_path_inp_crct = vault_path_inp
            if platform.system() == 'Linux':
                vault_path_inp_crct = vault_path_inp_crct.replace(' ', '\\ ')
            vault_passphrase = getpass_asterisk(
                "Enter passphrase for this vault: ")
            recovery_passphrase = getpass_asterisk(
                "Enter recovery passphrase for this vault: ")

            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000,
            )
            protect_key = base64.urlsafe_b64encode(
                kdf.derive(vault_passphrase.encode()))

            fernet_key = Fernet.generate_key()
            f_protect = Fernet(protect_key)
            enc_key = f_protect.encrypt(fernet_key)

            recovery_salt = os.urandom(16)
            recovery_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=recovery_salt,
                iterations=390000,
            )
            recovery_protect_key = base64.urlsafe_b64encode(
                recovery_kdf.derive(recovery_passphrase.encode()))
            f_recovery_protect = Fernet(recovery_protect_key)
            recovery_enc_key = f_recovery_protect.encrypt(fernet_key)

            c.execute("INSERT INTO vaults (name, path, salt, enc_key, recovery_salt, recovery_enc_key) VALUES (?, ?, ?, ?, ?, ?)",
                      (vault_name, vault_path_inp_crct, salt, enc_key, recovery_salt, recovery_enc_key))
            conn.commit()
            print("Vault added successfully!")
        add_vault()

    while True:
        print("""
::::::::::::::::::::: Select an Option :::::::::::::::::::::
+----------------------------------------------------------+
|                     1. Encrypt Data.                     |
|                     2. Decrypt Data.                     |
|                     3. Open Vault.                       |
|                     4. Add New Vault.                    |
|                     5. Backup Decryption Key.            |
|                     6. Close Vaultlyn.                   |
|                     7. Change password.                  |
|                     8. What is Vaultlyn?                 |
|                     9. About Vaultlyn.                   |
|                     10. Toggle Self-Destruction Mode.    |
|                     11. Recover Vault Passphrase.        |
|                     12. Edit Vault Path.                 |
|                     13. List Vaults.                     |
|                     14. Delete Vault.                    |
+----------------------------------------------------------+
""")
        mainMenu = input("Choose an option: ")

        def list_vaults():
            c.execute("SELECT id, name, path FROM vaults")
            vaults = c.fetchall()
            if not vaults:
                print("No vaults found.")
                return None
            print("Available Vaults:")
            for v in vaults:
                print(f"ID: {v[0]}, Name: {v[1]}, Path: {v[2]}")
            return vaults

        def select_vault_id():
            list_vaults()
            vault_id = input("Enter vault ID: ")
            try:
                vault_id = int(vault_id)
            except ValueError:
                print("Invalid ID.")
                return None
            return vault_id

        def get_fernet_key(vault_id, passphrase, is_recovery=False):
            if is_recovery:
                c.execute(
                    "SELECT recovery_salt, recovery_enc_key FROM vaults WHERE id = ?", (vault_id,))
            else:
                c.execute(
                    "SELECT salt, enc_key FROM vaults WHERE id = ?", (vault_id,))
            result = c.fetchone()
            if not result:
                return None
            salt, enc_key = result
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=390000,
            )
            protect_key = base64.urlsafe_b64encode(
                kdf.derive(passphrase.encode()))
            f_protect = Fernet(protect_key)
            try:
                fernet_key = f_protect.decrypt(enc_key)
                return fernet_key
            except InvalidToken:
                return None

        if mainMenu == '1':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            vault_passphrase = getpass_asterisk("Enter vault passphrase: ")
            fernet_key = get_fernet_key(vault_id, vault_passphrase)
            if fernet_key is None:
                print("Wrong passphrase.")
                continue
            c.execute("SELECT path FROM vaults WHERE id = ?", (vault_id,))
            vault_folder = c.fetchone()[0]

            def encrypt_folder(vault_folder, fernet_key):
                f = Fernet(fernet_key)
                files = []
                for file in os.listdir(vault_folder):
                    file_path = os.path.join(vault_folder, file)
                    if os.path.isfile(file_path):
                        files.append(file_path)
                print(files)

                initialInput = input(
                    'Do you want to encrypt the files in this vault? (Y/N): ')
                if initialInput.lower() == 'y':
                    for file_path in files:
                        with open(file_path, "rb") as thefile:
                            contents = thefile.read()
                        try:
                            f.decrypt(contents)
                            print(
                                f"{file_path} is already encrypted, skipping...")
                            continue
                        except InvalidToken:
                            pass
                        content_encrypted = f.encrypt(contents)
                        with open(file_path, "wb") as thefile:
                            thefile.write(content_encrypted)
                    show_loading_animation("Encrypting data...", 2)
                    print("The vault is now encrypted...")
            encrypt_folder(vault_folder, fernet_key)
        elif mainMenu == '2':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            vault_passphrase = getpass_asterisk("Enter vault passphrase: ")
            fernet_key = get_fernet_key(vault_id, vault_passphrase)
            if fernet_key is None:
                print("Wrong passphrase.")
                continue
            c.execute("SELECT path FROM vaults WHERE id = ?", (vault_id,))
            decrypt_dir = c.fetchone()[0]

            decrypt_confirmation = input(
                "Do you want to decrypt your files? (Y/N): ")
            if decrypt_confirmation.lower() == 'y':
                def decrypt_folder(decrypt_dir, fernet_key):
                    f = Fernet(fernet_key)
                    files = []
                    for file in os.listdir(decrypt_dir):
                        file_path = os.path.join(decrypt_dir, file)
                        if os.path.isfile(file_path):
                            files.append(file_path)
                    print(files)

                    for file_path in files:
                        with open(file_path, "rb") as thefile:
                            contents = thefile.read()
                        try:
                            contents_decrypted = f.decrypt(contents)
                        except InvalidToken:
                            print(
                                f"{file_path} not encrypted or wrong key, skipping...")
                            continue
                        with open(file_path, "wb") as thefile:
                            thefile.write(contents_decrypted)
                    show_loading_animation("Decrypting data...", 2)
                    print("Decryption Successful...")
                decrypt_folder(decrypt_dir, fernet_key)
            else:
                pass
        elif mainMenu == '3':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            c.execute('SELECT path FROM vaults WHERE id = ?', (vault_id,))
            result = c.fetchone()

            if result:
                vault_path = result[0]
                if os.path.exists(vault_path):
                    if platform.system() == 'Windows':
                        os.startfile(vault_path)
                    elif platform.system() == 'Darwin':
                        os.system('open ' + vault_path)
                    else:
                        subprocess.Popen(['xdg-open', vault_path])
                else:
                    print("Vault path does not exist.")
            else:
                print("Vault not found.")
        elif mainMenu == '4':
            def add_vault():
                vault_name = input("Enter vault name: ")
                vault_path_inp = input("Enter vault path: ")
                if '\\' in vault_path_inp:
                    vault_path_inp_crct = vault_path_inp.replace('\\', '/')
                else:
                    vault_path_inp_crct = vault_path_inp
                if platform.system() == 'Linux':
                    vault_path_inp_crct = vault_path_inp_crct.replace(
                        ' ', '\\ ')
                vault_passphrase = getpass_asterisk(
                    "Enter passphrase for this vault: ")
                recovery_passphrase = getpass_asterisk(
                    "Enter recovery passphrase for this vault: ")

                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=390000,
                )
                protect_key = base64.urlsafe_b64encode(
                    kdf.derive(vault_passphrase.encode()))

                fernet_key = Fernet.generate_key()
                f_protect = Fernet(protect_key)
                enc_key = f_protect.encrypt(fernet_key)

                recovery_salt = os.urandom(16)
                recovery_kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=recovery_salt,
                    iterations=390000,
                )
                recovery_protect_key = base64.urlsafe_b64encode(
                    recovery_kdf.derive(recovery_passphrase.encode()))
                f_recovery_protect = Fernet(recovery_protect_key)
                recovery_enc_key = f_recovery_protect.encrypt(fernet_key)

                c.execute("INSERT INTO vaults (name, path, salt, enc_key, recovery_salt, recovery_enc_key) VALUES (?, ?, ?, ?, ?, ?)",
                          (vault_name, vault_path_inp_crct, salt, enc_key, recovery_salt, recovery_enc_key))
                conn.commit()
                print("Vault added successfully!")
            add_vault()
        elif mainMenu == '5':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            vault_passphrase = getpass_asterisk(
                "Enter vault passphrase to backup key: ")
            fernet_key = get_fernet_key(vault_id, vault_passphrase)
            if fernet_key is None:
                print("Wrong passphrase.")
                continue
            print("Backup Decryption Key (save this securely):")
            print(fernet_key.decode())
            input("Press ENTER to continue...")
        elif mainMenu == '6':
            show_loading_animation("Vaultlyn closing...", 1)
            print("Bye! See you later!")
            conn.close()
            exit()
        elif mainMenu == '7':
            def change_password():
                current_password = getpass_asterisk(
                    "Enter your current password: ")
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
                    print("Password changed successfully!")
                else:
                    print("Incorrect password. Password change failed.")
            change_password()
        elif mainMenu == '8':
            print("""
                  Vaultlyn is a File encryption vault which is used for locking files on a computer locally by encrypting it.
                  This program uses 'Fernet Encryption' to lock the files. When a file is locked using
                  Vaultlyn, it can be only unlocked with the dedicated decryption key which was generated
                  while locking the files. THIS TYPE OF ENCRYPTION CANNOT BE MANIPULATED WITHOUT THE DECRYPTION KEY.
                  Vaultlyn supports multiple vaults with individual passphrases and recovery options.
                  Vaultlyn is an open source program, made by Sidharth Prabhu from Frissco Creative Labs.
                  ©Frissco Creative Labs 2025
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
                             Version 1.15
                     ©Frissco Creative Labs 2025
                     Developed by Sidharth Prabhu
""")
            input("Press ENTER to continue...")
        elif mainMenu == '10':
            c.execute("SELECT self_destruct_enabled FROM users")
            current = c.fetchone()[0]
            new = 1 if current == 0 else 0
            c.execute("UPDATE users SET self_destruct_enabled = ?", (new,))
            conn.commit()
            print(f"Self-destruction mode {'enabled' if new else 'disabled'}.")
        elif mainMenu == '11':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            recovery_passphrase = getpass_asterisk(
                "Enter recovery passphrase: ")
            fernet_key = get_fernet_key(
                vault_id, recovery_passphrase, is_recovery=True)
            if fernet_key is None:
                print("Wrong recovery passphrase.")
                continue
            print("Recovery successful. Set new passphrase.")
            new_passphrase = getpass_asterisk("Enter new passphrase: ")
            new_recovery_passphrase = getpass_asterisk(
                "Enter new recovery passphrase: ")
            new_salt = os.urandom(16)
            new_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=new_salt,
                iterations=390000,
            )
            new_protect_key = base64.urlsafe_b64encode(
                new_kdf.derive(new_passphrase.encode()))
            f_new_protect = Fernet(new_protect_key)
            new_enc_key = f_new_protect.encrypt(fernet_key)

            new_recovery_salt = os.urandom(16)
            new_recovery_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=new_recovery_salt,
                iterations=390000,
            )
            new_recovery_protect_key = base64.urlsafe_b64encode(
                new_recovery_kdf.derive(new_recovery_passphrase.encode()))
            f_new_recovery_protect = Fernet(new_recovery_protect_key)
            new_recovery_enc_key = f_new_recovery_protect.encrypt(fernet_key)

            c.execute("UPDATE vaults SET salt = ?, enc_key = ?, recovery_salt = ?, recovery_enc_key = ? WHERE id = ?",
                      (new_salt, new_enc_key, new_recovery_salt, new_recovery_enc_key, vault_id))
            conn.commit()
            print("Passphrase recovered and updated.")
        elif mainMenu == '12':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            new_vault_path = input("Enter the new path for the vault: ")
            if '\\' in new_vault_path:
                new_vault_path = new_vault_path.replace('\\', '/')
            if platform.system() == 'Linux':
                new_vault_path = new_vault_path.replace(' ', '\\ ')
            c.execute("UPDATE vaults SET path = ? WHERE id = ?",
                      (new_vault_path, vault_id))
            conn.commit()
            print("Vault path updated successfully!")
        elif mainMenu == '13':
            list_vaults()
            input("Press ENTER to continue...")
        elif mainMenu == '14':
            vault_id = select_vault_id()
            if vault_id is None:
                continue
            confirm = input(
                "Are you sure you want to delete this vault and its data? (Y/N): ")
            if confirm.lower() == 'y':
                c.execute("SELECT path FROM vaults WHERE id = ?", (vault_id,))
                result = c.fetchone()
                if result:
                    path = result[0]
                    if os.path.exists(path):
                        shutil.rmtree(path)
                c.execute("DELETE FROM vaults WHERE id = ?", (vault_id,))
                conn.commit()
                print("Vault deleted successfully!")
            else:
                print("Deletion cancelled.")
        else:
            print("Please select a valid option...")
else:
    print("User not found.")
conn.close()
