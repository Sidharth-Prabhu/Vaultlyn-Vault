import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import shutil
import bcrypt
import sqlite3
import platform
import subprocess
import sys
from cryptography.fernet import Fernet, InvalidToken
import os
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QDialog, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QListWidget, QTreeWidget, QHBoxLayout,
    QTreeWidgetItem, QFileDialog, QInputDialog, QListWidgetItem, QWidget,
    QMenu, QAction
)
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QPixmap

CONFIG_DIR = 'CONFIG'
DB_PATH = os.path.join(CONFIG_DIR, 'user_info.db')
# Adjust this path to your logo file
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo.png')


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setWindowIcon(QIcon("icon.png"))

        # Add logo
        logo_label = QLabel(self)
        pixmap = QPixmap(LOGO_PATH)
        if not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(
                300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
        else:
            logo_label.setText("Logo not found")
        logo_label.setAlignment(Qt.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        button = QPushButton("Login")
        button.clicked.connect(self.login)
        layout = QVBoxLayout()
        layout.addWidget(logo_label)
        layout.addWidget(QLabel("Enter password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(button)
        self.setLayout(layout)

    def login(self):
        password = self.password_input.text()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT password, failed_attempts, self_destruct_enabled FROM users")
        result = c.fetchone()
        if result:
            stored_hash, failed, self_destruct = result
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                c.execute("UPDATE users SET failed_attempts = 0")
                conn.commit()
                conn.close()
                self.accept()
                return
            else:
                failed += 1
                c.execute("UPDATE users SET failed_attempts = ?", (failed,))
                conn.commit()
                if self_destruct and failed >= 5:
                    c.execute("SELECT path FROM vaults")
                    paths = c.fetchall()
                    for p in paths:
                        if os.path.exists(p[0]):
                            shutil.rmtree(p[0])
                    c.execute("DELETE FROM vaults")
                    conn.commit()
                    QMessageBox.critical(
                        self, "Error", "Self-destruction activated. All vault data deleted.")
                    conn.close()
                    sys.exit()
                else:
                    QMessageBox.warning(self, "Error", "Wrong password.")
        else:
            conn.close()
            QMessageBox.warning(self, "Error", "No user found.")


class CreateUserDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Create User")
        self.setWindowIcon(QIcon("icon.png"))
        self.name_input = QLineEdit()
        self.email_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        button = QPushButton("Create")
        button.clicked.connect(self.create)
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Name:"))
        layout.addWidget(self.name_input)
        layout.addWidget(QLabel("Email:"))
        layout.addWidget(self.email_input)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(button)
        self.setLayout(layout)

    def create(self):
        name = self.name_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        if not name or not email or not password:
            QMessageBox.warning(self, "Error", "Fill all fields.")
            return
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed))
        conn.commit()
        conn.close()
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vaultlyn V1.15")
        self.setWindowIcon(QIcon("icon.png"))
        self.setAcceptDrops(True)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT name, self_destruct_enabled FROM users")
        self.user_name, self.self_destruct = c.fetchone()
        conn.close()

        # Create menu bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        edit_menu = menubar.addMenu("Edit")
        help_menu = menubar.addMenu("Help")

        # File menu actions
        add_vault_action = QAction("Add New Vault", self)
        add_vault_action.triggered.connect(self.add_vault)
        file_menu.addAction(add_vault_action)
        close_action = QAction("Close Vaultlyn", self)
        close_action.triggered.connect(self.close)
        file_menu.addAction(close_action)

        # Edit menu actions
        encrypt_action = QAction("Encrypt Data", self)
        encrypt_action.triggered.connect(self.encrypt)
        edit_menu.addAction(encrypt_action)
        decrypt_action = QAction("Decrypt Data", self)
        decrypt_action.triggered.connect(self.decrypt)
        edit_menu.addAction(decrypt_action)
        backup_key_action = QAction("Backup Decryption Key", self)
        backup_key_action.triggered.connect(self.backup_key)
        edit_menu.addAction(backup_key_action)
        change_password_action = QAction("Change Password", self)
        change_password_action.triggered.connect(self.change_password)
        edit_menu.addAction(change_password_action)
        toggle_self_destruct_action = QAction("Toggle Self-Destruction", self)
        toggle_self_destruct_action.triggered.connect(
            self.toggle_self_destruct)
        edit_menu.addAction(toggle_self_destruct_action)
        recover_passphrase_action = QAction("Recover Passphrase", self)
        recover_passphrase_action.triggered.connect(self.recover_passphrase)
        edit_menu.addAction(recover_passphrase_action)
        edit_path_action = QAction("Edit Vault Path", self)
        edit_path_action.triggered.connect(self.edit_path)
        edit_menu.addAction(edit_path_action)
        delete_vault_action = QAction("Delete Vault", self)
        delete_vault_action.triggered.connect(self.delete_vault)
        edit_menu.addAction(delete_vault_action)

        # Help menu actions
        what_is_action = QAction("What is Vaultlyn?", self)
        what_is_action.triggered.connect(self.what_is)
        help_menu.addAction(what_is_action)
        about_action = QAction("About Vaultlyn", self)
        about_action.triggered.connect(self.about)
        help_menu.addAction(about_action)

        # Vault list with context menu
        self.vault_list = QListWidget()
        self.vault_list.itemClicked.connect(self.show_files)
        self.vault_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vault_list.customContextMenuRequested.connect(
            self.show_context_menu)

        # Search bar with timer
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search files/folders...")
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(300)  # 300ms delay
        self.search_timer.timeout.connect(self.perform_search)
        self.search_input.textChanged.connect(self.schedule_search)

        # File tree with drag-and-drop and context menu support
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Files"])
        self.file_tree.itemDoubleClicked.connect(self.open_file)
        self.file_tree.setAcceptDrops(True)
        self.file_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(
            self.show_file_context_menu)

        # Layout
        layout = QHBoxLayout()
        left = QVBoxLayout()
        # Add logo to main window
        logo_label = QLabel(self)
        pixmap = QPixmap(LOGO_PATH)
        if not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(
                300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
        else:
            logo_label.setText("Logo not found")
        logo_label.setAlignment(Qt.AlignCenter)
        left.addWidget(logo_label)
        left.addWidget(QLabel(f"Welcome, {self.user_name}!"))
        left.addWidget(QLabel("Vaults:"))
        left.addWidget(self.vault_list)
        encrypt_button = QPushButton("Encrypt Data")
        encrypt_button.clicked.connect(self.encrypt)
        left.addWidget(encrypt_button)
        decrypt_button = QPushButton("Decrypt Data")
        decrypt_button.clicked.connect(self.decrypt)
        left.addWidget(decrypt_button)
        layout.addLayout(left)

        right = QVBoxLayout()
        right.addWidget(self.search_input)
        right.addWidget(self.file_tree)
        layout.addLayout(right)

        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.load_vaults()
        self.resize(800, 600)

    def show_context_menu(self, position):
        item = self.vault_list.itemAt(position)
        if not item:
            return
        menu = QMenu(self)
        encrypt_action = QAction("Encrypt Data", self)
        encrypt_action.triggered.connect(self.encrypt)
        menu.addAction(encrypt_action)
        decrypt_action = QAction("Decrypt Data", self)
        decrypt_action.triggered.connect(self.decrypt)
        menu.addAction(decrypt_action)
        open_vault_action = QAction("Open Vault", self)
        open_vault_action.triggered.connect(self.open_vault)
        menu.addAction(open_vault_action)
        delete_vault_action = QAction("Delete Vault", self)
        delete_vault_action.triggered.connect(self.delete_vault)
        menu.addAction(delete_vault_action)
        menu.exec_(self.vault_list.mapToGlobal(position))

    def show_file_context_menu(self, position):
        item = self.file_tree.itemAt(position)
        if not item:
            return
        menu = QMenu(self)
        remove_decrypt_action = QAction("Remove and Decrypt File", self)
        remove_decrypt_action.triggered.connect(
            lambda: self.remove_and_decrypt_file(item))
        menu.addAction(remove_decrypt_action)
        menu.exec_(self.file_tree.mapToGlobal(position))

    def load_vaults(self):
        self.vault_list.clear()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT id, name, path FROM vaults")
        vaults = c.fetchall()
        for vid, vname, vpath in vaults:
            item = QListWidgetItem(f"{vname} ({vpath})")
            item.setData(Qt.UserRole, vid)
            self.vault_list.addItem(item)
        conn.close()

    def get_selected_vault_id(self):
        item = self.vault_list.currentItem()
        if item:
            return item.data(Qt.UserRole)
        else:
            QMessageBox.warning(self, "Error", "Select a vault.")
            return None

    def show_files(self, item):
        vid = item.data(Qt.UserRole)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT path FROM vaults WHERE id=?", (vid,))
        path = c.fetchone()[0]
        conn.close()
        self.file_tree.clear()
        if os.path.exists(path):
            root = QTreeWidgetItem([os.path.basename(path)])
            root.setData(0, Qt.UserRole, path)
            self.file_tree.addTopLevelItem(root)
            self.add_tree_items(root, path)
            root.setExpanded(True)
        else:
            QMessageBox.warning(self, "Error", "Path does not exist.")

    def add_tree_items(self, parent, path):
        for item in os.listdir(path):
            full = os.path.join(path, item)
            child = QTreeWidgetItem([item])
            child.setData(0, Qt.UserRole, full)
            parent.addChild(child)
            if os.path.isdir(full):
                self.add_tree_items(child, full)

    def open_file(self, item, col):
        full_path = item.data(0, Qt.UserRole)
        if full_path and os.path.exists(full_path):
            try:
                if os.path.isfile(full_path):
                    if platform.system() == 'Windows':
                        os.startfile(full_path)
                    elif platform.system() == 'Darwin':
                        subprocess.call(['open', full_path])
                    else:
                        subprocess.call(['xdg-open', full_path])
                else:
                    # For directories, open the folder
                    if platform.system() == 'Windows':
                        os.startfile(full_path)
                    elif platform.system() == 'Darwin':
                        subprocess.call(['open', full_path])
                    else:
                        subprocess.call(['xdg-open', full_path])
            except (OSError, subprocess.CalledProcessError) as e:
                QMessageBox.warning(
                    self, "Error", f"Failed to open {full_path}: {e}")

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        vid = self.get_selected_vault_id()
        if vid is None:
            QMessageBox.warning(
                self, "Error", "Please select a vault before dropping files.")
            event.ignore()
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT path FROM vaults WHERE id=?", (vid,))
        vault_path = c.fetchone()[0]
        conn.close()
        if not os.path.exists(vault_path):
            QMessageBox.warning(self, "Error", "Vault path does not exist.")
            event.ignore()
            return
        urls = event.mimeData().urls()
        files_to_encrypt = [url.toLocalFile()
                            for url in urls if os.path.isfile(url.toLocalFile())]
        if not files_to_encrypt:
            QMessageBox.warning(
                self, "Error", "No valid files to encrypt. Please drop files only.")
            event.ignore()
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter vault passphrase:", QLineEdit.Password)
        if not ok:
            event.ignore()
            return
        fernet_key = self.get_fernet_key(vid, passphrase)
        if fernet_key is None:
            QMessageBox.warning(self, "Error", "Wrong passphrase.")
            event.ignore()
            return
        f = Fernet(fernet_key)
        skipped_files = []
        for src_path in files_to_encrypt:
            dest_path = os.path.join(vault_path, os.path.basename(src_path))
            try:
                with open(src_path, "rb") as tf:
                    contents = tf.read()
                enc = f.encrypt(contents)
                with open(dest_path, "wb") as tf:
                    tf.write(enc)
                # Refresh file tree
                self.show_files(self.vault_list.currentItem())
            except (PermissionError, OSError, InvalidToken) as e:
                skipped_files.append(f"{src_path}: {e}")
                continue
        message = f"Added and encrypted {len(files_to_encrypt) - len(skipped_files)} files to the vault."
        if skipped_files:
            message += f"\nSkipped {len(skipped_files)} files due to errors:\n" + \
                "\n".join(skipped_files[:5])
        QMessageBox.information(self, "Success", message)
        event.accept()

    def add_vault_with_path(self, path):
        name, ok = QInputDialog.getText(
            self, "Vault Name", "Enter vault name:")
        if not ok:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter passphrase:", QLineEdit.Password)
        if not ok:
            return
        recovery, ok = QInputDialog.getText(
            self, "Recovery", "Enter recovery passphrase:", QLineEdit.Password)
        if not ok:
            return
        vault_path = path.replace('\\', '/')
        if platform.system() == 'Linux':
            vault_path = vault_path.replace(' ', '\\ ')
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=390000)
        protect_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        fernet_key = Fernet.generate_key()
        f_protect = Fernet(protect_key)
        enc_key = f_protect.encrypt(fernet_key)
        recovery_salt = os.urandom(16)
        recovery_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(
        ), length=32, salt=recovery_salt, iterations=390000)
        recovery_protect_key = base64.urlsafe_b64encode(
            recovery_kdf.derive(recovery.encode()))
        f_recovery_protect = Fernet(recovery_protect_key)
        recovery_enc_key = f_recovery_protect.encrypt(fernet_key)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO vaults (name, path, salt, enc_key, recovery_salt, recovery_enc_key) VALUES (?, ?, ?, ?, ?, ?)",
                  (name, vault_path, salt, enc_key, recovery_salt, recovery_enc_key))
        conn.commit()
        conn.close()
        self.load_vaults()
        QMessageBox.information(self, "Success", "Vault added!")

    def add_vault(self):
        name, ok = QInputDialog.getText(
            self, "Vault Name", "Enter vault name:")
        if not ok:
            return
        path = QFileDialog.getExistingDirectory(self, "Select Vault Path")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter passphrase:", QLineEdit.Password)
        if not ok:
            return
        recovery, ok = QInputDialog.getText(
            self, "Recovery", "Enter recovery passphrase:", QLineEdit.Password)
        if not ok:
            return
        vault_path = path.replace('\\', '/')
        if platform.system() == 'Linux':
            vault_path = vault_path.replace(' ', '\\ ')
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=390000)
        protect_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        fernet_key = Fernet.generate_key()
        f_protect = Fernet(protect_key)
        enc_key = f_protect.encrypt(fernet_key)
        recovery_salt = os.urandom(16)
        recovery_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(
        ), length=32, salt=recovery_salt, iterations=390000)
        recovery_protect_key = base64.urlsafe_b64encode(
            recovery_kdf.derive(recovery.encode()))
        f_recovery_protect = Fernet(recovery_protect_key)
        recovery_enc_key = f_recovery_protect.encrypt(fernet_key)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO vaults (name, path, salt, enc_key, recovery_salt, recovery_enc_key) VALUES (?, ?, ?, ?, ?, ?)",
                  (name, vault_path, salt, enc_key, recovery_salt, recovery_enc_key))
        conn.commit()
        conn.close()
        self.load_vaults()
        QMessageBox.information(self, "Success", "Vault added!")

    def encrypt(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter vault passphrase:", QLineEdit.Password)
        if not ok:
            return
        fernet_key = self.get_fernet_key(vid, passphrase)
        if fernet_key is None:
            QMessageBox.warning(self, "Error", "Wrong passphrase.")
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT path FROM vaults WHERE id=?", (vid,))
        path = c.fetchone()[0]
        conn.close()
        f = Fernet(fernet_key)
        files = []
        skip_dirs = {'.git', '.DS_Store', '__pycache__'}
        for root, dirs, fs in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            files.extend(os.path.join(root, file) for file in fs)
        reply = QMessageBox.question(
            self, "Confirm", f"Encrypt {len(files)} files?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            skipped_files = []
            for fp in files:
                try:
                    with open(fp, "rb") as tf:
                        contents = tf.read()
                    try:
                        f.decrypt(contents)
                        continue
                    except InvalidToken:
                        pass
                    enc = f.encrypt(contents)
                    try:
                        with open(fp, "wb") as tf:
                            tf.write(enc)
                    except (PermissionError, OSError) as e:
                        skipped_files.append(f"{fp}: {e}")
                        continue
                except (PermissionError, OSError) as e:
                    skipped_files.append(f"{fp}: {e}")
                    continue
            self.load_vaults()
            message = "The vault is now encrypted."
            if skipped_files:
                message += f"\nSkipped {len(skipped_files)} files due to errors:\n" + \
                    "\n".join(skipped_files[:5])
            QMessageBox.information(self, "Success", message)

    def decrypt(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter vault passphrase:", QLineEdit.Password)
        if not ok:
            return
        fernet_key = self.get_fernet_key(vid, passphrase)
        if fernet_key is None:
            QMessageBox.warning(self, "Error", "Wrong passphrase.")
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT path FROM vaults WHERE id=?", (vid,))
        path = c.fetchone()[0]
        conn.close()
        reply = QMessageBox.question(
            self, "Confirm", "Decrypt files?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            f = Fernet(fernet_key)
            files = []
            skip_dirs = {'.git', '.DS_Store', '__pycache__'}
            for root, dirs, fs in os.walk(path):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                files.extend(os.path.join(root, file) for file in fs)
            skipped_files = []
            for fp in files:
                try:
                    with open(fp, "rb") as tf:
                        contents = tf.read()
                    try:
                        dec = f.decrypt(contents)
                    except InvalidToken:
                        skipped_files.append(
                            f"{fp}: Not encrypted or wrong key")
                        continue
                    try:
                        with open(fp, "wb") as tf:
                            tf.write(dec)
                    except (PermissionError, OSError) as e:
                        skipped_files.append(f"{fp}: {e}")
                        continue
                except (PermissionError, OSError) as e:
                    skipped_files.append(f"{fp}: {e}")
                    continue
            self.load_vaults()
            message = "Decryption Successful."
            if skipped_files:
                message += f"\nSkipped {len(skipped_files)} files due to errors:\n" + \
                    "\n".join(skipped_files[:5])
            QMessageBox.information(self, "Success", message)

    def open_vault(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT path FROM vaults WHERE id=?", (vid,))
        path = c.fetchone()[0]
        conn.close()
        if os.path.exists(path):
            try:
                if platform.system() == 'Windows':
                    os.startfile(path)
                elif platform.system() == 'Darwin':
                    subprocess.call(['open', path])
                else:
                    subprocess.call(['xdg-open', path])
            except (OSError, subprocess.CalledProcessError) as e:
                QMessageBox.warning(
                    self, "Error", f"Failed to open vault: {e}")
        else:
            QMessageBox.warning(self, "Error", "Path does not exist.")

    def backup_key(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter vault passphrase:", QLineEdit.Password)
        if not ok:
            return
        fernet_key = self.get_fernet_key(vid, passphrase)
        if fernet_key is None:
            QMessageBox.warning(self, "Error", "Wrong passphrase.")
            return
        QMessageBox.information(
            self, "Backup Key", f"Backup Decryption Key (save this securely):\n{fernet_key.decode()}")

    def change_password(self):
        current, ok = QInputDialog.getText(
            self, "Current Password", "Enter current password:", QLineEdit.Password)
        if not ok:
            return
        new, ok = QInputDialog.getText(
            self, "New Password", "Enter new password:", QLineEdit.Password)
        if not ok:
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password, email FROM users")
        stored_hash, email = c.fetchone()
        if bcrypt.checkpw(current.encode(), stored_hash.encode()):
            new_hash = bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode()
            c.execute("UPDATE users SET password=? WHERE email=?",
                      (new_hash, email))
            conn.commit()
            QMessageBox.information(
                self, "Success", "Password changed successfully!")
        else:
            QMessageBox.warning(
                self, "Error", "Incorrect password. Password change failed.")
        conn.close()

    def toggle_self_destruct(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT self_destruct_enabled FROM users")
        current = c.fetchone()[0]
        new = 1 if current == 0 else 0
        c.execute("UPDATE users SET self_destruct_enabled=?", (new,))
        conn.commit()
        conn.close()
        QMessageBox.information(
            self, "Success", f"Self-destruction mode {'enabled' if new else 'disabled'}.")

    def recover_passphrase(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        recovery, ok = QInputDialog.getText(
            self, "Recovery Passphrase", "Enter recovery passphrase:", QLineEdit.Password)
        if not ok:
            return
        fernet_key = self.get_fernet_key(vid, recovery, is_recovery=True)
        if fernet_key is None:
            QMessageBox.warning(self, "Error", "Wrong recovery passphrase.")
            return
        new_pass, ok = QInputDialog.getText(
            self, "New Passphrase", "Enter new passphrase:", QLineEdit.Password)
        if not ok:
            return
        new_rec, ok = QInputDialog.getText(
            self, "New Recovery Passphrase", "Enter new recovery passphrase:", QLineEdit.Password)
        if not ok:
            return
        new_salt = os.urandom(16)
        new_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                             length=32, salt=new_salt, iterations=390000)
        new_protect_key = base64.urlsafe_b64encode(
            new_kdf.derive(new_pass.encode()))
        f_new_protect = Fernet(new_protect_key)
        new_enc_key = f_new_protect.encrypt(fernet_key)
        new_recovery_salt = os.urandom(16)
        new_recovery_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(
        ), length=32, salt=new_recovery_salt, iterations=390000)
        new_recovery_protect_key = base64.urlsafe_b64encode(
            new_recovery_kdf.derive(new_rec.encode()))
        f_new_recovery_protect = Fernet(new_recovery_protect_key)
        new_recovery_enc_key = f_new_recovery_protect.encrypt(fernet_key)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE vaults SET salt=?, enc_key=?, recovery_salt=?, recovery_enc_key=? WHERE id=?",
                  (new_salt, new_enc_key, new_recovery_salt, new_recovery_enc_key, vid))
        conn.commit()
        conn.close()
        QMessageBox.information(
            self, "Success", "Passphrase recovered and updated.")

    def edit_path(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        new_path = QFileDialog.getExistingDirectory(
            self, "Select New Vault Path")
        if not new_path:
            return
        new_path = new_path.replace('\\', '/')
        if platform.system() == 'Linux':
            new_path = new_path.replace(' ', '\\ ')
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE vaults SET path=? WHERE id=?", (new_path, vid))
        conn.commit()
        conn.close()
        self.load_vaults()
        QMessageBox.information(
            self, "Success", "Vault path updated successfully!")

    def delete_vault(self):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        reply = QMessageBox.question(
            self, "Confirm", "Are you sure you want to delete this vault and its data?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT path FROM vaults WHERE id=?", (vid,))
            path = c.fetchone()[0]
            if os.path.exists(path):
                try:
                    shutil.rmtree(path)
                except (PermissionError, OSError) as e:
                    QMessageBox.warning(
                        self, "Error", f"Failed to delete vault directory: {e}")
            c.execute("DELETE FROM vaults WHERE id=?", (vid,))
            conn.commit()
            conn.close()
            self.load_vaults()
            QMessageBox.information(
                self, "Success", "Vault deleted successfully!")

    def what_is(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("What is Vaultlyn?")
        dialog.setWindowIcon(QIcon("icon.png"))

        # Add logo
        logo_label = QLabel(dialog)
        pixmap = QPixmap(LOGO_PATH)
        if not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(
                300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
        else:
            logo_label.setText("Logo not found")
        logo_label.setAlignment(Qt.AlignCenter)

        # Formatted text
        text_label = QLabel(dialog)
        text_label.setTextFormat(Qt.RichText)
        text_label.setAlignment(Qt.AlignJustify)
        text_label.setWordWrap(True)
        text = """
            <h2>Vaultlyn Overview</h2>
            <p>Vaultlyn is a file encryption vault designed to secure your files locally by encrypting them on your computer.</p>
            
            <h3>Key Features:</h3>
            <ul>
                <li><b>Fernet Encryption:</b> Utilizes robust Fernet encryption to lock files, ensuring they can only be unlocked with the dedicated decryption key generated during encryption.</li>
                <li><b>Security Note:</b> This encryption cannot be manipulated without the decryption key, providing strong protection.</li>
                <li><b>Multiple Vaults:</b> Supports the creation of multiple vaults, each with individual passphrases and recovery options for added flexibility.</li>
            </ul>
            
            <h3>About Vaultlyn:</h3>
            <p>Vaultlyn is an open-source program developed by Sidharth Prabhu from Frissco Creative Labs. ©Frissco Creative Labs 2025</p>
        """
        text_label.setText(text)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(logo_label)
        layout.addWidget(text_label)
        layout.addStretch()
        dialog.setLayout(layout)
        dialog.resize(400, 300)
        dialog.exec_()

    def about(self):
        text = """
Vaultlyn Version 1.15
©Frissco Creative Labs 2025
Developed by Sidharth Prabhu
"""
        QMessageBox.information(self, "About Vaultlyn", text)

    def get_fernet_key(self, vault_id, passphrase, is_recovery=False):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if is_recovery:
            c.execute(
                "SELECT recovery_salt, recovery_enc_key FROM vaults WHERE id = ?", (vault_id,))
        else:
            c.execute(
                "SELECT salt, enc_key FROM vaults WHERE id = ?", (vault_id,))
        result = c.fetchone()
        conn.close()
        if not result:
            return None
        salt, enc_key = result
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                         salt=salt, iterations=390000)
        protect_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        f_protect = Fernet(protect_key)
        try:
            fernet_key = f_protect.decrypt(enc_key)
            return fernet_key
        except InvalidToken:
            return None

    def remove_and_decrypt_file(self, item):
        vid = self.get_selected_vault_id()
        if vid is None:
            return
        full_path = item.data(0, Qt.UserRole)
        if not full_path or not os.path.exists(full_path):
            QMessageBox.warning(self, "Error", "Selected file does not exist.")
            return
        passphrase, ok = QInputDialog.getText(
            self, "Passphrase", "Enter vault passphrase:", QLineEdit.Password)
        if not ok:
            return
        fernet_key = self.get_fernet_key(vid, passphrase)
        if fernet_key is None:
            QMessageBox.warning(self, "Error", "Wrong passphrase.")
            return
        f = Fernet(fernet_key)
        try:
            with open(full_path, "rb") as tf:
                contents = tf.read()
            try:
                dec_contents = f.decrypt(contents)
                temp_path = full_path + ".decrypted"
                with open(temp_path, "wb") as tf:
                    tf.write(dec_contents)
                os.remove(full_path)
                shutil.move(temp_path, full_path)
                # Refresh file tree
                self.show_files(self.vault_list.currentItem())
                QMessageBox.information(
                    self, "Success", f"File {os.path.basename(full_path)} removed and decrypted.")
            except InvalidToken:
                QMessageBox.warning(
                    self, "Error", "File is not encrypted or wrong key.")
                return
        except (PermissionError, OSError) as e:
            QMessageBox.warning(
                self, "Error", f"Failed to remove/decrypt file: {e}")
            return

    def schedule_search(self):
        # Start or restart the timer when text changes
        self.search_timer.start()

    def perform_search(self):
        search_text = self.search_input.text().lower()
        if len(search_text) < 3:  # Minimum 3 characters
            return
        items = self.file_tree.findItems(
            search_text, Qt.MatchContains | Qt.MatchRecursive, 0)
        if items:
            item = items[0]  # Select the first matching item
            self.file_tree.setCurrentItem(item)
            self.file_tree.scrollToItem(item)
        else:
            QMessageBox.warning(
                self, "Search", "No matching files or folders found.")

    def close(self):
        QMessageBox.information(self, "Closing", "Bye! See you later!")
        QApplication.quit()


if __name__ == "__main__":
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (name TEXT, email TEXT, password TEXT, self_destruct_enabled INTEGER DEFAULT 0, failed_attempts INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS vaults
                 (id INTEGER PRIMARY KEY, name TEXT, path TEXT, salt BLOB, enc_key BLOB, recovery_salt BLOB, recovery_enc_key BLOB)''')
    conn.commit()
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    conn.close()

    app = QApplication(sys.argv)
    if user_count == 0:
        create_dlg = CreateUserDialog()
        if create_dlg.exec_() == QDialog.Accepted:
            rules_text = """Before getting started, We wanted to inform some rules about this program...
1. Don't forget your passwords. If you do so, use the recovery option, but keep recovery passphrases safe.
2. Vaultlyn now prevents multiple encryptions by skipping already encrypted files.
3. Each vault has its own passphrase for security.
With that cleared, Welcome to Vaultlyn!"""
            QMessageBox.information(None, "Rules", rules_text)
    else:
        login_dlg = LoginDialog()
        if login_dlg.exec_() != QDialog.Accepted:
            sys.exit()

    main_win = MainWindow()
    main_win.show()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM vaults")
    vault_count = c.fetchone()[0]
    conn.close()
    if vault_count == 0:
        reply = QMessageBox.question(
            main_win, "No Vaults", "No vaults found. Let's create your first vault.", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            main_win.add_vault()

    sys.exit(app.exec_())
