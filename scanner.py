import os
import shutil
import subprocess
import requests
import argparse
import json
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from colorama import Fore, Back, Style, init
from html import escape

# Ініціалізація colorama
init(autoreset=True)

# Перевірка наявності інструментів
def check_tools():
    tools = ['nmap', 'nikto', 'sqlmap', 'xsstrike', 'gobuster', 'burpsuite', 'openvas', 'arachni', 'wapiti', 'wpscan', 'metasploit']
    for tool in tools:
        if shutil.which(tool) is None:
            print(f"{Fore.RED}[!] {tool} не знайдено. Переконайтеся, що він встановлений.")
            return False
    return True

# Логування результатів у HTML форматі
def log_result(result, tool_name):
    filename = f'{tool_name}_results.html'
    with open(filename, 'a') as log_file:
        log_file.write(f"<h3>{tool_name} ({datetime.now()})</h3><pre>{escape(result)}</pre>")

# Перевірка HTTP-заголовків
def check_security_headers(target):
    print(f"{Fore.CYAN}[+] Перевірка HTTP-заголовків для {target}")
    try:
        response = requests.get(target)
        headers = response.headers
        issues = []

        if 'X-Frame-Options' not in headers:
            issues.append('X-Frame-Options відсутній (Clickjacking)')
        if 'Strict-Transport-Security' not in headers:
            issues.append('Strict-Transport-Security відсутній (HSTS)')
        if 'Content-Security-Policy' not in headers:
            issues.append('Content-Security-Policy відсутній (XSS захист)')
        if 'X-Content-Type-Options' not in headers:
            issues.append('X-Content-Type-Options відсутній (MIME sniffing)')
        if 'Referrer-Policy' not in headers:
            issues.append('Referrer-Policy відсутній')
        if 'X-XSS-Protection' not in headers:
            issues.append('X-XSS-Protection відсутній')

        if issues:
            result = f"Проблеми із заголовками:\n" + '\n'.join(issues)
        else:
            result = "Заголовки безпеки налаштовані коректно."

        print(result)
        log_result(result, 'headers')

    except Exception as e:
        print(f"{Fore.RED}Помилка під час перевірки заголовків: {e}")
        log_result(f"Помилка заголовків: {e}", 'headers')

# Функції для виконання інструментів
def scan_ports(target):
    print(f"{Fore.GREEN}[+] Сканування портів для {target}")
    try:
        result = subprocess.run(['nmap', '-sS', '-sV', '-T4', target], capture_output=True, text=True)
        if result.returncode == 0:
            log_result(f"Порти:\n{result.stdout}", 'nmap')
        else:
            print(f"{Fore.RED}Помилка при виконанні nmap: {result.stderr}")
            log_result(f"Помилка nmap: {result.stderr}", 'nmap')
    except Exception as e:
        print(f"{Fore.RED}Помилка під час сканування портів: {e}")

# Додаткові інструменти
def run_wpscan(target):
    print(f"{Fore.GREEN}[+] Виконання WPScan для {target}")
    try:
        result = subprocess.run(['wpscan', '--url', target], capture_output=True, text=True)
        if result.returncode == 0:
            log_result(f"WPScan:\n{result.stdout}", 'wpscan')
        else:
            print(f"{Fore.RED}Помилка при виконанні WPScan: {result.stderr}")
            log_result(f"Помилка WPScan: {result.stderr}", 'wpscan')
    except Exception as e:
        print(f"{Fore.RED}Помилка під час виконання WPScan: {e}")

def run_metasploit(target):
    print(f"{Fore.GREEN}[+] Виконання Metasploit для {target}")
    try:
        result = subprocess.run(['msfconsole', '-q', '-x', f'use exploit/windows/smb/ms08_067_netapi; set RHOST {target}; exploit'], capture_output=True, text=True)
        if result.returncode == 0:
            log_result(f"Metasploit:\n{result.stdout}", 'metasploit')
        else:
            print(f"{Fore.RED}Помилка при виконанні Metasploit: {result.stderr}")
            log_result(f"Помилка Metasploit: {result.stderr}", 'metasploit')
    except Exception as e:
        print(f"{Fore.RED}Помилка під час виконання Metasploit: {e}")

# Завантаження конфігурацій
def load_config():
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)
        return config
    except FileNotFoundError:
        print(f"{Fore.RED}Конфігураційний файл не знайдений. Використовуємо стандартні налаштування.")
        return {"target": "http://example.com"}

# Оновлений main з меню
def main():
    config = load_config()
    if not config:
        return

    print(Fore.YELLOW + Style.BRIGHT + "\n--- Безпекове сканування веб-сайтів ---")
    print(Fore.GREEN + Style.BRIGHT + "Задайте URL для сканування:")
    target = input(Fore.CYAN + "Введіть URL (наприклад, http://site.com): ")

    if not check_tools():
        return

    while True:
        print(Fore.YELLOW + "\nВибір інструментів для сканування:")
        print(Fore.BLUE + "1. Сканування портів (nmap)")
        print(Fore.BLUE + "2. Перевірка вразливостей (nikto)")
        print(Fore.BLUE + "3. SQL Injection тест (sqlmap)")
        print(Fore.BLUE + "4. XSS тест (XSStrike)")
        print(Fore.BLUE + "5. Пошук директорій (Gobuster)")
        print(Fore.BLUE + "6. Перевірка HTTP-заголовків")
        print(Fore.BLUE + "7. Виконання Burp Suite")
        print(Fore.BLUE + "8. Виконання OpenVAS")
        print(Fore.BLUE + "9. Виконання Arachni")
        print(Fore.BLUE + "10. Виконання Wapiti")
        print(Fore.BLUE + "11. Виконання WPScan")
        print(Fore.BLUE + "12. Виконання Metasploit")
        print(Fore.RED + "13. Завершити сканування")
        
        choice = input(Fore.CYAN + "\nВиберіть номер інструмента або 13 для завершення: ")
        
        if choice == '1':
            scan_ports(target)
        elif choice == '11':
            run_wpscan(target)
        elif choice == '12':
            run_metasploit(target)
        elif choice == '13':
            print(Fore.GREEN + "\n--- Сканування завершено. Результати збережено. ---")
            break
        else:
            print(Fore.RED + "Невірний вибір, спробуйте ще раз.")

if __name__ == '__main__':
    main()