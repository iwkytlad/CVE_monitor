import datetime
import socket
import json
from pathlib import Path
import platform
import subprocess
import os


class CVE_Monitor():
    def __init__(self, path):
        self.path = path
        self.cve_db = []
        self.hosts = []
        self.vulns = []
        self.software = []

    def initialize(self):
        cd = datetime.datetime.now()
        Path(self.path / 'data').mkdir(parents=True, exist_ok=True)
        Path(self.path / 'reports').mkdir(parents=True, exist_ok=True)
        Path(self.path / 'alerts').mkdir(parents=True, exist_ok=True)

    def run(self):
        self.initialize()
        self.cve_db = self.load_cve_database()

        self.software = self.load_installed_software()
        self.hosts = self.software.get('hosts', [])
        print(f"Загружено CVE: {len(self.cve_db)}")
        print(f"Загружено хостов: {len(self.hosts)}")
        print("Инициализация завершена")
        self.vulns = self.scan_all_hosts()
        print("Все хосты просканированы")
        self.generate_reports()
        print("Репорт открыт в браузере")
        self.save_results_json()
        self.generate_alerts()
        print("Отчеты созданы")

    def load_cve_database(self):
        try:
            with open(self.path / 'data' / 'hot_cves.json', 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not data:
                print('hot_cves.json is empty')
                return []
            return data
        except:
            raise FileNotFoundError('hot_cves.json not found')

    def load_installed_software(self):
        sw_file = self.path / 'data' / 'installed_software.json'

        if not sw_file.exists():
            print("installed_software.json not found")
            return self.generate_software_json()

        try:
            with open(sw_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not data:
                print("installed_software.json is empty")
                return self.generate_software_json()
            return data
        except json.JSONDecodeError:
            print("errors in installed_software.json")
            return self.generate_software_json()

    # Сгенерировано AI

    def get_host_info(self):
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ip": ip}

    # Сгенерировано AI

    def get_installed_software(self):
        """Собирает список установленного ПО"""
        software = []
        os_name = platform.system()

        try:
            if os_name == "Windows":
                result = subprocess.run(['winget', 'list'], capture_output=True, text=True, timeout=30)
                # ... парсинг

            elif os_name == "Linux":
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=30)
                # ... парсинг

            elif os_name == "Darwin":  # macOS
                try:
                    result = subprocess.run(['brew', 'list', '--versions'], capture_output=True, text=True, timeout=30)
                    # ... парсинг
                except FileNotFoundError:
                    print("⚠️ Brew не установлен. Создаю тестовые данные...")
                    # Возвращаем тестовые данные для macOS
                    return [
                        {"name": "python3", "version": "3.11.5"},
                        {"name": "nginx", "version": "1.24.0"},
                        {"name": "openssl", "version": "3.0.13"}
                    ]

        except subprocess.TimeoutExpired:
            print("⚠️ Команда выполнения ПО превысила время")
            return []
        except Exception as e:
            print(f"⚠️ Ошибка при получении списка ПО: {e}")
            return []

        return software

    # Сгенерировано AI

    def generate_software_json(self):
        """Создаёт файл installed_software.json и возвращает данные"""
        host = self.get_host_info()
        host["software"] = self.get_installed_software()

        data = {"hosts": [host]}
        output_path = self.path / 'data' / 'installed_software.json'

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"✅ Файл создан: {output_path}")
        return data

    def scan_host(self, host):
        host_software = host.get('software')
        vuln = []
        for software in host_software:
            for vulnerability in self.cve_db:
                if vulnerability.get('software') == software.get('name') and (
                        software.get('version') in vulnerability.get('versions_affected', [])):
                    problem = {}
                    problem['host'] = host.get('hostname')
                    problem['name'] = vulnerability.get('software')
                    problem['ip'] = host.get('ip')
                    problem['version'] = software.get('version')
                    problem['cve_id'] = vulnerability.get('id')
                    problem['severity'] = vulnerability.get('severity')
                    problem['cvss_score'] = vulnerability.get('cvss_score')
                    problem['description'] = vulnerability.get('description')

                    vuln.append(problem)
        return vuln

    def scan_all_hosts(self):
        vuln = []
        for host in self.hosts:
            vuln.extend(self.scan_host(host))
        return vuln

    def generate_reports(self):
        cd = datetime.datetime.now()
        comp_name = socket.gethostname()
        with open(self.path / 'reports' / f'scan_report_{comp_name}_{cd.year}_{cd.month}_{cd.day}.html', 'w',
                  encoding='utf-8') as f:
            # Громоздко, переписать
            f.write('<!DOCTYPE html> \n')
            f.write('<html> \n')
            f.write('<head> \n')
            f.write('   <meta charset="utf-8">\n')
            f.write('   <title>CVE Scan Report</title> \n')
            f.write('   <style> \n')
            f.write(
                '       table { border-collapse: collapse; } th, td { border: 1px solid black; padding: 8px; } .critical { color: red; } .high { color: orange; } \n')
            f.write('   </style> \n')
            f.write('</head> \n')
            f.write('<body> \n')
            f.write('   <h1>🔒 CVE Scan Report</h1> \n')
            f.write(f'   <p> Дата: {cd.day}.{cd.month}.{cd.year}</p> \n')
            f.write(f'   <p> Устройство: {comp_name}</p> \n')
            os_name = platform.system()
            f.write(f'   <p> OS: {os_name}</p> \n')
            f.write(f'   <p> IP: {socket.gethostbyname(socket.gethostname())}</p> \n')

            f.write('    <h2>📊 Статистика</h2> \n')
            f.write('    <ul> \n')
            f.write(f'        <li>Всего уязвимостей: {len(self.vulns)}</li> \n')
            high = 0
            critical = 0
            for vuln in self.vulns:
                if vuln['severity'] == 'high':
                    high += 1
                if vuln['severity'] == 'critical':
                    critical += 1
            f.write(f'        <li>Critical: {critical}</li> \n')
            f.write(f'        <li>High: {high}</li> \n')
            f.write('   </ul> \n')
            f.write('\n')
            print(self.vulns)
            if self.vulns:
                f.write('    <h2>📋 Уязвимости</h2>\n')
                f.write('    <table> \n')
                f.write(f'        <tr> \n')
                f.write(
                    '            <th>ПО</th>\n          <th>Версия</th>\n           <th>CVE</th>\n          <th>Severity</th>\n         <th>CVSS</th>\n')
                f.write('        </tr>\n')
                for vuln in self.vulns:
                    f.write(f'        <tr> \n')
                    f.write(
                        f'            <th>{vuln['name']}</th>\n          <th>{vuln['version']}</th>\n           <th>{vuln['cve_id']}</th>\n          <th class="{vuln['severity']}">{vuln['severity']}</th>\n         <th class="{vuln['severity']}">{vuln['cvss_score']}</th>\n')
                    f.write('        </tr>\n')
                f.write('    </table> \n')
            else:
                f.write('    <h2>✅ Нет уязвимостей</h2>\n')
            f.write('</body> \n')
            f.write('</html> \n')
            self.open_report(self.path / 'reports' / f'scan_report_{comp_name}_{cd.year}_{cd.month}_{cd.day}.html')

    def open_report(self, report_path):
        system = platform.system()
        if system == "Darwin":
            os.system(f"open {report_path}")
        elif system == "Windows":
            os.system(f"start {report_path}")
        else:
            os.system(f"xdg-open {report_path}")

    def save_results_json(self):
        cd = datetime.datetime.now()
        comp_name = socket.gethostname()
        with open(Path(self.path / 'reports' / f'scan_results_{comp_name}_{cd.year}_{cd.month}_{cd.day}.json'), 'w',
                  encoding='utf-8') as f:
            for vuln in self.vulns:
                json.dump(vuln, f, ensure_ascii=False, indent=4)

    def generate_alerts(self):
        cd = datetime.datetime.now()
        comp_name = socket.gethostname()
        os_name = platform.system()
        with open(Path(self.path / 'alerts' / f'critical_alerts_{comp_name}_{cd.year}_{cd.month}_{cd.day}.txt'), 'w',
                  encoding='utf-8') as f:
            f.write(f"""Дата: {cd.day}.{cd.month}.{cd.year} 
Устройство: {comp_name}
OS: {os_name}
IP: {socket.gethostbyname(socket.gethostname())}
""")
            f.write('\n')
            sorted_vulns = sorted(self.vulns, key=lambda vuln: vuln['severity'])
            if self.vulns:
                if sorted_vulns[0]['severity'] == 'critical':
                    print(sorted_vulns)
                    count = 1
                    for vuln in sorted_vulns:
                        if vuln['severity'] == 'critical':
                            f.write(f'Уязвимость {count}: \n')
                            f.write(f""" ПО: {vuln['name']}
Версия: {vuln['version']}
CVE: {vuln['cve_id']}
Уровень критичности: {vuln['severity']}
CVSS: {vuln['cvss_score']}
Описание: {vuln['description']}\n""")
            else:
                f.write('✅ Нет критических уязвимостей')


if __name__ == '__main__':
    path = Path(__file__).parent.absolute()
    my_device = CVE_Monitor(path)
    my_device.run()
