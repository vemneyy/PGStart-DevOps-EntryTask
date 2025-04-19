#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import random
import shlex
import socket
import string
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path

import paramiko


def log(message: str) -> None:
    """Выводит сообщение в стандартный вывод с префиксом."""
    print(f"[PostgreInstaller] {message}")


def gen_password(length: int = 16) -> str:
    """Генерирует случайный пароль указанной длины."""
    alphabet = string.ascii_letters + string.digits
    alphabet = alphabet.replace("'", "")
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(length))


@dataclass
class Host:
    """Представляет удалённый хост и операции над ним."""
    name: str
    load_score: float | None = None
    ssh: paramiko.SSHClient | None = None
    os_family: str | None = None
    data_dir: str | None = None
    postgresql_conf_path: str | None = None
    pg_hba_conf_path: str | None = None

    def connect(self, key_path: Path) -> None:
        """
        Устанавливает SSH-соединение с удалённым хостом от имени пользователя `root` с использованием заданного SSH-ключа.

        :param key_path: Объект `Path`, указывающий на путь к приватному ключу SSH (обычно `.pem` или `.key` файл).
        :raises RuntimeError: В случае ошибки аутентификации или других проблем при подключении.
        """
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            key_filename_str = str(key_path)
            log(f"[{self.name}] Попытка подключения с ключом: {key_filename_str}")
            self.ssh.connect(
                hostname=self.name,
                username="root",
                key_filename=key_filename_str,
                timeout=10
            )
            log(f"[{self.name}] SSH-подключение успешно.")

        except paramiko.AuthenticationException as auth_exc:
            raise RuntimeError(
                f"SSH-аутентификация к {self.name} не удалась: {auth_exc}. "
                f"Проверьте ключ {key_path} и права доступа (должны быть 600 или 400)."
            )

        except Exception as exc:
            raise RuntimeError(f"SSH-подключение к {self.name} не удалось: {exc}")

    def run(self, cmd: str, check: bool = True, hide_output: bool = False) -> str:
        """
        Выполняет команду на удалённой системе через SSH и возвращает её стандартный вывод.

        :param cmd: Команда оболочки, которую необходимо выполнить на удалённой системе.
        :param check: Если `True` (по умолчанию), возбуждает исключение при ненулевом коде завершения команды.
        :param hide_output: Если `True`, подавляет вывод команды в лог.
        :return: Стандартный вывод команды как строка (без завершающих переносов строк).
        :raises RuntimeError: Если `check=True` и команда завершилась с ненулевым кодом возврата.
        :raises RuntimeError: Если SSH-сессия не была установлена до вызова метода.
        """
        if not self.ssh:
            raise RuntimeError(f"[{self.name}] SSH‑сессия не инициализирована перед вызовом run().")

        full_cmd_log = f"[{self.name}] Выполняется: {cmd}"
        if not hide_output:
            log(full_cmd_log)

        stdin, stdout, stderr = self.ssh.exec_command(f"export LC_ALL=C; {cmd}", get_pty=True)
        exit_code = stdout.channel.recv_exit_status()

        out = stdout.read().decode('utf-8', errors='ignore')
        err = stderr.read().decode('utf-8', errors='ignore')

        if check and exit_code != 0:
            error_details = err.strip() or out.strip()
            log(f"Ошибка выполнения команды: {full_cmd_log}")
            raise RuntimeError(
                f"Команда '{cmd}' на {self.name} завершилась с кодом {exit_code}: {error_details}"
            )

        return out.strip()

    def manage_service(self, service_name: str, action: str):
        """
        Управление службой systemd на удалённом сервере через SSH.

        Поддерживаются следующие действия:
        - `restart`: перезапуск службы (обычно используется после изменения конфигурации).
        - `enable_and_start`: включение службы в автозагрузку и немедленный запуск.
        - `stop`: остановка службы.

        :param service_name: Имя службы systemd, например 'nginx', 'sshd', 'docker'.
        :param action: Тип действия. Поддерживаемые значения: 'restart', 'enable_and_start', 'stop'.
        :raises ValueError: Если указано некорректное действие.
        :raises RuntimeError: Если выполнение команды завершилось с ошибкой.
        """
        actions = {
            "restart": {
                "cmd": f"systemctl restart {service_name}",
                "log_start": f"Перезапуск службы {service_name} для применения настроек...",
                "log_success": f"Служба {service_name} перезапущена.",
                "error": f"Не удалось перезапустить службу {service_name}"
            },
            "enable_and_start": {
                "cmd": f"systemctl enable --now {service_name}",
                "log_start": f"Включение и запуск службы {service_name}...",
                "log_success": f"Служба {service_name} включена и запущена.",
                "error": f"Не удалось включить/запустить службу {service_name}"
            },
            "stop": {
                "cmd": f"systemctl stop {service_name}",
                "log_start": f"Остановка службы {service_name}...",
                "log_success": f"Служба {service_name} остановлена.",
                "error": f"Не удалось остановить службу {service_name}"
            }
        }

        log(f"[{self.name}] {actions[action]['log_start']}")

        try:
            self.run(actions[action]['cmd'])
            log(f"[{self.name}] {actions[action]['log_success']}")

        except Exception as e:
            log(f"[{self.name}] Ошибка при выполнении действия '{action}' над службой {service_name}. Проверка статуса...")
            status = self.run(f"systemctl --no-pager -l status {service_name}", check=False)
            log(f"[{self.name}] Статус службы:\n{status}")
            raise RuntimeError(f"{actions[action]['error']}: {e}")

    def detect_os_family(self) -> None:
        """
        Определяет семейство ОС (debian или rhel) на хосте.
        """
        log(f"[{self.name}] Определение семейства ОС...")
        info = self.run("cat /etc/os-release", hide_output=True)

        if any(x in info for x in
               ("ID_LIKE=\"rhel", "ID=centos", "ID=almalinux", "ID=fedora")):
            self.os_family = "rhel"
            log(f"[{self.name}] Определено семейство ОС: rhel")
        elif any(x in info for x in ("ID=debian", "ID=ubuntu")):
            self.os_family = "debian"
            log(f"[{self.name}] Определено семейство ОС: debian")
        else:
            log(f"[{self.name}] Не удалось определить ОС по /etc/os-release, пробую найти менеджер пакетов...")
            if self.run("command -v dnf", check=False, hide_output=True):
                self.os_family = "rhel"
                log(f"[{self.name}] Обнаружен 'dnf', предполагаю RHEL-семейство.")
            elif self.run("command -v yum", check=False, hide_output=True):
                self.os_family = "rhel"
                log(f"[{self.name}] Обнаружен 'yum', предполагаю RHEL-семейство.")
            elif self.run("command -v apt-get", check=False, hide_output=True):
                self.os_family = "debian"
                log(f"[{self.name}] Обнаружен 'apt-get', предполагаю Debian-семейство.")
            else:
                raise RuntimeError(
                    f"[{self.name}] Неподдерживаемый дистрибутив: не удалось определить семейство ОС и не найдены менеджеры пакетов (dnf, yum, apt-get).")

    def compute_load(self) -> None:
        """
        Рассчитывает относительную нагрузку (loadavg1 / nproc).
        """
        log(f"[{self.name}] Расчет средней нагрузки...")
        cpu_str = self.run("nproc", hide_output=True)
        load_str = self.run("awk '{print $1}' /proc/loadavg", hide_output=True)

        try:
            cpu = int(cpu_str)
            load1 = float(load_str)
            if cpu <= 0:
                log(f"[{self.name}] ПРЕДУПРЕЖДЕНИЕ: nproc вернул {cpu}. Использую 1 ядро для расчета нагрузки.")
                cpu = 1
            self.load_score = load1 / cpu
            log(f"[{self.name}] Число ядер={cpu}, LoadAvg1={load1:.2f}, Оценка нагрузки={self.load_score:.2f}")

        except (ValueError, TypeError) as e:
            raise RuntimeError(
                f"Не удалось вычислить нагрузку на {self.name}. nproc='{cpu_str}', loadavg='{load_str}'. Ошибка: {e}")

    def install_postgres(self) -> None:
        """
        Удаляет старую версию (если есть) и устанавливает PostgreSQL.
        """
        log(f"[{self.name}] Попытка остановить и удалить существующий PostgreSQL...")

        units_output = self.run(
            "systemctl list-units --type=service --no-legend --no-pager | grep '^postgresql' | awk '{print $1}'",
            hide_output=True)
        unit_names = units_output.strip().splitlines()

        for unit in unit_names:
            self.manage_service(unit.strip(), "stop")

        if self.os_family == "debian":
            log(f"[{self.name}] Обновление списков пакетов apt...")
            self.run("apt-get update -yq", hide_output=True)
            log(f"[{self.name}] Удаление пакетов postgresql*...")
            self.run("DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge 'postgresql*' || true", check=False,
                     hide_output=True)
            log(f"[{self.name}] Удаление каталогов /var/lib/postgresql/* и /etc/postgresql/*...")
            self.run("rm -rf /var/lib/postgresql/* /etc/postgresql/*", check=False, hide_output=True)
        elif self.os_family == "rhel":
            log(f"[{self.name}] Обновление списков пакетов dnf...")
            self.run("sudo dnf makecache -yq", hide_output=True)
            log(f"[{self.name}] Удаление пакетов postgresql*...")
            self.run("dnf remove -y 'postgresql*' || yum remove -y 'postgresql*' || true", check=False,
                     hide_output=True)
            log(f"[{self.name}] Удаление каталогов /var/lib/pgsql/* и /usr/pgsql-*...")
            self.run("rm -rf /var/lib/pgsql/* /usr/pgsql-*", check=False, hide_output=True)
        else:
            raise RuntimeError(f"[{self.name}] Неизвестное семейство ОС '{self.os_family}' для удаления PostgreSQL.")

        log(f"[{self.name}] Установка PostgreSQL...")

        if self.os_family == "debian":
            self.run("DEBIAN_FRONTEND=noninteractive apt-get install -yq postgresql postgresql-contrib")
        elif self.os_family == "rhel":
            self.run("dnf install -y postgresql-server postgresql-contrib")
            self.run("/usr/bin/postgresql-setup --initdb")
        else:
            raise RuntimeError(f"[{self.name}] Неизвестное семейство ОС '{self.os_family}' для установки PostgreSQL.")

        log(f"[{self.name}] Установка PostgreSQL завершена.")

    def install_psql_client(self) -> None:
        """
        Устанавливает только клиент psql, если он еще не установлен.
        """
        log(f"[{self.name}] Проверка и установка клиента psql...")

        if self.os_family == "debian":
            if self.run("dpkg -s postgresql-client > /dev/null 2>&1", check=False, hide_output=True) == '':
                log(f"[{self.name}] postgresql-client не найден, установка...")
                self.run("apt-get update -yq", hide_output=True)
                self.run("DEBIAN_FRONTEND=noninteractive apt-get install -yq postgresql-client")
                log(f"[{self.name}] postgresql-client установлен.")
            else:
                log(f"[{self.name}] Клиент psql (postgresql-client) уже установлен.")
        elif self.os_family == "rhel":
            if self.run("rpm -q postgresql > /dev/null 2>&1", check=False, hide_output=True) == '':
                log(f"[{self.name}] Пакет postgresql (содержащий клиент) не найден, установка...")
                self.run("dnf install -y postgresql")
                log(f"[{self.name}] Пакет postgresql установлен.")
            else:
                log(f"[{self.name}] Клиент psql (пакет postgresql) уже установлен.")
        else:
            raise RuntimeError(f"[{self.name}] Неизвестное семейство ОС '{self.os_family}' для установки клиента psql.")

    def discover_config_files(self) -> None:
        """
        Определяет пути к файлам postgresql.conf и pg_hba.conf согласно стандартным расположениям для Debian и RHEL.
        """
        log(f"[{self.name}] Определение путей к конфигурационным файлам для {self.os_family}...")

        if self.os_family == "debian":
            log(f"[{self.name}] Поиск установленной версии PostgreSQL в /etc/postgresql/...")
            find_version_cmd = "find /etc/postgresql/ -maxdepth 1 -mindepth 1 -type d -regextype posix-extended -regex '.*/[0-9]+(\\.[0-9]+)?$' -printf '%f\\n' | sort -V | tail -n 1"
            version = self.run(find_version_cmd, check=False, hide_output=True).strip()

            if not version:
                ls_version_cmd = "ls -1 /etc/postgresql/ | grep -E '^[0-9]+(\\.[0-9]+)?$' | sort -V | tail -n 1"
                version = self.run(ls_version_cmd, check=False, hide_output=True).strip()
            if not version:
                raise RuntimeError(
                    f"[{self.name}] Не удалось определить установленную версию PostgreSQL в /etc/postgresql/. Проверьте, установлен ли PostgreSQL и существует ли каталог /etc/postgresql/<version>/main/.")

            log(f"[{self.name}] Обнаружена версия PostgreSQL: {version}")
            base_path = f"/etc/postgresql/{version}/main"
            self.postgresql_conf_path = f"{base_path}/postgresql.conf"
            self.pg_hba_conf_path = f"{base_path}/pg_hba.conf"
            self.data_dir = base_path
        elif self.os_family == "rhel":
            log(f"[{self.name}] Используются стандартные пути для RHEL.")
            base_path = "/var/lib/pgsql/data"
            self.postgresql_conf_path = f"{base_path}/postgresql.conf"
            self.pg_hba_conf_path = f"{base_path}/pg_hba.conf"
            self.data_dir = base_path
        else:
            raise RuntimeError(
                f"[{self.name}] Неподдерживаемое или неопределенное семейство ОС '{self.os_family}' для определения путей конфигурации.")

        log(f"[{self.name}] Проверка существования файла: {self.postgresql_conf_path}")
        try:
            self.run(f"test -f {shlex.quote(self.postgresql_conf_path)}", check=True, hide_output=True)
        except RuntimeError as e:
            raise RuntimeError(
                f"[{self.name}] Файл postgresql.conf не найден по ожидаемому пути: {self.postgresql_conf_path}. Убедитесь, что PostgreSQL установлен и инициализирован корректно. Ошибка: {e}")

        log(f"[{self.name}] Проверка существования файла: {self.pg_hba_conf_path}")
        try:
            self.run(f"test -f {shlex.quote(self.pg_hba_conf_path)}", check=True, hide_output=True)
        except RuntimeError as e:
            raise RuntimeError(
                f"[{self.name}] Файл pg_hba.conf не найден по ожидаемому пути: {self.pg_hba_conf_path}. Убедитесь, что PostgreSQL установлен и инициализирован корректно. Ошибка: {e}")

        log(f"[{self.name}] Пути к конфигурационным файлам успешно определены и проверены.")
        log(f"[{self.name}] postgresql.conf: {self.postgresql_conf_path}")
        log(f"[{self.name}] pg_hba.conf: {self.pg_hba_conf_path}")
        log(f"[{self.name}] Каталог: {self.data_dir}")

    def tune_conf(self) -> None:
        """
        Настраивает postgresql.conf (в основном, listen_addresses).
        """
        if not self.postgresql_conf_path:
            raise RuntimeError(f"[{self.name}] tune_conf вызван без определенного postgresql_conf_path.")

        config_file_path = self.postgresql_conf_path
        config_file_path_quoted = shlex.quote(config_file_path)
        log(f"[{self.name}] Настройка {config_file_path}...")

        log(f"[{self.name}] Установка listen_addresses = '*'...")
        sed_cmd_listen = f"sed -i -e \"s/^[#[:space:]]*listen_addresses[[:space:]]*=.*$/listen_addresses = '*' /\" {config_file_path_quoted}"
        self.run(sed_cmd_listen, hide_output=True)

        grep_cmd_listen = f"grep -q \"^listen_addresses[[:space:]]*=\" {config_file_path_quoted} || echo \"listen_addresses = '*'\" >> {config_file_path_quoted}"
        self.run(grep_cmd_listen, hide_output=True)
        log(f"[{self.name}] Параметр listen_addresses установлен в '*' в {config_file_path}")

    def configure_pg_hba(self, student_ip: str) -> None:
        """
        Настраивает pg_hba.conf для доступа роли student и общего доступа.
        """
        if not self.pg_hba_conf_path:
            raise RuntimeError(f"[{self.name}] configure_pg_hba вызван без определенного pg_hba_conf_path.")

        hba_path = self.pg_hba_conf_path
        hba_path_quoted = shlex.quote(hba_path)
        log(f"[{self.name}] Настройка {hba_path}...")

        student_ip_cleaned = student_ip.split('/')[0]
        rule_student = f"host\tall\tstudent\t{student_ip_cleaned}/32\tmd5"

        escaped_student_pattern = f"host[[:space:]]+all[[:space:]]+student[[:space:]]+{student_ip_cleaned.replace('.', '[.]')}/32"

        log(f"[{self.name}] Удаление существующих правил для student ({student_ip_cleaned}) в {hba_path}...")
        self.run(f"sed -i -e '/^{escaped_student_pattern}/d' {hba_path_quoted}", check=False, hide_output=True)

        log(f"[{self.name}] Добавление новых правил в {hba_path}...")
        hba_rules_block = f"""{rule_student}"""
        hba_rules_for_sed_i = hba_rules_block.replace("\n", "\\n")
        marker = "### DEPLOY_POSTGRES_HBA_RULES_MARKER ###"
        marker_quoted = shlex.quote(marker)

        self.run(f"sed -i -e '/{marker}/d' {hba_path_quoted}", check=False, hide_output=True)

        sed_insert_after_comments_cmd = f"sed -i -e '/^#.*$/{{:a;n;/^#.*$/ba;i\\{hba_rules_for_sed_i}\\n{marker}\\n}}' {hba_path_quoted}"
        self.run(sed_insert_after_comments_cmd, check=False, hide_output=True)

        marker_check_cmd = f"grep -q {marker_quoted} {hba_path_quoted}"
        stdin_mc, stdout_mc, stderr_mc = self.ssh.exec_command(marker_check_cmd)
        exit_status_mc = stdout_mc.channel.recv_exit_status()

        if exit_status_mc != 0:
            log(f"[{self.name}] Вставка правил pg_hba в начало файла...")
            sed_insert_at_beginning_cmd = f"sed -i '1i{hba_rules_for_sed_i}\\n{marker}' {hba_path_quoted}"
            self.run(sed_insert_at_beginning_cmd, hide_output=True)

        self.run(f"sed -i -e '/{marker}/d' {hba_path_quoted}", hide_output=True)

        log(f"[{self.name}] Проверка наличия правил в {hba_path}...")
        rule_student_check_cmd = f"grep -qE '^[[:space:]]*host[[:space:]]+all[[:space:]]+student[[:space:]]+{student_ip_cleaned.replace('.', '[.]')}/32' {hba_path_quoted}"

        stdin_sc, stdout_sc, stderr_sc = self.ssh.exec_command(rule_student_check_cmd)
        if stdout_sc.channel.recv_exit_status() != 0:
            log(f"[{self.name}] ПРЕДУПРЕЖДЕНИЕ: Не удалось верифицировать правило для student в {hba_path}")
        else:
            log(f"[{self.name}] Правило для student найдено в {hba_path}.")

    def create_student_role(self, student_pass: str) -> None:
        """
        Создает роль 'student' или обновляет её пароль, если она уже существует.
        """
        log(f"[{self.name}] Создание или обновление роли student...")
        escaped_pass_sql = student_pass.replace("'", "''")
        sql_command = f"""
        DO $$
        BEGIN
           IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'student') THEN
              CREATE ROLE student LOGIN PASSWORD '{escaped_pass_sql}';
           ELSE
              ALTER ROLE student WITH LOGIN PASSWORD '{escaped_pass_sql}';
           END IF;
        END
        $$;
        """
        psql_cmd = f"psql -c {shlex.quote(sql_command)}"
        full_su_cmd = f"su - postgres -c {shlex.quote(psql_cmd)}"
        self.run(full_su_cmd, hide_output=True)

    def configure_firewall(self) -> None:
        """
        Настраивает межсетевой экран ОС (firewalld или ufw), открывая порт 5432/tcp.
        """
        log(f"[{self.name}] Настройка межсетевого экрана...")
        firewall_configured = False

        log(f"[{self.name}] Проверка статуса firewalld...")
        firewalld_check_cmd = "systemctl is-active --quiet firewalld"
        stdin_fw, stdout_fw, stderr_fw = self.ssh.exec_command(firewalld_check_cmd)
        firewalld_active = stdout_fw.channel.recv_exit_status() == 0

        if firewalld_active:
            log(f"[{self.name}] Обнаружен активный firewalld. Открытие порта/службы PostgreSQL...")
            service_check_cmd = "firewall-cmd --get-services | grep -qw postgresql"
            stdin_svc, stdout_svc, stderr_svc = self.ssh.exec_command(service_check_cmd)
            service_exists = stdout_svc.channel.recv_exit_status() == 0

            if service_exists:
                log(f"[{self.name}] Используется служба 'postgresql' для firewalld.")
                self.run("firewall-cmd --permanent --add-service=postgresql", check=True)
            else:
                log(f"[{self.name}] Служба 'postgresql' не найдена в firewalld, используется порт 5432/tcp.")
                self.run("firewall-cmd --permanent --add-port=5432/tcp", check=True)
            self.run("firewall-cmd --reload", check=True)
            log(f"[{self.name}] Правило firewalld для PostgreSQL добавлено и применено.")
            firewall_configured = True
        else:
            log(f"[{self.name}] firewalld не активен или не установлен.")

        log(f"[{self.name}] Проверка наличия ufw...")
        ufw_exists_cmd = "command -v ufw"
        stdin_ufw_exists, stdout_ufw_exists, stderr_ufw_exists = self.ssh.exec_command(ufw_exists_cmd)
        ufw_exists = stdout_ufw_exists.channel.recv_exit_status() == 0

        if ufw_exists:
            log(f"[{self.name}] Утилита ufw найдена. Проверка статуса...")
            ufw_status_output = self.run("ufw status", check=False, hide_output=True)
            if "Status: active" in ufw_status_output:
                log(f"[{self.name}] Обнаружен активный ufw. Открытие порта 5432/tcp...")
                self.run("ufw allow 5432/tcp comment 'Allow PostgreSQL access'", check=True)
                log(f"[{self.name}] Правило ufw 'allow 5432/tcp' добавлено.")
                firewall_configured = True
            else:
                log(f"[{self.name}] ufw установлен, но не активен.")
        else:
            log(f"[{self.name}] ufw не установлен.")

        if not firewall_configured:
            log(f"[{self.name}] ПРЕДУПРЕЖДЕНИЕ: Не удалось обнаружить и настроить известный межсетевой экран (firewalld/ufw). Порт 5432 может быть недоступен извне.")
        else:
            log(f"[{self.name}] Настройка межсетевого экрана завершена.")

    def check_remote_connection(self, target_host_or_ip: str, user: str, password: str,
                                dbname: str = "postgres") -> None:
        """
        Проверяет удаленное подключение с этого хоста к target_host_or_ip от имени user.
        target_host_or_ip может быть именем хоста или IP-адресом.
        """
        log(f"[{self.name}] Проверка подключения к {target_host_or_ip}:5432 от имени {user}...")
        escaped_password = shlex.quote(password)
        psql_command = shlex.quote(f"SELECT 1")
        # Используем переданное имя хоста или IP в команде psql
        cmd = (f"PGPASSWORD={escaped_password} "
               f"psql -h {target_host_or_ip} -U {user} -d {dbname} -tAqw -c {psql_command}")
        output = self.run(cmd, check=True, hide_output=False)
        if output != "1":
            raise RuntimeError(
                f"Удаленная проверка 'SELECT 1' от {user}@{self.name} к {target_host_or_ip} не удалась. Ожидался вывод '1', получено: '{output}'")
        log(f"[{self.name}] Проверка подключения к {target_host_or_ip} от имени {user} УСПЕШНА (SELECT 1 вернул '1').")

    def close(self) -> None:
        """
        Метод для закрытия соединения SSH
        """
        if self.ssh:
            host_name = self.name
            log(f"[{host_name}] Закрытие SSH-соединения...")

            try:
                self.ssh.close()
                self.ssh = None
                log(f"[{host_name}] SSH-соединение закрыто.")

            except Exception as e:
                log(f"[{host_name}] Ошибка при закрытии SSH соединения: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Удалённая установка и настройка PostgreSQL на менее загружённом из двух серверов.",
        epilog="Пример: ./deploy_postgres.py server1.example.com,198.51.100.27"  # Обновлен пример
    )
    parser.add_argument("hosts", help="Два IP-адреса или DNS-имени через запятую")

    parser.add_argument(
        "--ssh-key",
        default=str(Path.home() / ".ssh" / "id_rsa"),  # Изменено на id_rsa (приватный ключ)
        help="Путь к приватному SSH ключу пользователя root (по умолчанию: ~/.ssh/id_rsa)"
    )
    args = parser.parse_args()

    hosts_raw = [h.strip() for h in args.hosts.split(",") if h.strip()]

    if len(hosts_raw) != 2:
        log(f"Ошибка: необходимо указать ровно два хоста через запятую. Указано: {len(hosts_raw)}")
        sys.exit(1)

    key_path = Path(args.ssh_key).expanduser().resolve()
    log(f"Используется SSH ключ: {key_path}")

    if not key_path.exists():
        log(f"Ошибка: SSH ключ {key_path} не найден.")
        sys.exit(1)

    if not key_path.is_file():
        log(f"Ошибка: Путь к SSH ключу {key_path} не является файлом.")
        sys.exit(1)

    hosts = [Host(name=h) for h in hosts_raw]
    target: Host | None = None
    other: Host | None = None
    student_ip_resolved: str | None = None

    try:
        # --- 1. Сбор информации ---
        log("-" * 30)
        log("Этап 1: Подключение и сбор информации")
        log("-" * 30)

        for h in hosts:
            h.connect(key_path)
            h.detect_os_family()
            h.compute_load()

        # --- 2. Выбор целевого сервера ---
        log("-" * 30)
        log("Этап 2: Выбор целевого сервера")
        log("-" * 30)

        if hosts[0].load_score <= hosts[1].load_score:
            target = hosts[0]
            other = hosts[1]
        else:
            target = hosts[1]
            other = hosts[0]

        log(f"Выбран {target.name} для установки PostgreSQL (нагрузка: {target.load_score:.2f}).")
        log(f"Сервер {other.name} будет использоваться для проверки подключения (нагрузка: {other.load_score:.2f}).")

        try:
            log(f"Разрешение имени хоста {other.name} в IP-адрес для конфигурации pg_hba.conf...")
            student_ip_resolved = socket.gethostbyname(other.name)
            log(f"Имя хоста {other.name} разрешено в IP: {student_ip_resolved}")

        except socket.gaierror as e:
            log(f"Ошибка: Не удалось разрешить имя хоста {other.name} в IP-адрес: {e}")
            raise RuntimeError(f"Невозможно продолжить без IP-адреса для {other.name}") from e

        student_pass = gen_password()
        log(f"Пароль для роли student сгенерирован (будет выведен в конце).")

        # --- 3. Установка и настройка PostgreSQL на target ---
        log("-" * 30)
        log(f"Этап 3: Установка и настройка PostgreSQL на {target.name}")
        log("-" * 30)
        target.install_postgres()
        target.manage_service("postgresql", "enable_and_start")
        target.discover_config_files()
        target.tune_conf()
        target.configure_pg_hba(student_ip_resolved)
        target.create_student_role(student_pass)
        target.manage_service("postgresql", "restart")
        log(f"PostgreSQL на {target.name} установлен, настроен и перезапущен.")

        # --- 4. Настройка межсетевого экрана на target ---
        log("-" * 30)
        log(f"Этап 4: Настройка межсетевого экрана на {target.name}")
        log("-" * 30)
        target.configure_firewall()

        # --- 5. Установка клиента на other и проверка подключения ---
        log("-" * 30)
        log(f"Этап 5: Проверка подключения с {other.name}")
        log("-" * 30)
        log(f"Установка клиента psql на {other.name} (если необходимо)...")
        other.install_psql_client()

        try:
            log(f"Разрешение имени целевого хоста {target.name} в IP-адрес для проверки подключения...")
            target_ip_resolved = socket.gethostbyname(target.name)
            log(f"Имя хоста {target.name} разрешено в IP: {target_ip_resolved}")

        except socket.gaierror as e:
            log(f"Ошибка: Не удалось разрешить имя целевого хоста {target.name} в IP-адрес: {e}")
            raise RuntimeError(f"Невозможно выполнить проверку подключения без IP-адреса для {target.name}") from e

        log(f"Проверка удаленного подключения SELECT 1 с {other.name} на {target.name} ({target_ip_resolved}) от имени student...")
        other.check_remote_connection(target_ip_resolved, "student", student_pass)

    except KeyboardInterrupt:
        log("\nВыполнение прервано пользователем (Ctrl+C).")
        log("Попытка закрыть SSH соединения...")
        for h in hosts:
            if h: h.close()
        sys.exit(130)

    except Exception as e:
        log(f"\n!!! ОШИБКА ВЫПОЛНЕНИЯ СКРИПТА !!!")
        log(traceback.format_exc())
        log(f"Критическая ошибка: {e}")
        log("Попытка закрыть SSH соединения...")
        for h in hosts:
            if h: h.close()
        sys.exit(2)

    finally:
        for h in hosts:
            if h and h.ssh:
                h.close()

    log("=" * 30)
    log("Установка и настройка PostgreSQL завершены УСПЕШНО! ")
    log("=" * 30)
    log(f"PostgreSQL ({target.os_family}) запущен на: {target.name}:5432")
    log(f"Каталог данных (определен по pg_hba.conf): {target.data_dir}")
    log(f"Файл конфигурации postgresql.conf: {target.postgresql_conf_path}")
    log(f"Файл конфигурации pg_hba.conf: {target.pg_hba_conf_path}")
    log(f"Роль 'student' может подключаться с хоста: {other.name} (IP: {student_ip_resolved})")
    log("=" * 30)
    log(f"Для подключения с хоста {other.name}:")
    log(f"psql -h {target.name} -U student -d postgres")
    log(f"Пароль роли student: {student_pass}")
    sys.exit(0)


if __name__ == "__main__":
    main()
