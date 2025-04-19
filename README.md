# Автоматический установщик и конфигуратор PostgreSQL

**Автор:** Сапрыкин Семён

## Обзор

Этот Python-скрипт автоматизирует развертывание и базовую настройку сервера PostgreSQL на одном из двух указанных удаленных хостов Linux. Он определяет, какой из двух хостов имеет меньшую текущую нагрузку (на основе `loadavg / nproc`), и устанавливает PostgreSQL на этот сервер

Скрипт выполняет следующие ключевые действия:

1.  Подключается к обоим указанным хостам по SSH с привилегиями `root` и аутентификацией по ключу
2.  Определяет семейство ОС (Debian-based или RHEL-based) на каждом хосте
3.  Рассчитывает простой показатель нагрузки для каждого хоста
4.  Выбирает хост с меньшим показателем нагрузки в качестве целевого для установки
5.  На целевом хосте:
    *   Пытается остановить и удалить все существующие установки PostgreSQL
    *   Устанавливает последние доступные в стандартных репозиториях пакеты PostgreSQL сервера и `contrib`
    *   Включает автозагрузку и запускает службу PostgreSQL
    *   Обнаруживает пути к файлам `postgresql.conf` и `pg_hba.conf`
    *   Настраивает `postgresql.conf` для прослушивания на всех сетевых интерфейсах (`listen_addresses = '*'`)
    *   Настраивает `pg_hba.conf` для разрешения подключений для нового пользователя `student` с IP-адреса *другого* хоста, используя аутентификацию по паролю (`md5`)
    *   Создает роль базы данных `student` со случайно сгенерированным безопасным паролем
    *   Перезапускает службу PostgreSQL для применения изменений
    *   Настраивает системный межсетевой экран (`firewalld` или `ufw`, если активен) для разрешения входящих подключений на порт 5432/tcp
7.  **На *другом* хосте:**
    *   Устанавливает пакет клиента `psql`, если он еще не установлен
    *   Выполняет тестовое подключение к только что установленному серверу PostgreSQL на целевом хосте, используя пользователя `student` и сгенерированный пароль
8.  Выводит детали подключения (целевой хост, имя пользователя, пароль) после успешного завершения

## Предварительные требования

1.  **Python:** Python 3.9+ должен быть установлен на машине, с которой вы запускаете скрипт
2.  **Paramiko:** Библиотека Python `paramiko` необходима для операций SSH. Установите ее с помощью pip:

    ```bash
    pip3 install paramiko
    ```

    Или:

    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Целевые хосты:** Два сервера Linux, доступные по SSH.
    *   На целевых хостах требуется доступ в Интернет для загрузки пакетов
4.  **Доступ по SSH:**
    *   **Доступ root:** Скрипту требуется доступ по SSH от имени пользователя `root` к обоим целевым хостам
    *   **Аутентификация по ключу:** На обоих целевых хостах должна быть настроена SSH-аутентификация по ключу для пользователя `root`. Скрипт не поддерживает аутентификацию по паролю
    *   **Приватный ключ SSH:** Вам понадобится соответствующий файл приватного ключа SSH на машине, с которой вы запускаете скрипт

## Установка

1.  Клонируйте этот репозиторий или загрузите скрипт `deploy.py`
2.  Убедитесь, что у вас установлены Python 3 и pip
3.  Установите необходимую библиотеки:
    ```bash
    pip3 install -r requirements.txt
    ```

## Использование

Запустите скрипт с вашей локальной машины, указав имена хостов или IP-адреса двух целевых серверов в виде строки, разделенной запятыми

```bash
chmod +x ./deploy.py
```

```bash
./deploy.py [опции] <хост1>,<хост2>
```

Или:

```bash
python3 deploy.py [опции] <хост1>,<хост2>
```

**Аргументы:**

*   `<хост1>,<хост2>`: Список из ровно двух имен хостов или IP-адресов, разделенных запятой. Не используйте пробелы вокруг запятой
*   `--ssh-key ПУТЬ`: (Необязательный) Указывает путь к файлу приватного ключа SSH, используемого для аутентификации от имени `root` на целевых хостах. (**По умолчанию:** `~/.ssh/id_rsa`)

**Примеры:**

1.  **Использование с указанием доменных имён:**
    ```bash
    ./deploy.py server-alpha.example.com,server-beta.example.com
    ```

2.  **Использование IP-адресов:**
    ```bash
    ./deploy.py 192.168.10.5,192.168.10.6
    ```

3.  **Указание пользовательского приватного ключа SSH:**
    ```bash
    ./deploy.py node1.lab,node2.lab --ssh-key key.key
    ```

**Вывод:**

Скрипт будет логировать свой прогресс в стандартный вывод. После успешного завершения он отобразит:

*   Хост, на котором был установлен PostgreSQL.
*   Обнаруженное семейство ОС и путь к каталогу данных.
*   Пути к конфигурационным файлам (`postgresql.conf`, `pg_hba.conf`).
*   Хост, с которого пользователь `student` может подключаться.
*   Команду для подключения с помощью `psql`.
*   **Случайно сгенерированный пароль для пользователя `student`.**

```
==============================
Установка и настройка PostgreSQL завершены УСПЕШНО!
==============================
PostgreSQL (debian) запущен на: server-beta.example.com:5432
Каталог данных (определен по pg_hba.conf): /etc/postgresql/14/main
Файл конфигурации postgresql.conf: /etc/postgresql/14/main/postgresql.conf
Файл конфигурации pg_hba.conf: /etc/postgresql/14/main/pg_hba.conf
Роль 'student' может подключаться с хоста: server-alpha.example.com (IP: 192.168.10.5)
==============================
Для подключения с хоста server-alpha.example.com:
psql -h server-beta.example.com -U student -d postgres
Пароль роли student: aBcDeFgHiJkLmNoP
```
## Обработка ошибок

Скрипт включает обработку распространенных ошибок, таких как:

*   Указано неверное количество хостов.
*   Файл SSH-ключа не найден или недоступен.
*   Сбои SSH-подключения (тайм-аут, ошибка аутентификации).
*   Ошибки выполнения команд на удаленных хостах (ненулевой код завершения).
*   Не удалось определить ОС или конфигурационные файлы.
*   Не удалось разрешить имена хостов.
*   Сбой теста подключения.

В случае критической ошибки скрипт выведет сообщение об ошибке, покажет traceback, попытается закрыть все открытые SSH-соединения и завершит работу с ненулевым кодом возврата.


## Пример работы скрипта

```
(venv) sonoma@main-vm:~/postgres-devops$ ./deploy_postgres.py debian-server,alma-server

[PostgreInstaller] Используется SSH ключ: /home/sonoma/.ssh/id_rsa
[PostgreInstaller] ------------------------------
[PostgreInstaller] Этап 1: Подключение и сбор информации
[PostgreInstaller] ------------------------------
[PostgreInstaller] [debian-server] Попытка подключения с ключом: /home/sonoma/.ssh/id_rsa
[PostgreInstaller] [debian-server] SSH-подключение успешно.
[PostgreInstaller] [debian-server] Определение семейства ОС...
[PostgreInstaller] [debian-server] Определено семейство ОС: debian
[PostgreInstaller] [debian-server] Расчет средней нагрузки...
[PostgreInstaller] [debian-server] Число ядер=2, LoadAvg1=0.01, Оценка нагрузки=0.01
[PostgreInstaller] [alma-server] Попытка подключения с ключом: /home/sonoma/.ssh/id_rsa
[PostgreInstaller] [alma-server] SSH-подключение успешно.
[PostgreInstaller] [alma-server] Определение семейства ОС...
[PostgreInstaller] [alma-server] Определено семейство ОС: rhel
[PostgreInstaller] [alma-server] Расчет средней нагрузки...
[PostgreInstaller] [alma-server] Число ядер=2, LoadAvg1=0.02, Оценка нагрузки=0.01
[PostgreInstaller] ------------------------------
[PostgreInstaller] Этап 2: Выбор целевого сервера
[PostgreInstaller] ------------------------------
[PostgreInstaller] Выбран debian-server для установки PostgreSQL (нагрузка: 0.01).
[PostgreInstaller] Сервер alma-server будет использоваться для проверки подключения (нагрузка: 0.01).
[PostgreInstaller] Разрешение имени хоста alma-server в IP-адрес для конфигурации pg_hba.conf...
[PostgreInstaller] Имя хоста alma-server разрешено в IP: 10.0.10.12
[PostgreInstaller] Пароль для роли student сгенерирован (будет выведен в конце).
[PostgreInstaller] ------------------------------
[PostgreInstaller] Этап 3: Установка и настройка PostgreSQL на debian-server
[PostgreInstaller] ------------------------------
[PostgreInstaller] [debian-server] Попытка остановить и удалить существующий PostgreSQL...
[PostgreInstaller] [debian-server] Обновление списков пакетов apt...
[PostgreInstaller] [debian-server] Удаление пакетов postgresql*...
[PostgreInstaller] [debian-server] Удаление каталогов /var/lib/postgresql/* и /etc/postgresql/*...
[PostgreInstaller] [debian-server] Установка PostgreSQL...
[PostgreInstaller] [debian-server] Выполняется: DEBIAN_FRONTEND=noninteractive apt-get install -yq postgresql postgresql-contrib
[PostgreInstaller] [debian-server] Установка PostgreSQL завершена.
[PostgreInstaller] [debian-server] Включение и запуск службы postgresql...
[PostgreInstaller] [debian-server] Выполняется: systemctl enable --now postgresql
[PostgreInstaller] [debian-server] Служба postgresql включена и запущена.
[PostgreInstaller] [debian-server] Определение путей к конфигурационным файлам для debian...
[PostgreInstaller] [debian-server] Поиск установленной версии PostgreSQL в /etc/postgresql/...
[PostgreInstaller] [debian-server] Обнаружена версия PostgreSQL: 15
[PostgreInstaller] [debian-server] Проверка существования файла: /etc/postgresql/15/main/postgresql.conf
[PostgreInstaller] [debian-server] Проверка существования файла: /etc/postgresql/15/main/pg_hba.conf
[PostgreInstaller] [debian-server] Пути к конфигурационным файлам успешно определены и проверены.
[PostgreInstaller] [debian-server] postgresql.conf: /etc/postgresql/15/main/postgresql.conf
[PostgreInstaller] [debian-server] pg_hba.conf: /etc/postgresql/15/main/pg_hba.conf
[PostgreInstaller] [debian-server] Каталог: /etc/postgresql/15/main
[PostgreInstaller] [debian-server] Настройка /etc/postgresql/15/main/postgresql.conf...
[PostgreInstaller] [debian-server] Установка listen_addresses = '*'...
[PostgreInstaller] [debian-server] Параметр listen_addresses установлен в '*' в /etc/postgresql/15/main/postgresql.conf
[PostgreInstaller] [debian-server] Настройка /etc/postgresql/15/main/pg_hba.conf...
[PostgreInstaller] [debian-server] Удаление существующих правил для student (10.0.10.12) в /etc/postgresql/15/main/pg_hba.conf...
[PostgreInstaller] [debian-server] Добавление новых правил в /etc/postgresql/15/main/pg_hba.conf...
[PostgreInstaller] [debian-server] Вставка правил pg_hba в начало файла...
[PostgreInstaller] [debian-server] Проверка наличия правил в /etc/postgresql/15/main/pg_hba.conf...
[PostgreInstaller] [debian-server] Правило для student найдено в /etc/postgresql/15/main/pg_hba.conf.
[PostgreInstaller] [debian-server] Создание или обновление роли student...
[PostgreInstaller] [debian-server] Перезапуск службы postgresql для применения настроек...
[PostgreInstaller] [debian-server] Выполняется: systemctl restart postgresql
[PostgreInstaller] [debian-server] Служба postgresql перезапущена.
[PostgreInstaller] PostgreSQL на debian-server установлен, настроен и перезапущен.
[PostgreInstaller] ------------------------------
[PostgreInstaller] Этап 4: Настройка межсетевого экрана на debian-server
[PostgreInstaller] ------------------------------
[PostgreInstaller] [debian-server] Настройка межсетевого экрана...
[PostgreInstaller] [debian-server] Проверка статуса firewalld...
[PostgreInstaller] [debian-server] firewalld не активен или не установлен.
[PostgreInstaller] [debian-server] Проверка наличия ufw...
[PostgreInstaller] [debian-server] ufw не установлен.
[PostgreInstaller] [debian-server] ПРЕДУПРЕЖДЕНИЕ: Не удалось обнаружить и настроить известный межсетевой экран (firewalld/ufw). Порт 5432 может быть недоступен извне.
[PostgreInstaller] ------------------------------
[PostgreInstaller] Этап 5: Проверка подключения с alma-server
[PostgreInstaller] ------------------------------
[PostgreInstaller] Установка клиента psql на alma-server (если необходимо)...
[PostgreInstaller] [alma-server] Проверка и установка клиента psql...
[PostgreInstaller] [alma-server] Пакет postgresql (содержащий клиент) не найден, установка...
[PostgreInstaller] [alma-server] Выполняется: dnf install -y postgresql
[PostgreInstaller] [alma-server] Пакет postgresql установлен.
[PostgreInstaller] Разрешение имени целевого хоста debian-server в IP-адрес для проверки подключения...
[PostgreInstaller] Имя хоста debian-server разрешено в IP: 10.0.10.11
[PostgreInstaller] Проверка удаленного подключения SELECT 1 с alma-server на debian-server (10.0.10.11) от имени student...
[PostgreInstaller] [alma-server] Проверка подключения к 10.0.10.11:5432 от имени student...
[PostgreInstaller] [alma-server] Выполняется: PGPASSWORD=kjWuU2q4SFaHV56g psql -h 10.0.10.11 -U student -d postgres -tAqw -c 'SELECT 1'
[PostgreInstaller] [alma-server] Проверка подключения к 10.0.10.11 от имени student УСПЕШНА (SELECT 1 вернул '1').
[PostgreInstaller] [debian-server] Закрытие SSH-соединения...
[PostgreInstaller] [debian-server] SSH-соединение закрыто.
[PostgreInstaller] [alma-server] Закрытие SSH-соединения...
[PostgreInstaller] [alma-server] SSH-соединение закрыто.
[PostgreInstaller] ==============================
[PostgreInstaller] Установка и настройка PostgreSQL завершены УСПЕШНО! 
[PostgreInstaller] ==============================
[PostgreInstaller] PostgreSQL (debian) запущен на: debian-server:5432
[PostgreInstaller] Каталог данных (определен по pg_hba.conf): /etc/postgresql/15/main
[PostgreInstaller] Файл конфигурации postgresql.conf: /etc/postgresql/15/main/postgresql.conf
[PostgreInstaller] Файл конфигурации pg_hba.conf: /etc/postgresql/15/main/pg_hba.conf
[PostgreInstaller] Роль 'student' может подключаться с хоста: alma-server (IP: 10.0.10.12)
[PostgreInstaller] ==============================
[PostgreInstaller] Для подключения с хоста alma-server:
[PostgreInstaller] psql -h debian-server -U student -d postgres
[PostgreInstaller] Пароль роли student: kjWuU2q4SFaHV56g
```
