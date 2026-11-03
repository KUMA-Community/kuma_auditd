# kuma_auditd

Скрипт автоматизации настройки демона аудита (`auditd`) на Linux-хостах и отправки событий безопасности в коллектор SIEM-системы **Kaspersky Unified Monitoring and Analysis Platform (KUMA)** с использованием `rsyslog` или `syslog-ng`.

## Основные возможности (v3)

* **Поддержка IPv4 и FQDN:** Возможность указать, как IP-адрес, так и доменное имя (FQDN) коллектора KUMA через флаг `-kuma_host` (или `-kuma_ip` для обратной совместимости).
* **Гибкий выбор транспорта и демона логирования:** Поддержка протоколов `UDP`, `TCP` и `TCP + TLS` (с верификацией сертификата коллектора или без нее) для `rsyslog` и `syslog-ng`.
* **Интерактивная проверка DNS / `/etc/hosts`:** Автоматическая проверка разрешения FQDN с предложением добавить запись в `/etc/hosts` (с созданием резервной копии `/etc/hosts.backup`), если имя не резолвится.
* **Маршрутизация событий на основании тега:** Строгая фильтрация по тегу `auditd` (с остановкой дальнейшей обработки `& stop` в `rsyslog`), исключающая пересылку лишних системных логов на коллектор и их дублирование в `/var/log/syslog`.
* **Автоматическая настройка `auditd.conf`:** Проверка параметра `name_format = NONE` и автоматическое переключение `log_format` из `RAW` в `ENRICHED` с сохранением бэкапа.
* **Настройка источника правил `auditd`:** Поддержка локального файла правил или автоматическое скачивание `/opt/audit.rules` с сервера KUMA по `scp` (с предварительной проверкой доступности порта `22/TCP`), а также добавление расширенных правил из базы знаний KUMA без создания дубликатов при повторных запусках.
* **Проверка синтаксиса и доставки:** Валидация конфигурации (`syslog-ng -s` / `rsyslogd -N1`), проверка доступности TCP-порта коллектора, автоматическая загрузка правил через `augenrules --load` и проверка наполняемости `/var/log/audit/audit.log`.

---

## Требования

* Права суперпользователя (`root`).
* Установленный и активный демон `auditd` (`auditd.service`).
* Установленный и активный демон `rsyslog` (`rsyslog.service`) или `syslog-ng` (`syslog-ng.service`).
* Для работы поверх **TLS**:
  * При использовании `rsyslog`: установленный пакет `rsyslog-gnutls`.
  * При использовании верификации сертификата (`-tls_ca`): установленная утилита `openssl` и корневой/промежуточный сертификат CA в формате PEM.

---

## Параметры запуска

```text
./kuma_auditd.sh -kuma_host <IP_OR_FQDN> -port <PORT_NUMBER> -tcp|-udp -rsyslog|-syslog_ng [-tls] [-tls_ca <CA_FILE>] [-tls_peer <NAME>] [/path/file with rules] [-h]
```

| Параметр | Обязательный | Описание |
| :--- | :---: | :--- |
| `-kuma_host` (или `-kuma_ip`) | Да | IPv4-адрес или FQDN коллектора KUMA. При использовании `syslog-ng` с `-tls_ca` рекомендуется указывать FQDN, соответствующий CN/SAN сертификата коллектора. |
| `-port` | Да | Порт коллектора KUMA (`1–65535`). |
| `-tcp` / `-udp` | Да | Протокол транспортного уровня (взаимоисключающие флаги). |
| `-rsyslog` / `-syslog_ng` | Да | Используемый системный демон логирования (взаимоисключающие флаги). |
| `-tls` | Нет | Включение шифрования TLS (требует флага `-tcp`). |
| `-tls_ca < путь >` | Нет | Путь к PEM-файлу CA-сертификата для проверки подлинности коллектора KUMA (требует `-tls`). Если не указан, используется шифрование без проверки сертификата. |
| `-tls_peer < имя >` | Условно | FQDN/CN из сертификата коллектора KUMA (используется в `rsyslog` при указании `-tls_ca`). Если в `-kuma_host` уже передан FQDN, подставляется автоматически. |
| `/path/to/audit.rules` | Нет | Путь к локальному файлу правил `auditd`. Если не указан, скрипт предложит скачать правила из директории `/opt/audit.rules` с сервера KUMA по `scp`. |
| `-h` | Нет | Вывод справки по использованию скрипта. |

---

## Примеры использования

### 1. Базовая отправка по TCP или UDP (без TLS)

Отправка через **rsyslog** по TCP (правила скачиваются с сервера KUMA):
```bash
sudo ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -tcp -rsyslog
```

Отправка через **syslog-ng** по TCP с использованием локального файла правил:
```bash
sudo ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -syslog_ng ./audit.rules
```

Отправка через **syslog-ng** по UDP с указанием полного пути к правилам:
```bash
sudo ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -udp -syslog_ng /tmp/audit.rules
```

### 2. Отправка по TCP + TLS без проверки сертификата коллектора

Через **rsyslog** (режим `anon`):
```bash
sudo ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -tcp -rsyslog -tls
```

Через **syslog-ng** (режим `peer-verify(required-untrusted)`):
```bash
sudo ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -syslog_ng -tls
```

### 3. Отправка по TCP + TLS с проверкой сертификата (CA Validation)

Через **syslog-ng** (режим `peer-verify(required-trusted)`, целевой адрес должен совпадать с FQDN в сертификате коллектора):
```bash
sudo ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -syslog_ng -tls -tls_ca /root/core-internal-ca.cert /tmp/audit.rules
```

Через **rsyslog** по FQDN (`-tls_peer` определится автоматически как `kuma.example.local`):
```bash
sudo ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -rsyslog -tls -tls_ca /tmp/core-internal-ca.cert
```

Через **rsyslog** по IP-адресу с явным указанием имени пира (`-tls_peer`):
```bash
sudo ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -tcp -rsyslog -tls -tls_ca /tmp/core-internal-ca.cert -tls_peer kuma.example.local
```

---

## Что делает скрипт пошагово

1. **Валидация входных параметров:** Проверяет корректность IPv4/FQDN, диапазона портов, совместимость флагов (`-tls` только с `-tcp`, наличие файла `-tls_ca`).
2. **Проверка разрешения имени и сети:**
   * Если передан FQDN, проверяет его через системный резолвер (`getent ahosts`). При неудаче интерактивно предлагает добавить связку `IP -> FQDN` в `/etc/hosts`.
   * При выборе TCP или TLS проверяет доступность целевого порта коллектора KUMA (`$KUMA_PORT`).
3. **Проверка служб и конфигурации `auditd`:**
   * Убеждается, что выбранный демон логирования и `auditd.service` активны.
   * Проверяет наличие `name_format = NONE` в `/etc/audit/auditd.conf`.
   * Если `log_format = RAW`, сохраняет бэкап `/etc/audit/auditd.conf.backup` и меняет значение на `ENRICHED`.
4. **Настройка `rsyslog` / `syslog-ng`:**
   * Переименовывает предыдущие конфигурационные файлы скрипта в `*.backup`, чтобы избежать дублирующей отправки событий.
   * Для `syslog-ng` с `-tls_ca` копирует сертификат в `/etc/syslog-ng/cert/` и создает символическую ссылку по хешу `openssl x509 -hash`.
   * Генерирует целевой конфигурационный файл, проверяет синтаксис и перезапускает службу логирования.
5. **Установка правил `auditd`:**
   * Копирует указанный локальный файл правил в `/etc/audit/rules.d/audit.rules` или скачивает `/opt/audit.rules` с коллектора KUMA по `scp`.
   * Дописывает дополнительные правила из [Базы знаний KUMA](https://kb.kuma-community.ru/books/podkliucenie-istocnikov/page/nastroika-auditd-na-unix-sistemax), предварительно фильтруя уже существующие правила для защиты от дубликатов.
   * Применяет правила через `augenrules --load` и перезапускает `auditd` (поддерживается как `systemctl`, так и `service auditd restart`).
6. **Контроль записи логов:** Сравнивает размер `/var/log/audit/audit.log` с интервалом в 10 секунд, подтверждая фактическую запись событий аудита.
