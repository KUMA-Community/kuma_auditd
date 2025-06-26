# kuma_auditd
Скрипт для автоматической настройки отправки событий с Linux-хостов

**Предварительные требования**:
1. Сделать файл kuma_auditd.sh исполняемым:
`chmod +x kuma_auditd_v2.sh`

2. Загрузить на сервер KUMA в папку /opt/ файл с правилами (альтернативный вариант, загрузить файл с правилами на хост, где выполняется запуск скрипта):
`wget -O /opt/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules`

**Параметры запуска скрипта `kuma_auditd`**:
`./kuma_auditd.sh [-ip <KUMA_IP_ADDRESS>] [-p <PORT_NUMBER>] [-tcp|-udp] [/path/file with rules] [-h]`

