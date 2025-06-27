# kuma_auditd
Скрипт для автоматической настройки отправки событий с Linux-хостов.  
Подробнее про настройку `auditd` здесь https://kb.kuma-community.ru/books/podkliucenie-istocnikov/page/nastroika-auditd-na-unix-sistemax и настройку сбора событий с помощью `rsyslog` здесь https://kb.kuma-community.ru/books/podkliucenie-istocnikov/page/sbor-sobytii-auditd-s-pomoshhiu-rsyslog

## Предварительные требования:
1. На хосте Linux установить и запустить службы `rsyslog` и `auditd`.  
   
2. Загрузить на хост Linux файл `kuma_auditd.sh` и сделать его исполняемым:  
```
chmod +x kuma_auditd.sh
```  

3. Загрузить на сервер KUMA (для распределенной архитектуры на сервер коллектора) в папку /opt/ файл с правилами (альтернативный вариант, загрузить файл с правилами на хост, где выполняется запуск скрипта):  
```
wget -O /opt/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
```  

## Параметры запуска скрипта `kuma_auditd.sh`:  
`sudo ./kuma_auditd.sh [-ip <KUMA_IP_ADDRESS>] [-p <PORT_NUMBER>] [-tcp|-udp] [/path/file with rules] [-h]`  

`-kuma_ip` -- IP-адрес сервера (или коллектора) KUMA  
`-port` -- порт сервиса коллектора KUMA, предназначенного для приема и обработки событий auditd  
`-tcp` -- использовать протокол TCP для передачи событий  
`-udp` -- использовать протокол UDP для передачи событий  
`/path/file with rules` -- локальный путь к файлу с правилами аудита (опционально). Если не указан, тогда скрипт выполнит загрузку файла с сервера KUMA  
`-h` -- показать справку  

## Примеры использования:  
- Если отправка событий необходима по протоколу TCP и файл с правилами находится на сервере KUMA:  
```
sudo ./kuma_auditd.sh -kuma_ip 10.10.10.10 -port 5555 -tcp
```  

- Если отправка событий необходима по протоколу UDP и файл с правилами находится в папке со скриптом:  
```
sudo ./kuma_auditd.sh -kuma_ip 10.10.10.10 -port 5555 -udp audit.rules
```  

- Если отправка событий необходима по протоколу TCP и файл с правилами находится в папке /tmp/:  
```
sudo ./kuma_auditd.sh -kuma_ip 10.10.10.10 -port 5555 -tcp /tmp/audit.rules
```
