#!/bin/bash
#Version 2 (25.06.2025)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_USAGE="\n$(basename "$0") [-ip <KUMA_IP_ADDRESS>] [-p <PORT_NUMBER>] [-tcp|-udp] [/path/file with rules] [-h]\n
Where:
    ${YELLOW}-kuma_ip${NC} -- KUMA IP address
    ${YELLOW}-port${NC} -- use specific port for sending events to KUMA Collector
    ${YELLOW}-tcp${NC} -- use TCP for sending events to KUMA Collector
    ${YELLOW}-udp${NC} -- use UDP for sending events to KUMA Collector
    ${YELLOW}/path/file with rules${NC} -- local auditd rules file (optional). If not specified, the script will download the file from KUMA server
    ${YELLOW}-h${NC} -- show help\n
Example:
    ./kuma_auditd.sh -kuma_ip 10.10.10.10 -port 5555 -tcp
    ./kuma_auditd.sh -kuma_ip 10.10.10.10 -port 5555 -tcp audit.rules
    ./kuma_auditd.sh -kuma_ip 10.10.10.10 -port 5555 -tcp /tmp/audit.rules\n"

# Show usage information if no arguments are given
if [[ $# -eq 0 ]]; then
	echo -e "${RED}Required arguments are missing${NC}"
	echo -e "$SCRIPT_USAGE"
	exit 1
fi

# Checking first parameter
case "$1" in
	"-h")
	    echo -e "$SCRIPT_USAGE"
        exit 1
	;;

    "-kuma_ip")
        if [[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
           KUMA_IP="$2"
        else
           echo -e ""${RED}Wrong IP Address format${NC}""
           exit 1
        fi
        case "$3" in
            "-port")
                if [[ "$4" =~ ^[0-9]{4,5}$ ]]; then
                    KUMA_PORT="$4"
                fi
            ;;
            "-tcp")
                echo -e "${RED}Error: Port number must be specified as the second parameter${NC}"
                echo -e "$SCRIPT_USAGE"
                exit 1
            ;;

            "-udp")
                echo -e "${RED}Error: Port number must be specified as the second parameter${NC}"
                echo -e "$SCRIPT_USAGE"
                exit 1
            ;;

            * )
                echo -e "${RED}Something is wrong here...${NC}"
                echo -e "$SCRIPT_USAGE"
                exit 1
            ;;
        esac
    ;;
    "-port")
        echo -e "${RED}Error: KUMA IP Address must be specified as first parameter${NC}"
        echo -e "$SCRIPT_USAGE"
        exit 1
    ;;
    "-tcp")
        echo -e "${RED}Error: KUMA IP Address must be specified as first parameter${NC}"
        echo -e "$SCRIPT_USAGE"
        exit 1
    ;;

    "-udp")
        echo -e "${RED}Error: KUMA IP Address must be specified as first parameter${NC}"
        echo -e "$SCRIPT_USAGE"
        exit 1
    ;;

    * )
        echo -e "${RED}Something is wrong here...${NC}"
        echo -e "$SCRIPT_USAGE"
        exit 1
    ;; 
esac

# Checking rsyslog status
RSYSLOG_STATUS=$(systemctl is-active rsyslog.service)
if [[ "$RSYSLOG_STATUS" != "active" ]]; then
    echo -e "${RED}Error: rsyslog is not installed or activated (Status: $RSYSLOG_STATUS)${NC}"
    exit 1
fi

echo -e "Checking Rsyslog status - ${GREEN}OK${NC}"

# Checking auditd status
AUDITD_STATUS=$(systemctl is-active auditd.service)
if [[ "$AUDITD_STATUS" != "active" ]]; then
    echo -e "${RED}Error: auditd is not installed or activated (Status: $AUDITD_STATUS)${NC}"
    exit 1
fi

echo -e "Checking Auditd status - ${GREEN}OK${NC}"

# Checking the name_format parameter in /etc/audit/auditd.conf
NAME_FORMAT_CHECKING=$(cat /etc/audit/auditd.conf | grep -oP 'name_format\s*=\s*\K\w+')
if [[ "$NAME_FORMAT_CHECKING" != "NONE" ]]; then
    echo -e "${RED}Parameter 'name_format' in /etc/audit/auditd.conf not 'NONE' (Value: $NAME_FORMAT_CHECKING). Please change it to 'NONE' and restart auditd.service${NC}"
    exit 1
fi

echo -e "Checking the name_format parameter in /etc/audit/auditd.conf - ${GREEN}OK${NC}"

# Creating file audit.conf in /etc/rsyslog.d
# If TCP is used to send events to KUMA Collector
if [[ "$5" == "-tcp" ]]; then
    cat > /etc/rsyslog.d/audit.conf <<EOF
\$ModLoad imfile
\$InputFileName /var/log/audit/audit.log
\$InputFileTag tag_audit_log:
\$InputFileStateFile audit_log
\$InputFileSeverity info
\$InputFileFacility local6
\$InputRunFileMonitor
*.* @@$KUMA_IP:$KUMA_PORT
EOF

# If UDP is used to send events to KUMA Collector
elif [[ "$5" == "-udp" ]]; then
    cat > /etc/rsyslog.d/audit_test.conf <<EOF
\$ModLoad imfile
\$InputFileName /var/log/audit/audit.log
\$InputFileTag tag_audit_log:
\$InputFileStateFile audit_log
\$InputFileSeverity info
\$InputFileFacility local6
\$InputRunFileMonitor
template(name="AuditFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag% %msg%\n")
*.* @$KUMA_IP:$KUMA_PORT;AuditFormat
EOF

# If protocol is missing
else
	echo -e "${RED}Error: Protocol is missing (use -tcp or -udp)${NC}"
	echo -e "$SCRIPT_USAGE"
	exit 1
fi

# Checking file audit.conf was created successfuly
if [ -f "/etc/rsyslog.d/audit.conf" ]; then
    echo -e "Creating file /etc/rsyslog.d/audit.conf - ${GREEN}OK${NC}"
else
    echo -e "${RED}Error: Failed to create audit.conf file${NC}"
    exit 1
fi

# Restart rsyslog service
if  systemctl restart rsyslog.service; then
    echo -e "Restarting rsyslog service - ${GREEN}OK${NC}"
else 
    echo -e "${RED}Error: Failed to restart rsyslog${NC}"
    exit 1
fi

# Adding auditd rules to /etc/audit/rules.d/
# If a local auditd rules file is specified
if [ $# -ge 6 ] && [ -f "$6" ]; then
    if ! cp "$6" /etc/audit/rules.d/; then
        echo -e "${RED}Error: Cannot copy file to /etc/audit/rules.d/${NC}"
        exit 1
    else
        echo -e "Copying auditd rules to /etc/audit/rules.d/ - ${GREEN}OK${NC}"
    fi
else
    # Checking connection to KUMA Server
    if ! ping -c 1 -W 1 "$KUMA_IP" &> /dev/null; then
        echo -e "${RED}Error: Cannot reach KUMA server at $KUMA_IP${NC}"
        exit 1
    else
    # Downloading auditd rules from KUMA Server (default directory is /opt/)
        read -p "Please enter the username to download the file from the KUMA server: " SSH_USER
        echo
    # Using scp to download the file
        if scp "$SSH_USER@$KUMA_IP:/opt/audit.rules" /etc/audit/rules.d/ &> /dev/null; then
            echo -e ""Downloading auditd rules from KUMA Server - ${GREEN}OK${NC}""
        else
            echo -e "${RED}Error: Failed to download the file audit.rules ${NC}" >&2
            exit 1
        fi
    fi
fi

# Adding additional rules from the KUMA KB (https://kb.kuma-community.ru/books/podkliucenie-istocnikov/page/nastroika-auditd-na-unix-sistemax)
cat << EOF >> /etc/audit/rules.d/audit.rules
# root authorized_keys
-w /root/.ssh/authorized_keys -p wa -k rootkey

# motd audit
-w /etc/update-motd.d/ -p wa -k motd

# udev audit
-w /etc/udev/rules.d/ -p wa -k udev

# xdg audit
-w /etc/xdg/autostart/ -p wa -k xdg
-w /usr/share/autostart/ -p wa -k xdg

# Package Manager (APT/YUM/DNF)
-w /etc/yum/pluginconf.d/ -p wa -k package_man
-w /etc/apt/apt.conf.d/ -p wa -k package_man
-w /etc/dnf/plugins/dnfcon.conf -p wa -k package_man

# exta systemd
-w /usr/lib/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd
-w /usr/local/lib/systemd/ -p wa -k systemd
-w /usr/local/share/systemd/user -p wa -k systemd_user
-w /usr/share/systemd/user  -p wa -k systemd_user

# setcap audit
-w /usr/sbin/setcap -p x -k setcap

# rc audit 
-w /etc/rc.local -p wa -k rclocal  

## extra Shell/profile configurations
-w /etc/bash.bashrc -p wa -k shell_profiles
-w /etc/bash.bash_logout -p wa -k shell_profiles
-w /root/.profile -p wa -k shell_profiles
-w /root/.bashrc -p wa -k shell_profiles
-w /root/.bash_logout -p wa -k shell_profiles
-w /root/.bash_profile -p wa -k shell_profiles
-w /root/.bash_login -p wa -k shell_profiles

# extra search files
-w /usr/bin/find -p x -k T1083_File_And_DIrectory_Discovery

## Kernel Related Events
-w /usr/sbin/modprobe -p x -k T1547_Boot_or_Logon_Autostart_Execution
-w /usr/sbin/insmod -p x -k T1547_Boot_or_Logon_Autostart_Execution
-w /usr/sbin/lsmod -p x -k T1547_Boot_or_Logon_Autostart_Execution
-w /usr/sbin/rmmod -p x -k T1547_Boot_or_Logon_Autostart_Execution
-w /usr/sbin/modinfo -p x -k T1547_Boot_or_Logon_Autostart_Execution
-w /etc/modprobe.conf -p wa -k T1547.006_6
-w /etc/sysctl.conf -p wa -k sysctl

# extra file manipulation
-w /usr/bin/ftp -p x -k T1105_remote_file_copy
-w /usr/bin/sftp -p x -k T1105_remote_file_copy
-w /usr/bin/rsync -p x -k T1105_remote_file_copy
-w /usr/bin/cp -p x -k T1005_Data_from_Local_System
-w /usr/bin/dd -p x -k T1005_Data_from_Local_System
-a always,exit -F arch=b32 -S execve -S execveat -F exe=/usr/bin/shred -F -k T1070.004_1
-a always,exit -F arch=b64 -S execve -S execveat -F exe=/usr/bin/shred -F -k T1070.004_2

# split cmd audit
-w /usr/bin/split -p x -k split

EOF

echo -e "Adding additional rules from the KUMA KB - ${GREEN}OK${NC}"

# Restart auditd service
if  systemctl restart auditd.service; then
    echo -e "Restarting auditd service - ${GREEN}OK${NC}"
else 
    echo -e "${RED}Error: Failed to restart auditd${NC}"
    exit 1
fi

# Checking if the audit.log file is filling up
AUDITD_LOG_FILE="/var/log/audit/audit.log"

# Get current file size
INITIAL_SIZE=$(stat -c %s "$AUDITD_LOG_FILE")

# Waiting 2 seconds
sleep 2

# Checking size difference (before/after)
CURRENT_SIZE=$(stat -c %s "$AUDITD_LOG_FILE")

if [ "$INITIAL_SIZE" -lt "$CURRENT_SIZE" ]; then
    echo -e "Audit logs are successfully written to the $AUDITD_LOG_FILE - ${GREEN}OK${NC}"
else
    echo -e "${RED}Error: Audit logs are not being written to the $AUDITD_LOG_FILE ${NC}" >&2
    exit 1
fi