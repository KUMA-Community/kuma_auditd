#!/bin/bash
#Version 3 (03.11.2026)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SCRIPT_USAGE="\n$(basename "$0") -kuma_host <IP_OR_FQDN> -port <PORT_NUMBER> -tcp|-udp -rsyslog|-syslog_ng [-tls] [-tls_ca <CA_FILE>] [-tls_peer <NAME>] [/path/file with rules] [-h]\n
Where:
    ${YELLOW}-kuma_host${NC} (or ${YELLOW}-kuma_ip${NC}) -- KUMA Collector IPv4 address or FQDN
    ${YELLOW}-port${NC} -- use specific port for sending events to KUMA Collector
    ${YELLOW}-tcp${NC} -- use TCP for sending events to KUMA Collector
    ${YELLOW}-udp${NC} -- use UDP for sending events to KUMA Collector
    ${YELLOW}-rsyslog${NC} -- use rsyslog for sending auditd events to KUMA Collector
    ${YELLOW}-syslog_ng${NC} -- use syslog-ng for sending auditd events to KUMA Collector
    ${YELLOW}-tls${NC} -- send events over TLS (requires -tcp)
    ${YELLOW}-tls_ca${NC} <file> -- PEM CA certificate to validate the KUMA Collector certificate (optional; omit for TLS without certificate validation)
    ${YELLOW}-tls_peer${NC} <name> -- FQDN/CN from the KUMA Collector certificate (for rsyslog with -tls_ca; defaults to -kuma_host if FQDN is used)
    ${YELLOW}/path/file with rules${NC} -- local auditd rules file (optional). If not specified, the script will download the file from KUMA server
    ${YELLOW}-h${NC} -- show help\n
Example:
    ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -tcp -rsyslog
    ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -syslog_ng audit.rules
    ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -udp -syslog_ng /tmp/audit.rules
    ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -tcp -rsyslog -tls
    ./kuma_auditd.sh -kuma_host 10.10.10.10 -port 5555 -tcp -rsyslog -tls -tls_ca /root/ca.crt -tls_peer kuma.example.local
    ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -syslog_ng -tls
    ./kuma_auditd.sh -kuma_host kuma.example.local -port 5555 -tcp -syslog_ng -tls -tls_ca /root/ca.crt\n"

# Functions for validation IPv4 and FQDN/Hostname
is_valid_ipv4() {
    local ip="$1"
    local IFS='.'
    local -a octets
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
    return 0
}

is_valid_fqdn() {
    local host="$1"
    [[ ${#host} -le 253 ]] || return 1
    [[ "$host" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]] || return 1
    return 0
}

is_fqdn_resolvable() {
    local host="$1"
    if command -v getent &> /dev/null; then
        getent ahosts "$host" &> /dev/null
        return $?
    else
        ping -c 1 -W 1 "$host" &> /dev/null
        return $?
    fi
}

is_ssh_reachable() {
    local host="$1"
    local port="${2:-22}"
    timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" &> /dev/null
    return $?
}

is_port_reachable() {
    local host="$1"
    local port="$2"
    timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" &> /dev/null
    return $?
}

# Appends auditd rules from stdin to the target file without duplicating existing rules
append_kb_rules_safely() {
    local target_file="$1"
    local added_count=0
    local skipped_count=0
    local line norm_line

    touch "$target_file"

    declare -A existing_rules
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        read -r norm_line <<< "$line"
        existing_rules["$norm_line"]=1
    done < "$target_file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*(#|$) ]]; then
            if ! grep -Fxq "$line" "$target_file" 2>/dev/null; then
                echo "$line" >> "$target_file"
            fi
            continue
        fi

        read -r norm_line <<< "$line"
        if [[ -z "${existing_rules["$norm_line"]}" ]]; then
            echo "$line" >> "$target_file"
            existing_rules["$norm_line"]=1
            ((added_count++))
        else
            ((skipped_count++))
        fi
    done

    echo -e "Adding additional rules from the KUMA KB (Added: $added_count, Skipped duplicates: $skipped_count) - ${GREEN}OK${NC}"
}

# Show usage information if no arguments are given
if [[ $# -eq 0 ]]; then
    echo -e "${RED}Required arguments are missing${NC}"
    echo -e "$SCRIPT_USAGE"
    exit 1
fi

KUMA_HOST=""
IS_FQDN=0
KUMA_PORT=""
PROTO=""
SYSLOG_DAEMON=""
RULES_FILE=""
TLS=0
TLS_CA=""
TLS_PEER=""

# Parsing arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        "-h")
            echo -e "$SCRIPT_USAGE"
            exit 1
        ;;

        "-kuma_ip"|"-kuma_host")
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: $1 requires an IP address or FQDN${NC}"
                exit 1
            fi
            if is_valid_ipv4 "$2"; then
                KUMA_HOST="$2"
                IS_FQDN=0
                shift 2
            elif is_valid_fqdn "$2"; then
                KUMA_HOST="$2"
                IS_FQDN=1
                shift 2
            else
                echo -e "${RED}Error: Wrong IPv4 address or FQDN format: $2${NC}"
                exit 1
            fi
        ;;

        "-port")
            if [[ "$2" =~ ^[0-9]{1,5}$ ]] && (( 10#$2 >= 1 && 10#$2 <= 65535 )); then
                KUMA_PORT="$2"
                shift 2
            else
                echo -e "${RED}Wrong port number (must be 1-65535)${NC}"
                exit 1
            fi
        ;;

        "-tcp"|"-udp")
            NEW_PROTO="${1#-}"
            if [[ -n "$PROTO" && "$PROTO" != "$NEW_PROTO" ]]; then
                echo -e "${RED}Error: use either -tcp or -udp, not both${NC}"
                exit 1
            fi
            PROTO="$NEW_PROTO"
            shift
        ;;

        "-rsyslog"|"-syslog_ng")
            NEW_DAEMON="${1#-}"
            if [[ -n "$SYSLOG_DAEMON" && "$SYSLOG_DAEMON" != "$NEW_DAEMON" ]]; then
                echo -e "${RED}Error: use either -rsyslog or -syslog_ng, not both${NC}"
                exit 1
            fi
            SYSLOG_DAEMON="$NEW_DAEMON"
            shift
        ;;

        "-tls")
            TLS=1
            shift
        ;;

        "-tls_ca")
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: -tls_ca requires a path to a CA certificate file${NC}"
                exit 1
            fi
            TLS_CA="$2"
            shift 2
        ;;

        "-tls_peer")
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: -tls_peer requires a value${NC}"
                exit 1
            fi
            TLS_PEER="$2"
            shift 2
        ;;

        -*)
            echo -e "${RED}Unknown argument: $1${NC}"
            echo -e "$SCRIPT_USAGE"
            exit 1
        ;;

        *)
            RULES_FILE="$1"
            shift
        ;;
    esac
done

# Checking that all required arguments are specified
if [[ -z "$KUMA_HOST" ]]; then
    echo -e "${RED}Error: KUMA Collector IP or FQDN must be specified (-kuma_host or -kuma_ip)${NC}"
    echo -e "$SCRIPT_USAGE"
    exit 1
fi

if [[ -z "$KUMA_PORT" ]]; then
    echo -e "${RED}Error: Port number must be specified (-port)${NC}"
    echo -e "$SCRIPT_USAGE"
    exit 1
fi

if [[ -z "$PROTO" ]]; then
    echo -e "${RED}Error: Protocol is missing (use -tcp or -udp)${NC}"
    echo -e "$SCRIPT_USAGE"
    exit 1
fi

if [[ -z "$SYSLOG_DAEMON" ]]; then
    echo -e "${RED}Error: Syslog daemon is missing (use -rsyslog or -syslog_ng)${NC}"
    echo -e "$SCRIPT_USAGE"
    exit 1
fi

# Checking TLS-related arguments
if [[ -n "$TLS_CA" && "$TLS" -ne 1 ]]; then
    echo -e "${RED}Error: -tls_ca requires -tls${NC}"
    exit 1
fi

if [[ -n "$TLS_PEER" && "$TLS" -ne 1 ]]; then
    echo -e "${RED}Error: -tls_peer requires -tls${NC}"
    exit 1
fi

if [[ "$TLS" -eq 1 ]]; then
    if [[ "$PROTO" != "tcp" ]]; then
        echo -e "${RED}Error: -tls requires -tcp (TLS transport is not supported over UDP)${NC}"
        exit 1
    fi

    if [[ -n "$TLS_CA" && ! -f "$TLS_CA" ]]; then
        echo -e "${RED}Error: CA certificate file $TLS_CA not found${NC}"
        exit 1
    fi

    if [[ "$SYSLOG_DAEMON" == "rsyslog" && -n "$TLS_CA" ]]; then
        if [[ -z "$TLS_PEER" ]]; then
            if [[ "$IS_FQDN" -eq 1 ]]; then
                TLS_PEER="$KUMA_HOST"
                echo -e "${YELLOW}Info: -tls_peer not specified, using FQDN '$KUMA_HOST' for certificate validation${NC}"
            else
                echo -e "${RED}Error: -tls_peer must be specified together with -tls_ca for rsyslog when an IP address is used (FQDN/CN from the KUMA Collector certificate)${NC}"
                exit 1
            fi
        fi
    fi

    if [[ "$SYSLOG_DAEMON" == "syslog_ng" && -n "$TLS_CA" && "$IS_FQDN" -eq 0 ]]; then
        echo -e "${YELLOW}Warning: You specified an IP address ($KUMA_HOST) with syslog-ng TLS validation. syslog-ng strictly matches the target address against the certificate CN/SAN. If the collector certificate only contains an FQDN, event forwarding will fail.${NC}"
    fi

    if [[ -n "$TLS_CA" ]] && ! command -v openssl &> /dev/null; then
        echo -e "${RED}Error: openssl is required to configure TLS with certificate validation${NC}"
        exit 1
    fi
fi

# Checking FQDN resolution and offering to add an entry to /etc/hosts if unresolved
if [[ "$IS_FQDN" -eq 1 ]]; then
    if is_fqdn_resolvable "$KUMA_HOST"; then
        echo -e "Resolving FQDN $KUMA_HOST - ${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Warning: FQDN '$KUMA_HOST' cannot be resolved via DNS or /etc/hosts.${NC}"
        while true; do
            read -r -p "Would you like to add an entry for '$KUMA_HOST' to /etc/hosts? (yes/no): " ADD_HOSTS_ANS
            case "${ADD_HOSTS_ANS,,}" in
                yes|y)
                    while true; do
                        read -r -p "Please enter the IPv4 address for $KUMA_HOST: " TARGET_IP
                        if is_valid_ipv4 "$TARGET_IP"; then
                            [[ -f /etc/hosts.backup ]] || cp /etc/hosts /etc/hosts.backup
                            if grep -Eq "^[[:space:]]*[^#].*[[:space:]]+${KUMA_HOST}([[:space:]]+|$)" /etc/hosts; then
                                sed -i -E "s|^([[:space:]]*)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+([[:space:]]+.*\<${KUMA_HOST}\>)|\1${TARGET_IP}\2|" /etc/hosts
                            else
                                printf "%s\t%s\n" "$TARGET_IP" "$KUMA_HOST" >> /etc/hosts
                            fi

                            if is_fqdn_resolvable "$KUMA_HOST"; then
                                echo -e "Adding '$TARGET_IP $KUMA_HOST' to /etc/hosts and verifying resolution - ${GREEN}OK${NC}"
                            else
                                echo -e "${RED}Error: Added '$TARGET_IP $KUMA_HOST' to /etc/hosts, but resolution still failed${NC}"
                                exit 1
                            fi
                            break
                        else
                            echo -e "${RED}Invalid IPv4 address format: '$TARGET_IP'. Please try again.${NC}"
                        fi
                    done
                    break
                    ;;
                no|n)
                    echo -e "${YELLOW}Skipping /etc/hosts modification. Proceeding without FQDN resolution...${NC}"
                    break
                    ;;
                *)
                    echo -e "${YELLOW}Please answer 'yes' or 'no'.${NC}"
                    ;;
            esac
        done
    fi
fi

# Checking TCP reachability of KUMA Collector port before configuring/restarting logging daemon
if [[ "$PROTO" == "tcp" || "$TLS" -eq 1 ]]; then
    if is_port_reachable "$KUMA_HOST" "$KUMA_PORT"; then
        echo -e "Checking KUMA collector reachability on $KUMA_HOST:$KUMA_PORT (TCP) - ${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Warning: Cannot establish TCP connection to KUMA collector at $KUMA_HOST:$KUMA_PORT. Check network, firewall rules, or collector status. Continuing anyway...${NC}"
    fi
fi

# Checking status of the selected syslog daemon
if [[ "$SYSLOG_DAEMON" == "rsyslog" ]]; then
    SYSLOG_SERVICE="rsyslog.service"
    SYSLOG_NAME="Rsyslog"
else
    SYSLOG_SERVICE="syslog-ng.service"
    SYSLOG_NAME="Syslog-ng"
fi

SYSLOG_STATUS=$(systemctl is-active "$SYSLOG_SERVICE")
if [[ "$SYSLOG_STATUS" != "active" ]]; then
    echo -e "${RED}Error: $SYSLOG_DAEMON is not installed or activated (Status: $SYSLOG_STATUS)${NC}"
    exit 1
fi

echo -e "Checking $SYSLOG_NAME status - ${GREEN}OK${NC}"

# Checking auditd status
AUDITD_STATUS=$(systemctl is-active auditd.service)
if [[ "$AUDITD_STATUS" != "active" ]]; then
    echo -e "${RED}Error: auditd is not installed or activated (Status: $AUDITD_STATUS)${NC}"
    exit 1
fi

echo -e "Checking Auditd status - ${GREEN}OK${NC}"

# Checking the name_format parameter in /etc/audit/auditd.conf
NAME_FORMAT_CHECKING=$(grep -oP '^\s*name_format\s*=\s*\K\w+' /etc/audit/auditd.conf)
if [[ "$NAME_FORMAT_CHECKING" != "NONE" ]]; then
    echo -e "${RED}Parameter 'name_format' in /etc/audit/auditd.conf not 'NONE' (Value: $NAME_FORMAT_CHECKING). Please change it to 'NONE' and restart auditd.service${NC}"
    exit 1
fi

echo -e "Checking the name_format parameter in /etc/audit/auditd.conf - ${GREEN}OK${NC}"

# Checking the log_format parameter in /etc/audit/auditd.conf
LOG_FORMAT_CHECKING=$(grep -oP '^\s*log_format\s*=\s*\K\w+' /etc/audit/auditd.conf)
if [[ "${LOG_FORMAT_CHECKING^^}" == "RAW" ]]; then
    [ -f /etc/audit/auditd.conf.backup ] || cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup

    sed -i -E 's/^([[:space:]]*log_format[[:space:]]*=[[:space:]]*)RAW([[:space:]]*)$/\1ENRICHED\2/I' /etc/audit/auditd.conf

    LOG_FORMAT_CHECKING=$(grep -oP '^\s*log_format\s*=\s*\K\w+' /etc/audit/auditd.conf)
    if [[ "${LOG_FORMAT_CHECKING^^}" != "ENRICHED" ]]; then
        echo -e "${RED}Error: Failed to change 'log_format' from RAW to ENRICHED in /etc/audit/auditd.conf${NC}"
        exit 1
    fi

    echo -e "Changing the log_format parameter in /etc/audit/auditd.conf from RAW to ENRICHED - ${GREEN}OK${NC}"
elif [[ -z "$LOG_FORMAT_CHECKING" ]]; then
    echo -e "${YELLOW}Parameter 'log_format' is not set in /etc/audit/auditd.conf, leaving it unchanged${NC}"
else
    echo -e "Checking the log_format parameter in /etc/audit/auditd.conf (Value: $LOG_FORMAT_CHECKING) - ${GREEN}OK${NC}"
fi

backup_other_configs() {
    local dir="$1"; shift
    local keep="$1"; shift
    local name
    for name in "$@"; do
        if [[ "$name" != "$keep" && -f "$dir/$name" ]]; then
            mv "$dir/$name" "$dir/$name.backup"
            echo -e "${YELLOW}Found $dir/$name - renamed to $dir/$name.backup${NC}"
        fi
    done
}

# Creating the configuration file for the selected syslog daemon
if [[ "$SYSLOG_DAEMON" == "rsyslog" ]]; then

    RSYSLOG_CONF_NAMES=("audit.conf" "50-auditd-tls.conf")

    if [[ "$TLS" -eq 1 ]]; then
        SYSLOG_CONF_FILE="/etc/rsyslog.d/50-auditd-tls.conf"
    else
        SYSLOG_CONF_FILE="/etc/rsyslog.d/audit.conf"
    fi

    backup_other_configs "/etc/rsyslog.d" "$(basename "$SYSLOG_CONF_FILE")" "${RSYSLOG_CONF_NAMES[@]}"

    if [[ "$TLS" -eq 1 ]]; then

        if ! { dpkg -s rsyslog-gnutls &> /dev/null || rpm -q rsyslog-gnutls &> /dev/null; }; then
            echo -e "${YELLOW}Warning: could not confirm the rsyslog-gnutls (or equivalent) package is installed. If TLS fails to start, install it, e.g.: apt install rsyslog-gnutls${NC}"
        fi

        if [[ -n "$TLS_CA" ]]; then
            mkdir -p /etc/rsyslog
            if ! cp "$TLS_CA" /etc/rsyslog/ca.crt; then
                echo -e "${RED}Error: Cannot copy $TLS_CA to /etc/rsyslog/ca.crt${NC}"
                exit 1
            fi
            cat > "$SYSLOG_CONF_FILE" <<EOF
module(load="imfile")
module(load="omfwd")
module(load="gtls")

\$DefaultNetstreamDriver gtls
\$ActionSendStreamDriverMode 1
\$ActionSendStreamDriverAuthMode x509/name
\$ActionSendStreamDriverPermittedPeer $TLS_PEER
\$DefaultNetstreamDriverCAFile /etc/rsyslog/ca.crt

\$InputFileName /var/log/audit/audit.log
\$InputFileTag auditd:
\$InputFileStateFile audit_log
\$InputFileSeverity info
\$InputFileFacility local6
\$InputRunFileMonitor

if \$programname == 'auditd' then @@$KUMA_HOST:$KUMA_PORT
& stop
EOF
        else
            cat > "$SYSLOG_CONF_FILE" <<EOF
module(load="imfile")
module(load="omfwd")
module(load="gtls")

\$DefaultNetstreamDriver gtls
\$ActionSendStreamDriverMode 1
\$ActionSendStreamDriverAuthMode anon

\$InputFileName /var/log/audit/audit.log
\$InputFileTag auditd:
\$InputFileStateFile audit_log
\$InputFileSeverity info
\$InputFileFacility local6
\$InputRunFileMonitor

if \$programname == 'auditd' then @@$KUMA_HOST:$KUMA_PORT
& stop
EOF
        fi

    else

        if [[ "$PROTO" == "tcp" ]]; then
            cat > "$SYSLOG_CONF_FILE" <<EOF
module(load="imfile")
\$InputFileName /var/log/audit/audit.log
\$InputFileTag auditd:
\$InputFileStateFile audit_log
\$InputFileSeverity info
\$InputFileFacility local6
\$InputRunFileMonitor
if \$programname == 'auditd' then @@$KUMA_HOST:$KUMA_PORT
& stop
EOF
        else
            cat > "$SYSLOG_CONF_FILE" <<EOF
module(load="imfile")
\$InputFileName /var/log/audit/audit.log
\$InputFileTag auditd:
\$InputFileStateFile audit_log
\$InputFileSeverity info
\$InputFileFacility local6
\$InputRunFileMonitor
template(name="AuditFormat" type="string" string="<%PRI%>%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag% %msg%\n")
if \$programname == 'auditd' then @$KUMA_HOST:$KUMA_PORT;AuditFormat
& stop
EOF
        fi

    fi

else

    SYSLOG_CONF_DIR="/etc/syslog-ng/conf.d"
    SYSLOGNG_CONF_NAMES=("30-kuma-tcp.conf" "30-kuma-udp.conf" "30-kuma-tcp-tls-wo-cert-validation.conf" "30-kuma-tls-validation.conf")

    if ! grep -Eq '^[[:space:]]*@include.*conf\.d' /etc/syslog-ng/syslog-ng.conf 2>/dev/null; then
        echo -e "${RED}Error: /etc/syslog-ng/syslog-ng.conf does not include $SYSLOG_CONF_DIR. Add the line: @include \"$SYSLOG_CONF_DIR/*.conf\"${NC}"
        exit 1
    fi

    mkdir -p "$SYSLOG_CONF_DIR"

    if [[ "$TLS" -eq 1 && -n "$TLS_CA" ]]; then
        SYSLOG_CONF_FILE="$SYSLOG_CONF_DIR/30-kuma-tls-validation.conf"
    elif [[ "$TLS" -eq 1 ]]; then
        SYSLOG_CONF_FILE="$SYSLOG_CONF_DIR/30-kuma-tcp-tls-wo-cert-validation.conf"
    else
        SYSLOG_CONF_FILE="$SYSLOG_CONF_DIR/30-kuma-$PROTO.conf"
    fi

    backup_other_configs "$SYSLOG_CONF_DIR" "$(basename "$SYSLOG_CONF_FILE")" "${SYSLOGNG_CONF_NAMES[@]}"

    if [[ "$TLS" -eq 1 && -n "$TLS_CA" ]]; then

        mkdir -p /etc/syslog-ng/cert
        CA_BASENAME="$(basename "$TLS_CA")"
        if ! cp "$TLS_CA" "/etc/syslog-ng/cert/$CA_BASENAME"; then
            echo -e "${RED}Error: Cannot copy $TLS_CA to /etc/syslog-ng/cert/$CA_BASENAME${NC}"
            exit 1
        fi
        CA_HASH=$(openssl x509 -noout -hash -in "/etc/syslog-ng/cert/$CA_BASENAME")
        if [[ -z "$CA_HASH" ]]; then
            echo -e "${RED}Error: Failed to compute the hash of $CA_BASENAME with openssl${NC}"
            exit 1
        fi
        ln -sf "$CA_BASENAME" "/etc/syslog-ng/cert/$CA_HASH.0"

        cat > "$SYSLOG_CONF_FILE" <<'EOF'
source s_audit {
    file("/var/log/audit/audit.log"
        flags(no-parse)
        follow-freq(1)
        tags("tag_audit_log")
        persist-name("kuma_audit_source"));
};

template t_audit_format {
    template("<134>${ISODATE} ${HOST} auditd ${MSG}\n");
    template_escape(no);
};

destination d_kuma {
    network("__KUMA_HOST__" port(__KUMA_PORT__)
        template(t_audit_format)
        disk-buffer(
            mem-buf-size(10000)
            disk-buf-size(1G)
            reliable(yes)
        )
        transport("tls")
        tls(
            ca_dir("/etc/syslog-ng/cert/")
            peer-verify(required-trusted)
        )
    );
};

filter f_audit_kuma {
    tags("tag_audit_log");
};

log {
    source(s_audit);
    filter(f_audit_kuma);
    destination(d_kuma);
};
EOF
        sed -i "s|__KUMA_HOST__|$KUMA_HOST|; s|__KUMA_PORT__|$KUMA_PORT|" "$SYSLOG_CONF_FILE"

    elif [[ "$TLS" -eq 1 ]]; then

        cat > "$SYSLOG_CONF_FILE" <<'EOF'
source s_audit {
    file("/var/log/audit/audit.log"
        flags(no-parse)
        follow-freq(1)
        tags("tag_audit_log")
        persist-name("kuma_audit_source"));
};

template t_audit_format {
    template("<134>${ISODATE} ${HOST} auditd ${MSG}\n");
    template_escape(no);
};

destination d_kuma {
    tcp("__KUMA_HOST__" port(__KUMA_PORT__)
        template(t_audit_format)
        disk-buffer(
            mem-buf-size(10000)
            disk-buf-size(1G)
            reliable(yes)
        )
        tls(peer-verify(required-untrusted))
    );
};

filter f_audit_kuma {
    tags("tag_audit_log");
};

log {
    source(s_audit);
    filter(f_audit_kuma);
    destination(d_kuma);
};
EOF
        sed -i "s|__KUMA_HOST__|$KUMA_HOST|; s|__KUMA_PORT__|$KUMA_PORT|" "$SYSLOG_CONF_FILE"

    elif [[ "$PROTO" == "tcp" ]]; then
        cat > "$SYSLOG_CONF_FILE" <<'EOF'
source s_audit {
    file("/var/log/audit/audit.log"
        flags(no-parse)
        follow-freq(1)
        tags("tag_audit_log")
        persist-name("kuma_audit_source"));
};

template t_audit_format {
    template("<134>${ISODATE} ${HOST} auditd ${MSG}\n");
    template_escape(no);
};

destination d_kuma {
    tcp("__KUMA_HOST__" port(__KUMA_PORT__)
        template(t_audit_format)
        disk-buffer(
            mem-buf-size(10000)
            disk-buf-size(1G)
            reliable(yes)
        )
    );
};

filter f_audit_kuma {
    tags("tag_audit_log");
};

log {
    source(s_audit);
    filter(f_audit_kuma);
    destination(d_kuma);
};
EOF
        sed -i "s|__KUMA_HOST__|$KUMA_HOST|; s|__KUMA_PORT__|$KUMA_PORT|" "$SYSLOG_CONF_FILE"

    else
        cat > "$SYSLOG_CONF_FILE" <<'EOF'
source s_audit {
    file("/var/log/audit/audit.log"
        flags(no-parse)
        follow-freq(1)
        tags("tag_audit_log")
        persist-name("kuma_audit_source"));
};

template t_audit_format {
    template("<134>${ISODATE} ${HOST} auditd ${MSG}\n");
    template_escape(no);
};

destination d_kuma {
    udp("__KUMA_HOST__" port(__KUMA_PORT__)
        template(t_audit_format)
        disk-buffer(
            mem-buf-length(10000)
            disk-buf-size(1G)
        )
    );
};

filter f_audit_kuma {
    tags("tag_audit_log");
};

log {
    source(s_audit);
    filter(f_audit_kuma);
    destination(d_kuma);
};
EOF
        sed -i "s|__KUMA_HOST__|$KUMA_HOST|; s|__KUMA_PORT__|$KUMA_PORT|" "$SYSLOG_CONF_FILE"
    fi

fi

# Checking the configuration file was created successfully
if [ -f "$SYSLOG_CONF_FILE" ]; then
    echo -e "Creating file $SYSLOG_CONF_FILE - ${GREEN}OK${NC}"
else
    echo -e "${RED}Error: Failed to create $SYSLOG_CONF_FILE file${NC}"
    exit 1
fi

# Checking the configuration syntax before restarting the service
if [[ "$SYSLOG_DAEMON" == "syslog_ng" ]]; then
    if syslog-ng -s &> /dev/null; then
        echo -e "Checking syslog-ng configuration syntax - ${GREEN}OK${NC}"
    else
        echo -e "${RED}Error: syslog-ng configuration syntax check failed. Run 'syslog-ng -s' for details${NC}"
        exit 1
    fi
else
    if rsyslogd -N1 &> /dev/null; then
        echo -e "Checking rsyslog configuration syntax - ${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Warning: rsyslogd -N1 reported issues in the overall rsyslog configuration (possibly unrelated to $SYSLOG_CONF_FILE). Run 'rsyslogd -N1' for details. Continuing...${NC}"
    fi
fi

# Restart the selected syslog daemon
if systemctl restart "$SYSLOG_SERVICE"; then
    echo -e "Restarting $SYSLOG_DAEMON service - ${GREEN}OK${NC}"
else
    echo -e "${RED}Error: Failed to restart $SYSLOG_DAEMON${NC}"
    exit 1
fi

# Adding auditd rules to /etc/audit/rules.d/audit.rules
TARGET_RULES_FILE="/etc/audit/rules.d/audit.rules"

if [[ -n "$RULES_FILE" ]]; then
    if [ ! -f "$RULES_FILE" ]; then
        echo -e "${RED}Error: Rules file $RULES_FILE not found${NC}"
        exit 1
    fi
    if [[ "$(realpath -m "$RULES_FILE")" == "$(realpath -m "$TARGET_RULES_FILE")" ]]; then
        echo -e "Using existing $TARGET_RULES_FILE in place - ${GREEN}OK${NC}"
    elif ! cp "$RULES_FILE" "$TARGET_RULES_FILE"; then
        echo -e "${RED}Error: Cannot copy file to $TARGET_RULES_FILE${NC}"
        exit 1
    else
        echo -e "Copying auditd rules to $TARGET_RULES_FILE - ${GREEN}OK${NC}"
    fi
else
    if ! is_ssh_reachable "$KUMA_HOST" 22; then
        echo -e "${RED}Error: Cannot reach SSH (port 22) on KUMA server at $KUMA_HOST${NC}"
        exit 1
    else
        echo -e "Checking SSH availability on $KUMA_HOST:22 - ${GREEN}OK${NC}"
        read -r -p "Please enter the username to download the file from the KUMA server: " SSH_USER
        echo
        if scp -o ConnectTimeout=5 "$SSH_USER@$KUMA_HOST:/opt/audit.rules" "$TARGET_RULES_FILE" &> /dev/null; then
            echo -e "Downloading auditd rules from KUMA Server - ${GREEN}OK${NC}"
        else
            echo -e "${RED}Error: Failed to download the file audit.rules ${NC}" >&2
            exit 1
        fi
    fi
fi

append_kb_rules_safely "$TARGET_RULES_FILE" << 'EOF'
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
-a always,exit -F arch=b32 -S execve -S execveat -F exe=/usr/bin/shred -k T1070.004_1
-a always,exit -F arch=b64 -S execve -S execveat -F exe=/usr/bin/shred -k T1070.004_2

# split cmd audit
-w /usr/bin/split -p x -k split
EOF

# Restart auditd service (with augenrules support and fallback)
if command -v augenrules &> /dev/null; then
    augenrules --load &> /dev/null
    echo -e "Loading audit rules via augenrules - ${GREEN}OK${NC}"
fi

if systemctl restart auditd.service &> /dev/null; then
    echo -e "Restarting auditd service - ${GREEN}OK${NC}"
elif service auditd restart &> /dev/null; then
    echo -e "Restarting auditd service (via service) - ${GREEN}OK${NC}"
else
    echo -e "${RED}Error: Failed to restart auditd${NC}"
    exit 1
fi

# Checking if the audit.log file is filling up
AUDITD_LOG_FILE="/var/log/audit/audit.log"

INITIAL_SIZE=$(stat -c %s "$AUDITD_LOG_FILE")
sleep 10
CURRENT_SIZE=$(stat -c %s "$AUDITD_LOG_FILE")

if [ "$INITIAL_SIZE" -lt "$CURRENT_SIZE" ]; then
    echo -e "Audit logs are successfully written to the $AUDITD_LOG_FILE - ${GREEN}OK${NC}"
else
    echo -e "${RED}Error: Audit logs are not being written to the $AUDITD_LOG_FILE ${NC}" >&2
    exit 1
fi