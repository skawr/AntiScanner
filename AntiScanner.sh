#!/bin/bash
# ЕДИНЫЙ СКРИПТ УСТАНОВКИ V2.6 (Zero-Downtime, TCP-Protect, Smart OpenFilters API & Auto-Cleanup)

if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: Запустите от имени root (sudo)."
    exit 1
fi

echo "Обновление/Установка гибридного AntiScanner (с динамическим API OpenFilters)..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y ipset curl logrotate -qq
if dpkg -l | grep -q iptables-persistent; then
    apt-get purge -y iptables-persistent -qq
fi

cat << 'LOGROTATE_EOF' > /etc/logrotate.d/antiscanner
/var/log/antiscanner_update.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
}
LOGROTATE_EOF

SCRIPT_PATH="/usr/local/bin/update-antiscanner.sh"

cat << 'EOF' > "$SCRIPT_PATH"
#!/bin/bash
URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
IPSET_V4="SCANNERS-BLOCK-V4"
IPSET_V6="SCANNERS-BLOCK-V6"
TEMP_V4="${IPSET_V4}-TEMP"
TEMP_V6="${IPSET_V6}-TEMP"
WHITELIST_V4="WHITELIST-V4"

# Увеличен лимит maxelem до 500000 из-за большого объема баз
ipset create $IPSET_V4 hash:net family inet hashsize 4096 maxelem 500000 2>/dev/null
ipset create $IPSET_V6 hash:net family inet6 hashsize 4096 maxelem 500000 2>/dev/null
ipset create $WHITELIST_V4 hash:net family inet 2>/dev/null

# === АВТО-БЕЛЫЙ СПИСОК ===
ipset flush $WHITELIST_V4 2>/dev/null
VPS_GW=$(ip -4 route | grep default | awk '{print $3}')
[[ -n "$VPS_GW" ]] && ipset add $WHITELIST_V4 "$VPS_GW" 2>/dev/null
grep nameserver /etc/resolv.conf | awk '{print $2}' | grep -E '^[0-9.]+$' | while read -r dns; do
    ipset add $WHITELIST_V4 "$dns" 2>/dev/null
done

# === СКАЧИВАНИЕ И ОБНОВЛЕНИЕ БАЗ ===
if [[ "$1" != "--rules-only" ]]; then
    TEMP_FILE=$(mktemp)
    ipset create $TEMP_V4 hash:net family inet hashsize 4096 maxelem 500000 2>/dev/null || ipset flush $TEMP_V4
    ipset create $TEMP_V6 hash:net family inet6 hashsize 4096 maxelem 500000 2>/dev/null || ipset flush $TEMP_V6

    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Загрузка баз IP-адресов..."
    
    # 1. Загрузка базового Gist-списка
    curl -sSLf --max-time 30 "$URL" >> "$TEMP_FILE" 2>/dev/null

    # 2. Динамическая загрузка OpenFilters через API GitHub
    API_URL="https://api.github.com/repos/OpenFilters/internet-scanners/contents/cidr"
    KEYWORDS="censys|shodan|paloalto|shadowserver|driftnet|onyphe|zoomeye|leakix|rapid7|fofa|quake"
    
    # Парсим JSON ответа API, достаем прямые ссылки и фильтруем по ключевым словам
    curl -sSL --max-time 15 "$API_URL" | grep '"download_url":' | awk -F '"' '{print $4}' | grep -iE "($KEYWORDS)" | while read -r url; do
        curl -sSL --max-time 15 "$url" >> "$TEMP_FILE" 2>/dev/null
    done

    # 3. Обработка собранного файла
    if [[ -s "$TEMP_FILE" ]]; then
        while IFS= read -r subnet; do
            subnet=$(echo "$subnet" | awk '{print $1}') 
            [[ -z "$subnet" || "$subnet" == "#"* || "$subnet" == "<"* ]] && continue
            
            if [[ "$subnet" =~ : ]]; then
                ipset add $TEMP_V6 "$subnet" 2>/dev/null
            else
                ipset add $TEMP_V4 "$subnet" 2>/dev/null
            fi
        done < "$TEMP_FILE"

        # Блок защиты от соседей
        ip2int() { local a b c d; IFS=. read a b c d <<< "$1"; echo $((a * 256**3 + b * 256**2 + c * 256 + d)); }
        int2ip() { local ui32=$1; local ip n; for n in 1 2 3 4; do ip=$((ui32 & 0xff))${ip:+.}$ip; ui32=$((ui32 >> 8)); done; echo $ip; }

        VPS_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[0-9.]+')
        if [[ -n "$VPS_IP" ]]; then
            IP_INT=$(ip2int "$VPS_IP")
            START_IP=$(int2ip $((IP_INT - 500)))
            END_IP=$(int2ip $((IP_INT + 500)))
            ipset add $TEMP_V4 $START_IP-$END_IP 2>/dev/null
        fi

        ipset swap $TEMP_V4 $IPSET_V4
        ipset swap $TEMP_V6 $IPSET_V6
        echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Базы сканеров успешно обновлены (API Fetch)"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Ошибка скачивания списков."
    fi
    
    ipset destroy $TEMP_V4 2>/dev/null
    ipset destroy $TEMP_V6 2>/dev/null
    rm -f "$TEMP_FILE"
fi

# === ОЧИСТКА ЛЕГАСИ ===
for cmd in iptables ip6tables; do
    $cmd -D INPUT -j SCANNERS-BLOCK 2>/dev/null
    $cmd -D DOCKER-USER -j SCANNERS-BLOCK 2>/dev/null
    $cmd -F SCANNERS-BLOCK 2>/dev/null
    $cmd -X SCANNERS-BLOCK 2>/dev/null
done

# === ЗАЩИТА ОТ АНОМАЛЬНЫХ TCP-ФЛАГОВ ===
for cmd in iptables ip6tables; do
    if ! $cmd -L TCP-FLAGS-PROTECT -n &>/dev/null; then
        $cmd -N TCP-FLAGS-PROTECT
        $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL NONE -j DROP
        $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL ALL -j DROP
        $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
        $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
        $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
        $cmd -A TCP-FLAGS-PROTECT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
        $cmd -A TCP-FLAGS-PROTECT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
    fi
done

# === ПРИМЕНЕНИЕ ПРАВИЛ IPTABLES ===
for cmd in iptables ip6tables; do
    $cmd -D INPUT -i lo -j ACCEPT 2>/dev/null
    $cmd -D INPUT -p udp --sport 53 -j ACCEPT 2>/dev/null
    $cmd -D INPUT -p tcp --sport 53 -j ACCEPT 2>/dev/null
    $cmd -D INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    $cmd -D INPUT -j TCP-FLAGS-PROTECT 2>/dev/null
    $cmd -D INPUT -m set --match-set $IPSET_V4 src -j DROP 2>/dev/null
    $cmd -D INPUT -m set --match-set $IPSET_V6 src -j DROP 2>/dev/null
    $cmd -D INPUT -m set --match-set $WHITELIST_V4 src -j RETURN 2>/dev/null
done

iptables -I INPUT 1 -m set --match-set $IPSET_V4 src -j DROP
ip6tables -I INPUT 1 -m set --match-set $IPSET_V6 src -j DROP
iptables -I INPUT 1 -m set --match-set $WHITELIST_V4 src -j RETURN

iptables -I INPUT 1 -j TCP-FLAGS-PROTECT
ip6tables -I INPUT 1 -j TCP-FLAGS-PROTECT

iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ip6tables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -I INPUT 1 -p tcp --sport 53 -j ACCEPT
ip6tables -I INPUT 1 -p tcp --sport 53 -j ACCEPT
iptables -I INPUT 1 -p udp --sport 53 -j ACCEPT
ip6tables -I INPUT 1 -p udp --sport 53 -j ACCEPT
iptables -I INPUT 1 -i lo -j ACCEPT
ip6tables -I INPUT 1 -i lo -j ACCEPT

# DOCKER-USER
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    iptables -D DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -D DOCKER-USER -j TCP-FLAGS-PROTECT 2>/dev/null
    iptables -D DOCKER-USER -m set --match-set $IPSET_V4 src -j DROP 2>/dev/null
    iptables -D DOCKER-USER -m set --match-set $WHITELIST_V4 src -j RETURN 2>/dev/null
    
    iptables -I DOCKER-USER 1 -m set --match-set $IPSET_V4 src -j DROP
    iptables -I DOCKER-USER 1 -m set --match-set $WHITELIST_V4 src -j RETURN
    iptables -I DOCKER-USER 1 -j TCP-FLAGS-PROTECT
    iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi

if ip6tables -L DOCKER-USER -n >/dev/null 2>&1; then
    ip6tables -D DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    ip6tables -D DOCKER-USER -j TCP-FLAGS-PROTECT 2>/dev/null
    ip6tables -D DOCKER-USER -m set --match-set $IPSET_V6 src -j DROP 2>/dev/null
    
    ip6tables -I DOCKER-USER 1 -m set --match-set $IPSET_V6 src -j DROP
    ip6tables -I DOCKER-USER 1 -j TCP-FLAGS-PROTECT
    ip6tables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
fi
EOF

chmod +x "$SCRIPT_PATH"

# 4. Настройка Cron
crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" | crontab -
C_JOB="20 3 * * * $SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1"
(crontab -l 2>/dev/null; echo "$C_JOB") | crontab -

# 5. Интеграция с Systemd
echo "Настройка хуков..."
mkdir -p /etc/systemd/system/docker.service.d /etc/systemd/system/ufw.service.d
echo -e "[Service]\nExecStartPost=-$SCRIPT_PATH --rules-only" > /etc/systemd/system/docker.service.d/antiscanner-hook.conf
echo -e "[Service]\nExecStartPost=-$SCRIPT_PATH --rules-only" > /etc/systemd/system/ufw.service.d/antiscanner-hook.conf

cat << EOF_SYS > /etc/systemd/system/antiscanner-update.service
[Unit]
Description=Update AntiScanner Blocklist on Boot
After=network.target ufw.service docker.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "$SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SYS

systemctl daemon-reload
systemctl enable antiscanner-update.service &>/dev/null

# 6. Применение
echo "Сбор баз через API (может занять 10-15 секунд) и применение правил..."
$SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1
echo "Установка/Обновление успешно завершено!"
