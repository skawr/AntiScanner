#!/bin/bash
# ЕДИНЫЙ СКРИПТ УСТАНОВКИ V3.5.6 (Clean Architecture, Redundant DNS Fallback Removed)

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: Запустите от имени root."
    exit 1
fi

if ! command -v apt-get >/dev/null; then
    echo "Ошибка: Этот скрипт предназначен для Debian/Ubuntu."
    exit 1
fi

echo "Установка/Обновление AntiScanner V3.5.6..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y ipset curl logrotate mawk iptables util-linux -qq

if dpkg -l | grep -q iptables-persistent; then
    echo "[WARN] Обнаружен iptables-persistent. Скрипт не удаляет его автоматически, чтобы не нарушить вашу конфигурацию."
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
set -Eeuo pipefail

LOCK_FILE="/run/antiscanner.lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] AntiScanner уже запущен. Выход." >> /var/log/antiscanner_update.log
    exit 0
fi

# Конфигурация
URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
MIN_V4_RECORDS=1000
MAX_DROP_PERCENT=50
MIN_V6_RECORDS=0 # Установите реальный минимум (например, 50), если IPv6-база для вас критична
MAX_DROP_PERCENT_V6=50

# Блокировка SNI-сканеров от соседей по дата-центру
ENABLE_NEIGHBOR_BLOCK=true
NEIGHBOR_RANGE=500

if (( MAX_DROP_PERCENT < 0 || MAX_DROP_PERCENT >= 100 || MAX_DROP_PERCENT_V6 < 0 || MAX_DROP_PERCENT_V6 >= 100 )); then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] MAX_DROP_PERCENT должен быть от 0 до 99." >> /var/log/antiscanner_update.log
    exit 1
fi

CHAIN_MAIN="ANTISCANNER"
CHAIN_TCP="ANTISCANNER-TCP-FLAGS"

IPSET_V4="SCANNERS-BLOCK-V4"
IPSET_V6="SCANNERS-BLOCK-V6"
TEMP_V4="${IPSET_V4}-TEMP"
TEMP_V6="${IPSET_V6}-TEMP"
WHITELIST_V4="WHITELIST-V4"
WHITELIST_V6="WHITELIST-V6"

TEMP_LIST=""
RESTORE_FILE=""
API_RESP=""
TMP_DL=""

trap 'rm -f "${TEMP_LIST:-}" "${RESTORE_FILE:-}" "${API_RESP:-}" "${TMP_DL:-}"; ipset destroy "$TEMP_V4" 2>/dev/null || true; ipset destroy "$TEMP_V6" 2>/dev/null || true' EXIT

TEMP_LIST=$(mktemp)
RESTORE_FILE=$(mktemp)
API_RESP=$(mktemp)
TMP_DL=$(mktemp)

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1"; }

validate_ipset_type() {
    local set_name=$1
    local expected_family=$2

    if ipset list "$set_name" >/dev/null 2>&1; then
        local type family
        type=$(ipset list "$set_name" | mawk '/^Type:/ {print $2; exit}' || true)
        family=$(ipset list "$set_name" | mawk '
            /^Header:/ {
                for (i = 1; i <= NF; i++) {
                    if ($i == "family") {
                        print $(i+1)
                        exit
                    }
                }
            }' || true)

        if [[ "$type" != "hash:net" || "$family" != "$expected_family" ]]; then
            log "[ERROR] ipset $set_name имеет тип=$type family=$family, ожидалось hash:net/$expected_family."
            return 1
        fi
    else
        return 1
    fi
    return 0
}

ensure_ipset() {
    local set_name=$1
    local family=$2
    ipset create "$set_name" hash:net family "$family" hashsize 131072 maxelem 500000 2>/dev/null || true
    if ! validate_ipset_type "$set_name" "$family"; then
        log "[ERROR] Не удалось создать или получить доступ к $set_name. Проверьте поддержку модуля ipset в ядре ОС."
        exit 1
    fi
}

ensure_ipset "$IPSET_V4" inet
ensure_ipset "$IPSET_V6" inet6
ensure_ipset "$WHITELIST_V4" inet
ensure_ipset "$WHITELIST_V6" inet6

# === ШАГ 1: БЕЛЫЙ СПИСОК (IPv4 + IPv6) ===
ipset flush "$WHITELIST_V4" 2>/dev/null || true
ipset flush "$WHITELIST_V6" 2>/dev/null || true

VPS_GW=$(ip -4 route show default 2>/dev/null | mawk '{print $3}' | head -n1 || true)
[[ -n "$VPS_GW" ]] && ipset add "$WHITELIST_V4" "$VPS_GW" 2>/dev/null || true

VPS_GW6=$(ip -6 route show default 2>/dev/null | mawk '{print $3}' | head -n1 || true)
if [[ "$VPS_GW6" == *:* ]]; then
    ipset add "$WHITELIST_V6" "$VPS_GW6" 2>/dev/null || true
fi

grep nameserver /etc/resolv.conf | mawk '{print $2}' | while read -r dns; do
    # Очистка от суффиксов интерфейса (например, fe80::1%eth0 -> fe80::1)
    dns="${dns%%%*}"
    if [[ "$dns" =~ : ]]; then
        ipset add "$WHITELIST_V6" "$dns" 2>/dev/null || true
    elif [[ "$dns" =~ \. ]]; then
        ipset add "$WHITELIST_V4" "$dns" 2>/dev/null || true
    fi
done

# === ШАГ 2: СКАЧИВАНИЕ И ВАЛИДАЦИЯ ИСТОЧНИКОВ ===
if [[ "${1:-}" != "--rules-only" ]]; then
    log "[INFO] Загрузка баз сканеров..."
    
    if ! curl -sSLf --user-agent "Mozilla/5.0" --max-time 30 "$URL" > "$TEMP_LIST"; then
        log "[ERROR] Не удалось скачать Gist. Прерывание."
        exit 1
    fi
    
    GIST_V4_COUNT=$(mawk '
    function check_ip(ip,   a) {
        split(ip, a, ".")
        return (a[1] <= 255 && a[2] <= 255 && a[3] <= 255 && a[4] <= 255)
    }
    {
        sub(/#.*/, "")
        sub(/<.*/, "")
        if ($1 ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/) {
            split($1, p, "/")
            if (check_ip(p[1])) count++
        } else if ($1 ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}-[0-9]{1,3}(\.[0-9]{1,3}){3}$/) {
            split($1, p, "-")
            if (check_ip(p[1]) && check_ip(p[2])) count++
        }
    }
    END { print count+0 }
    ' "$TEMP_LIST")

    if (( GIST_V4_COUNT == 0 )); then
        log "[ERROR] База Gist не содержит валидных IPv4 адресов. Прерывание."
        exit 1
    fi

    API_URL="https://api.github.com/repos/OpenFilters/internet-scanners/contents/cidr"
    KEYWORDS="censys|shodan|paloalto|shadowserver|driftnet|onyphe|zoomeye|leakix|rapid7|fofa|quake"
    
    HTTP_CODE=$(curl -s -o "$API_RESP" -w "%{http_code}" -H "User-Agent: AntiScanner-V3.5.6" --max-time 15 "$API_URL" || true)
    if [[ "$HTTP_CODE" == "200" ]]; then
        SUCCESS_DL=0
        FAIL_DL=0
        
        while read -r url; do
            if curl -sSLf -H "User-Agent: AntiScanner-V3.5.6" --max-time 15 "$url" > "$TMP_DL"; then
                cat "$TMP_DL" >> "$TEMP_LIST"
                ((SUCCESS_DL+=1))
            else
                ((FAIL_DL+=1))
            fi
            : > "$TMP_DL"
        done < <(mawk -F '"' '/"download_url":/ {print $4}' "$API_RESP" | grep -iE "($KEYWORDS)")
        
        log "[INFO] OpenFilters: $SUCCESS_DL файлов загружено, $FAIL_DL не удалось."
    else
        log "[WARN] GitHub API недоступен (Код $HTTP_CODE). Используется только Gist."
    fi

    # === ШАГ 3: ПОДГОТОВКА СЕТОВ И МАТЕМАТИКА СОСЕДЕЙ ===
    ipset destroy "$TEMP_V4" 2>/dev/null || true
    ipset destroy "$TEMP_V6" 2>/dev/null || true
    ipset create "$TEMP_V4" hash:net family inet hashsize 131072 maxelem 500000
    ipset create "$TEMP_V6" hash:net family inet6 hashsize 131072 maxelem 500000

    mawk '
    function check_ip(ip,   a) {
        split(ip, a, ".")
        return (a[1] <= 255 && a[2] <= 255 && a[3] <= 255 && a[4] <= 255)
    }
    {
        sub(/#.*/, "")
        sub(/<.*/, "")
        if ($1 ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}(\/[0-9]{1,2})?$/) {
            split($1, p, "/")
            if (check_ip(p[1])) print "add '"$TEMP_V4"' " $1
        } else if ($1 ~ /^[0-9]{1,3}(\.[0-9]{1,3}){3}-[0-9]{1,3}(\.[0-9]{1,3}){3}$/) {
            split($1, p, "-")
            if (check_ip(p[1]) && check_ip(p[2])) print "add '"$TEMP_V4"' " $1
        } else if ($1 ~ /^[0-9A-Fa-f:]+(\/[0-9]{1,3})?$/) {
            print "add '"$TEMP_V6"' " $1
        }
    }' "$TEMP_LIST" > "$RESTORE_FILE"

    if [ "$ENABLE_NEIGHBOR_BLOCK" = true ]; then
        ip2int() { local a b c d; IFS=. read a b c d <<< "$1"; echo $((a * 256**3 + b * 256**2 + c * 256 + d)); }
        int2ip() { local ui32=$1; local ip n; for n in 1 2 3 4; do ip=$((ui32 & 0xff))${ip:+.}$ip; ui32=$((ui32 >> 8)); done; echo $ip; }

        VPS_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[0-9.]+' || true)
        if [[ -n "$VPS_IP" ]]; then
            IP_INT=$(ip2int "$VPS_IP")
            START_INT=$((IP_INT - NEIGHBOR_RANGE))
            END_INT=$((IP_INT + NEIGHBOR_RANGE))
            
            (( START_INT < 0 )) && START_INT=0
            (( END_INT > 4294967295 )) && END_INT=4294967295

            START_IP=$(int2ip $START_INT)
            END_IP=$(int2ip $END_INT)
            echo "add $TEMP_V4 $START_IP-$END_IP" >> "$RESTORE_FILE"
        fi
    fi

    # === ШАГ 4: ДВУХФАЗНАЯ ЗАМЕНА С КОМПЕНСАЦИОННЫМ ОТКАТОМ ===
    OLD_V4_COUNT=$(ipset list "$IPSET_V4" 2>/dev/null | mawk '/Number of entries:/ {print $4}' || echo 0)
    OLD_V6_COUNT=$(ipset list "$IPSET_V6" 2>/dev/null | mawk '/Number of entries:/ {print $4}' || echo 0)
    
    if ipset restore -! < "$RESTORE_FILE"; then
        ACTUAL_V4_COUNT=$(ipset list "$TEMP_V4" | mawk '/Number of entries:/ {print $4}' || true)
        ACTUAL_V6_COUNT=$(ipset list "$TEMP_V6" | mawk '/Number of entries:/ {print $4}' || true)
        [[ -z "$ACTUAL_V4_COUNT" ]] && ACTUAL_V4_COUNT=0
        [[ -z "$ACTUAL_V6_COUNT" ]] && ACTUAL_V6_COUNT=0

        if (( ACTUAL_V4_COUNT < MIN_V4_RECORDS )); then
            log "[ERROR] Размер IPv4 базы ($ACTUAL_V4_COUNT) ниже минимума ($MIN_V4_RECORDS). Откат."
            exit 1
        fi
        if (( ACTUAL_V6_COUNT < MIN_V6_RECORDS )); then
            log "[ERROR] Размер IPv6 базы ($ACTUAL_V6_COUNT) ниже минимума ($MIN_V6_RECORDS). Откат."
            exit 1
        fi

        if (( OLD_V4_COUNT > MIN_V4_RECORDS )); then
            MIN_ALLOWED_V4=$(( OLD_V4_COUNT * (100 - MAX_DROP_PERCENT) / 100 ))
            if (( ACTUAL_V4_COUNT < MIN_ALLOWED_V4 )); then
                log "[ERROR] Аномальное падение IPv4 базы: $OLD_V4_COUNT -> $ACTUAL_V4_COUNT (минимум $MIN_ALLOWED_V4). Откат."
                exit 1
            fi
        fi
        if (( OLD_V6_COUNT > MIN_V6_RECORDS )); then
            MIN_ALLOWED_V6=$(( OLD_V6_COUNT * (100 - MAX_DROP_PERCENT_V6) / 100 ))
            if (( ACTUAL_V6_COUNT < MIN_ALLOWED_V6 )); then
                log "[ERROR] Аномальное падение IPv6 базы: $OLD_V6_COUNT -> $ACTUAL_V6_COUNT (минимум $MIN_ALLOWED_V6). Откат."
                exit 1
            fi
        fi

        if ipset swap "$TEMP_V4" "$IPSET_V4"; then
            if ipset swap "$TEMP_V6" "$IPSET_V6"; then
                log "[SUCCESS] Двухфазная замена завершена. IPv4: $ACTUAL_V4_COUNT, IPv6: $ACTUAL_V6_COUNT."
            else
                log "[ERROR] Ошибка IPv6 swap. Инициация компенсационного отката IPv4..."
                if ipset swap "$TEMP_V4" "$IPSET_V4"; then
                    log "[SUCCESS] Откат IPv4 успешно завершен."
                else
                    log "[CRITICAL] Откат IPv4 не удался! Нарушена консистентность, требуется ручное вмешательство."
                    exit 2
                fi
                exit 1
            fi
        else
            log "[ERROR] Ошибка IPv4 swap. Отмена транзакции."
            exit 1
        fi
    else
        log "[ERROR] ipset restore failed. Отмена."
        exit 1
    fi
fi

# === ШАГ 5: МИГРАЦИЯ И УПРАВЛЕНИЕ ПРАВИЛАМИ IPTABLES ===
clean_legacy_jumps() {
    local chain=$1
    local cmd=$2
    while $cmd -D "$chain" -j "$CHAIN_MAIN" 2>/dev/null; do :; done
    while $cmd -D "$chain" -j "$CHAIN_TCP" 2>/dev/null; do :; done
    while $cmd -D "$chain" -j TCP-FLAGS-PROTECT 2>/dev/null; do :; done
    while $cmd -D "$chain" -j SCANNERS-BLOCK 2>/dev/null; do :; done
    while $cmd -D "$chain" -j WHITELIST 2>/dev/null; do :; done
}

clean_legacy_jumps INPUT iptables
clean_legacy_jumps INPUT ip6tables
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then clean_legacy_jumps DOCKER-USER iptables; fi
if ip6tables -L DOCKER-USER -n >/dev/null 2>&1; then clean_legacy_jumps DOCKER-USER ip6tables; fi

for cmd in iptables ip6tables; do
    $cmd -F SCANNERS-BLOCK 2>/dev/null || true
    $cmd -X SCANNERS-BLOCK 2>/dev/null || true
    $cmd -F WHITELIST 2>/dev/null || true
    $cmd -X WHITELIST 2>/dev/null || true
    $cmd -F TCP-FLAGS-PROTECT 2>/dev/null || true
    $cmd -X TCP-FLAGS-PROTECT 2>/dev/null || true
done

for cmd in iptables ip6tables; do
    if ! $cmd -L "$CHAIN_MAIN" -n >/dev/null 2>&1; then
        $cmd -N "$CHAIN_MAIN"
    fi
    $cmd -F "$CHAIN_MAIN"
done

for cmd in iptables ip6tables; do
    if ! $cmd -L "$CHAIN_TCP" -n >/dev/null 2>&1; then
        $cmd -N "$CHAIN_TCP"
    fi
    $cmd -F "$CHAIN_TCP"
    $cmd -A "$CHAIN_TCP" -p tcp --tcp-flags ALL NONE -j DROP
    $cmd -A "$CHAIN_TCP" -p tcp --tcp-flags ALL ALL -j DROP
    $cmd -A "$CHAIN_TCP" -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
    $cmd -A "$CHAIN_TCP" -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    $cmd -A "$CHAIN_TCP" -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    $cmd -A "$CHAIN_TCP" -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
done

for cmd in iptables ip6tables; do
    $cmd -A "$CHAIN_MAIN" -i lo -j ACCEPT
    
    if [ "$cmd" = "iptables" ]; then
        $cmd -A "$CHAIN_MAIN" -m set --match-set "$WHITELIST_V4" src -j ACCEPT
        $cmd -A "$CHAIN_MAIN" -p tcp -j "$CHAIN_TCP"
        $cmd -A "$CHAIN_MAIN" -m set --match-set "$IPSET_V4" src -j DROP
    else
        $cmd -A "$CHAIN_MAIN" -m set --match-set "$WHITELIST_V6" src -j ACCEPT
        $cmd -A "$CHAIN_MAIN" -p tcp -j "$CHAIN_TCP"
        $cmd -A "$CHAIN_MAIN" -m set --match-set "$IPSET_V6" src -j DROP
    fi

    $cmd -A "$CHAIN_MAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    $cmd -A "$CHAIN_MAIN" -j RETURN
done

for cmd in iptables ip6tables; do
    if ! $cmd -C INPUT -j "$CHAIN_MAIN" >/dev/null 2>&1; then
        $cmd -I INPUT 1 -j "$CHAIN_MAIN"
    fi
done

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    if ! iptables -C DOCKER-USER -j "$CHAIN_MAIN" >/dev/null 2>&1; then
        iptables -I DOCKER-USER 1 -j "$CHAIN_MAIN"
    fi
fi
if ip6tables -L DOCKER-USER -n >/dev/null 2>&1; then
    if ! ip6tables -C DOCKER-USER -j "$CHAIN_MAIN" >/dev/null 2>&1; then
        ip6tables -I DOCKER-USER 1 -j "$CHAIN_MAIN"
    fi
fi
EOF

chmod +x "$SCRIPT_PATH"

# === Настройка Cron и Systemd ===
crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" | crontab -
C_JOB="20 3 * * * $SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1"
(crontab -l 2>/dev/null; echo "$C_JOB") | crontab -

mkdir -p /etc/systemd/system/docker.service.d /etc/systemd/system/ufw.service.d
echo -e "[Service]\nExecStartPost=-/bin/bash -c '$SCRIPT_PATH --rules-only >> /var/log/antiscanner_update.log 2>&1'" > /etc/systemd/system/docker.service.d/antiscanner-hook.conf
echo -e "[Service]\nExecStartPost=-/bin/bash -c '$SCRIPT_PATH --rules-only >> /var/log/antiscanner_update.log 2>&1'" > /etc/systemd/system/ufw.service.d/antiscanner-hook.conf

cat << EOF_SYS > /etc/systemd/system/antiscanner-update.service
[Unit]
Description=Update AntiScanner Blocklist on Boot
After=network.target ufw.service docker.service

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
StandardOutput=append:/var/log/antiscanner_update.log
StandardError=append:/var/log/antiscanner_update.log
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SYS

systemctl daemon-reload
systemctl enable antiscanner-update.service &>/dev/null

echo "Запуск обновления V3.5.6..."
$SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1
echo "Установка AntiScanner V3.5.6 завершена!"
