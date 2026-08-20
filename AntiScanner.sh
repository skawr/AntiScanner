#!/bin/bash
# ЕДИНЫЙ СКРИПТ УСТАНОВКИ V2.0 (Zero-Downtime & Auto-Restore)

if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: Запустите от имени root (sudo)."
    exit 1
fi

echo "Настройка гибридного AntiScanner с автоматизацией..."

# 1. Установка пакетов и чистка
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y ipset curl logrotate -qq
if dpkg -l | grep -q iptables-persistent; then
    apt-get purge -y iptables-persistent -qq
fi

# 2. Настройка логов
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

# 3. ГЕНЕРАЦИЯ СКРИПТА (Поддержка swap и флага --rules-only)
cat << 'EOF' > "$SCRIPT_PATH"
#!/bin/bash
URL="https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt"
IPSET_V4="SCANNERS-BLOCK-V4"
IPSET_V6="SCANNERS-BLOCK-V6"
TEMP_V4="${IPSET_V4}-TEMP"
TEMP_V6="${IPSET_V6}-TEMP"

# Гарантируем, что базовые сеты существуют
ipset create $IPSET_V4 hash:net family inet hashsize 1024 maxelem 100000 2>/dev/null
ipset create $IPSET_V6 hash:net family inet6 hashsize 1024 maxelem 100000 2>/dev/null

# Если скрипт запущен БЕЗ флага --rules-only, то обновляем базы
if [[ "$1" != "--rules-only" ]]; then
    TEMP_FILE=$(mktemp)
    
    # Создаем/очищаем временные сеты
    ipset create $TEMP_V4 hash:net family inet hashsize 1024 maxelem 100000 2>/dev/null || ipset flush $TEMP_V4
    ipset create $TEMP_V6 hash:net family inet6 hashsize 1024 maxelem 100000 2>/dev/null || ipset flush $TEMP_V6

    if curl -sSL --max-time 30 "$URL" -o "$TEMP_FILE" && [[ -s "$TEMP_FILE" ]]; then
        while IFS= read -r subnet; do
            subnet=$(echo "$subnet" | xargs)
            [[ -z "$subnet" || "$subnet" == "#"* ]] && continue
            if [[ "$subnet" =~ : ]]; then
                ipset add $TEMP_V6 "$subnet" 2>/dev/null
            else
                ipset add $TEMP_V4 "$subnet" 2>/dev/null
            fi
        done < "$TEMP_FILE"

        # Бесшовный swap (Zero-Downtime)
        ipset swap $TEMP_V4 $IPSET_V4
        ipset swap $TEMP_V6 $IPSET_V6
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] Базы IP-адресов скачаны и обновлены (SWAP)"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] Не удалось скачать список. Используются старые базы."
    fi
    
    # Удаляем временный мусор
    ipset destroy $TEMP_V4 2>/dev/null
    ipset destroy $TEMP_V6 2>/dev/null
    rm -f "$TEMP_FILE"
fi

# Применяем/восстанавливаем правила iptables (выполняется всегда)
iptables -C INPUT -m set --match-set $IPSET_V4 src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set $IPSET_V4 src -j DROP
ip6tables -C INPUT -m set --match-set $IPSET_V6 src -j DROP 2>/dev/null || ip6tables -I INPUT 1 -m set --match-set $IPSET_V6 src -j DROP

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    iptables -C DOCKER-USER -m set --match-set $IPSET_V4 src -j DROP 2>/dev/null || iptables -I DOCKER-USER 1 -m set --match-set $IPSET_V4 src -j DROP
fi
if ip6tables -L DOCKER-USER -n >/dev/null 2>&1; then
    ip6tables -C DOCKER-USER -m set --match-set $IPSET_V6 src -j DROP 2>/dev/null || ip6tables -I DOCKER-USER 1 -m set --match-set $IPSET_V6 src -j DROP
fi

if [[ "$1" == "--rules-only" ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] Правила iptables/UFW восстановлены после перезапуска службы." >> /var/log/antiscanner_update.log
fi
EOF

chmod +x "$SCRIPT_PATH"

# 4. Настройка Cron (Только обновление баз)
C_JOB="20 3 * * * $SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1"
(crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" ; echo "$C_JOB") | crontab -

# 5. Интеграция с Systemd (Авто-восстановление при рестарте сервисов)
echo "Настройка хуков для UFW и Docker..."

# Хук для Docker
mkdir -p /etc/systemd/system/docker.service.d
cat << EOF_DOCKER > /etc/systemd/system/docker.service.d/antiscanner-hook.conf
[Service]
ExecStartPost=-$SCRIPT_PATH --rules-only
EOF_DOCKER

# Хук для UFW
mkdir -p /etc/systemd/system/ufw.service.d
cat << EOF_UFW > /etc/systemd/system/ufw.service.d/antiscanner-hook.conf
[Service]
ExecStartPost=-$SCRIPT_PATH --rules-only
EOF_UFW

# Основной юнит для загрузки сервера
cat << EOF_SYS > /etc/systemd/system/antiscanner-update.service
[Unit]
Description=Update AntiScanner Blocklist on Boot
After=network.target ufw.service docker.service

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SYS

systemctl daemon-reload
systemctl enable antiscanner-update.service &>/dev/null

# 6. Первый запуск
echo "Первичное применение баз и правил..."
$SCRIPT_PATH >> /var/log/antiscanner_update.log 2>&1

echo "Установка успешно завершена! Защита полностью автоматизирована."
