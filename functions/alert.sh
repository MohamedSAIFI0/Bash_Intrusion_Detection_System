#!/bin/bash
# functions/alert.sh

# Tableau associatif pour mémoriser le dernier timestamp d'alerte par IP (bash 4+)
declare -A last_alert_time

send_alert() {
    local ip="$1"
    local pattern="$2"
    local line="$3"
    local now=$(date +%s)

    # Ignorer si IP dans whitelist
    for whitelisted_ip in "${WHITELIST_IPS[@]}"; do
        if [[ "$ip" == "$whitelisted_ip" ]]; then
            return 0
        fi
    done

    # Vérifier cooldown pour cette IP
    if [[ -n "${last_alert_time[$ip]}" ]]; then
        local elapsed=$(( now - last_alert_time[$ip] ))
        if (( elapsed < ALERT_COOLDOWN )); then
            # Trop tôt pour renvoyer une alerte pour cette IP
            return 0
        fi
    fi

    # Mettre à jour le timestamp d'alerte
    last_alert_time[$ip]=$now

    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local alert_msg="[$timestamp] [ALERTE] Intrusion détectée : pattern='$pattern' ip='$ip' ligne='$line'"

    # Écrire dans le fichier log d'intrusion
    echo "$alert_msg" >> "$LOG_FILE"

    # Afficher dans la console
    echo "$alert_msg"

    # Envoyer email si configuré
    if [[ -n "$EMAIL_TO" ]]; then
        echo "$alert_msg" | mail -s "Alerte IDS détectée" "$EMAIL_TO"
    fi

    # Option wall (si activé)
    if [[ "$ALERT_METHOD" == "wall" ]]; then
        wall "$alert_msg"
    fi
}
