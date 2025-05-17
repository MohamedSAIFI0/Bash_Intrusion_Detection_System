#!/bin/bash
# functions/monitor.sh
# Fonction de surveillance des logs pour détection basique d'intrusions

# Inclure la configuration générale (variables, patterns, etc.)
source "$(dirname "$(readlink -f "$0")")/../config.sh"

# Inclure les fonctions liées aux alertes (send_alert)
source "$(dirname "$(readlink -f "$0")")/alert.sh"

# Fonction principale qui démarre la surveillance en temps réel des fichiers logs
start_monitoring() {
    echo "[INFO] Démarrage de la surveillance des logs..." >> "$LOG_FILE"

    # Lancer la surveillance en arrière-plan
    tail -F /var/log/auth.log /var/log/syslog 2>/dev/null | while read -r line; do
        for pattern in "${PATTERNS[@]}"; do
            if [[ "$line" =~ $pattern ]]; then
                ip=$(echo "$line" | grep -oP 'from \K[\d\.]+')

                echo "[ALERTE] Tentative suspecte détectée : \"$pattern\" - Ligne: $line" >> "$LOG_FILE"
                [[ -n "$ip" ]] && echo "[ALERTE] Adresse IP concernée : $ip" >> "$LOG_FILE"

                send_alert "$ip" "$pattern" "$line"
                # block_ip "$ip"  # Optionnel
            fi
        done
    done &
    
    # Récupérer le PID du processus de surveillance (le dernier en arrière-plan)
    local monitor_pid=$!
    
    # Enregistrer ce PID dans un fichier pour gestion ultérieure
    echo "$monitor_pid" > "$PID_FILE"
    
    echo "[INFO] Surveillance lancée en arrière-plan avec PID $monitor_pid" >> "$LOG_FILE"
}
