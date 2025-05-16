#!/bin/bash
# Script principal du système de detection d'intrusion (IDS) Bash

# Recuperer le chemin du script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Sourcer les fichiers de configuration et de fonctions
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/functions/monitor.sh"
source "$SCRIPT_DIR/functions/alert.sh"
source "$SCRIPT_DIR/functions/firewall.sh"

#Les Variables globales
MONITORING_ACTIVE=false
PID_FILE="$LOG_DIR/ids.pid"



#Verifier si L'IDS est en cours d'execution
is_ids_running(){
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0  # Le processus est en cours d'execution
        else
            # Supprimer le fichier PID obsolete
            rm -f "$PID_FILE"
        fi
    fi
    return 1  # L'IDS n'est pas en cours d'execution
}


# Fonction pour enregistrer le PID
save_pid() {
    echo $$ > "$PID_FILE"
}



# Fonction pour demarrer l'IDS
start_ids() {
    if is_ids_running; then
        echo "[ERREUR] L'IDS est déjà en cours d'exécution" >> "$INTRUSION_LOG"
        return 1
    fi
    
    # Créer les répertoires de logs et de rapports 
    mkdir -p "$LOG_DIR" "$REPORT_DIR"
    
    # Demarrer la surveillance
    start_monitoring
    
    # Enregistrer le PID
    save_pid
    
    MONITORING_ACTIVE=true
    
    echo "[INFO] IDS démarré avec succès (PID: $$)" >> "$INTRUSION_LOG"
    return 0
}

# Fonction pour arrêter l'IDS
stop_ids() {
    if ! is_ids_running; then
        echo "[ERREUR] L'IDS n'est pas en cours d'exécution" >> "$INTRUSION_LOG"
        return 1
    fi
    
    stop_monitoring
    
    # Supprimer le fichier PID
    rm -f "$PID_FILE"
    
    MONITORING_ACTIVE=false
    
    echo "[INFO] IDS arrêté avec succès" >> "$INTRUSION_LOG"
    return 0
}

# Fonction pour afficher l'etat de l'IDS
status_ids() {
    local status_file="$LOG_DIR/ids_status.txt"
    
    echo "=== ÉTAT DE L'IDS BASH ===" > "$status_file"
    echo "Date de vérification: $(date)" >> "$status_file"
    echo "" >> "$status_file"
    
    if is_ids_running; then
        local pid=$(cat "$PID_FILE")
        echo "STATUT: ACTIF (PID: $pid)" >> "$status_file"
        echo "En fonctionnement depuis: $(ps -p $pid -o lstart=)" >> "$status_file"
    else
        echo "STATUT: INACTIF" >> "$status_file"
    fi
    
    echo "" >> "$status_file"
    
    # Nombre d'alertes récentes
    local recent_alerts=$(grep -c "\[ALERTE\]" "$INTRUSION_LOG" 2>/dev/null || echo "0")
    echo "Alertes récentes: $recent_alerts" >> "$status_file"
    
    # Nombre d'IPs bloquées
    echo "IPs actuellement bloquées: ${#BLOCKED_IPS[@]}" >> "$status_file"
    
    echo "" >> "$status_file"
    echo "Fichiers logs surveillés:" >> "$status_file"
    
    # Vérifier quels fichiers logs sont surveillés
    for log_file in "$LOG_AUTH" "$LOG_SYSLOG" "$LOG_MESSAGES" "$LOG_NGINX"; do
        if [[ -f "$log_file" ]]; then
            echo "  - $log_file (OK)" >> "$status_file"
        else
            echo "  - $log_file (INTROUVABLE)" >> "$status_file"
        fi
    done
    
    echo "" >> "$status_file"
    echo "Configuration:" >> "$status_file"
    echo "  - Alertes par email: $ENABLE_EMAIL" >> "$status_file"
    echo "  - Alertes wall: $ENABLE_WALL" >> "$status_file"
    echo "  - Blocage automatique: $ENABLE_AUTO_BLOCK" >> "$status_file"
    if [[ "$ENABLE_AUTO_BLOCK" == "true" ]]; then
        echo "  - Durée de blocage: $BLOCK_DURATION secondes" >> "$status_file"
        echo "  - Pare-feu utilisé: $([[ "$USE_UFW" == "true" ]] && echo "UFW" || echo "iptables")" >> "$status_file"
    fi
    
    echo "" >> "$status_file"
    echo "================" >> "$status_file"
    
    cat "$status_file"
    echo "[INFO] État de l'IDS généré dans $status_file" >> "$INTRUSION_LOG"
    
    return 0
}