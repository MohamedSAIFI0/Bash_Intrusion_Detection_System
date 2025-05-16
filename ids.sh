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

