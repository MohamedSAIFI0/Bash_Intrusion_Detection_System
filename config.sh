#!/bin/bash
# Configuration du système de détection d'intrusion

# Chemins des fichiers de logs à surveiller
LOG_AUTH="/var/log/auth.log"
LOG_SYSLOG="/var/log/syslog"
LOG_MESSAGES="/var/log/messages"
LOG_NGINX="/var/log/nginx/access.log"

# Chemins des fichiers de l'IDS
LOG_DIR="$(dirname "$(readlink -f "$0")")/logs"
INTRUSION_LOG="$LOG_DIR/intrusion.log"
REPORT_DIR="$(dirname "$(readlink -f "$0")")/reports"
WEEKLY_REPORT="$REPORT_DIR/weekly_report.txt"

# Configuration des seuils d'alerte
SSH_FAIL_THRESHOLD=5          # Nombre d'échecs de connexion SSH avant alerte
SCAN_THRESHOLD=10             # Nombre de scans de ports avant alerte
BRUTE_FORCE_THRESHOLD=15      # Nombre de tentatives de brute force avant alerte
TIME_WINDOW=300               # Fenêtre de temps en secondes pour considérer des événements comme liés (5 minutes)

# Configuration des alertes
ENABLE_EMAIL=false            # Activer/désactiver les alertes par email
EMAIL_RECIPIENT="saifimsc@gmail.com"  # Adresse email pour les alertes
ENABLE_WALL=true              # Activer/désactiver les messages wall

# Configuration du blocage automatique
ENABLE_AUTO_BLOCK=false       # Activer/désactiver le blocage automatique
BLOCK_DURATION=3600           # Durée du blocage en secondes (1 heure)
USE_UFW=false                 # Utiliser UFW au lieu d'iptables

# Configuration de l'interface utilisateur
UI_TOOL="whiptail"            # "whiptail" ou "dialog"
TERMINAL_WIDTH=80             # Largeur du terminal pour l'affichage
TERMINAL_HEIGHT=24            # Hauteur du terminal pour l'affichage

# Configuration du daemon
CHECK_INTERVAL=5              # Intervalle de vérification en secondes en mode daemon

# Regex pour la détection d'événements suspects
SSH_FAIL_PATTERN="Failed password for .* from .* port"
ROOT_ACCESS_PATTERN="Failed password for root from .* port"
PORT_SCAN_PATTERN="SRC=.* DST=.* PROTO=(TCP|UDP) .* DPT="
BRUTE_FORCE_PATTERN="Failed password for .* from .* port .* ssh"

# Activer le mode debug (plus de détails dans les logs)
DEBUG=false