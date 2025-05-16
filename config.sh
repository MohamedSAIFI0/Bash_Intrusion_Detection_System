#!/bin/bash
# Fichier de configuration pour le système IDS

# === Chemins des répertoires et fichiers ===
LOG_DIR="$SCRIPT_DIR/logs"                      # Répertoire où stocker les journaux
REPORT_DIR="$SCRIPT_DIR/reports"                # Répertoire des rapports
LOG_FILE="$LOG_DIR/intrusion.log"               # Fichier de log d'intrusions
REPORT_FILE="$REPORT_DIR/weekly_report.txt"     # Rapport hebdomadaire

# === Fichier de log système à surveiller ===
SYSLOG_FILE="/var/log/auth.log"                 # Peut être adapté selon le système

# === Seuils de détection ===
MAX_FAILED_ATTEMPTS=5         # Nombre d’échecs max autorisé avant alerte
MONITOR_INTERVAL=30           # Temps (en secondes) entre chaque scan des logs
ALERT_COOLDOWN=60             # Délai entre 2 alertes pour une même IP

# === Méthode d’alerte ===
# Options possibles : wall, email
ALERT_METHOD="wall"

# Pour email (si activé)
#EMAIL_TO="admin@example.com"

# === Pare-feu utilisé ===
# Options possibles : ufw, iptables, none
FIREWALL_METHOD="ufw"

# === Adresse IP locales (jamais bloquées) ===
WHITELIST_IPS=("127.0.0.1" "192.168.1.1")

# === Regex de détection d'intrusions (ligne à rechercher dans le fichier log) ===
# Exemples : tentatives SSH échouées
PATTERNS=(
  "Failed password for"
  "authentication failure;"
  "Invalid user"
)

# === Autres paramètres optionnels ===
ENABLE_LOG_ROTATION=true         # Rotation automatique du log
MAX_LOG_SIZE=1000000             # Taille max du fichier log en octets avant rotation

