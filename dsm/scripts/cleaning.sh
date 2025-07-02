#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <app_name>"
    exit 1
fi

APP="$1"

# Pattern base da uccidere sempre
PATTERNS=(
    "$APP 2" 
    "main_restore.sh $APP"
    "criu restore --shell-job --dsm_server"
)

# Scansiona tutti i processi
ps -eo pid,cmd | while read -r pid cmd; do
    for pattern in "${PATTERNS[@]}"; do
        if [[ "$cmd" == *"$pattern"* ]]; then
            kill -9 "$pid" 2>/dev/null
            break
        fi
    done
done

