#!/usr/bin/env bash
set -e

##############################################
# USAGE CHECK
##############################################
if [ $# -ne 1 ]; then
    echo "Usage: $0 <app-name>"
    exit 1
fi

APP="$1"
CONFIG_DIR="$(dirname "$0")/config"
CONFIG_FILE="$CONFIG_DIR/${APP}_config"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Missing config file: $CONFIG_FILE"
    exit 1
fi

# Load config (paths, APP_EXEC, APP_SOURCE_DIR, etc.)
source "$CONFIG_FILE"

##############################################
# READ CORES LIST FROM CONFIG FILE
##############################################
# Expected line inside config:
#    CORES_CONFIG="1 2 4 6 8"
##############################################
CORES_CONFIG="8 2 3 4 5 7"


if [ -z "${CORES_CONFIG}" ]; then
    echo "❌ CORES_CONFIG not defined in $CONFIG_FILE"
    exit 1
fi

echo "[INFO] Core configs: ${CORES_CONFIG}"

##############################################
# OUTPUT CSV
##############################################
CSV="$SCRIPTS/results/vanilla_local_${APP}.csv"
echo "cores,exec_s,tot" > "$CSV"

##############################################
# CPU LIST BUILDER
##############################################
build_cpu_list() {
    local N=$1
    local MAX_PHYSICAL=28
    local cpu_list="0"

    # 1) physical cores (even IDs)
    for ((i=1; i<N && i<MAX_PHYSICAL; i++)); do
        cpu_list+=",$((i*2))"
    done

    # 2) SMT if needed
    if (( N > MAX_PHYSICAL )); then
        extra=$((N - MAX_PHYSICAL))
        for ((j=0; j<extra; j++)); do
            cpu_list+=",$((j*2+1))"
        done
    fi

    echo "$cpu_list"
}

##############################################
# MAIN LOOP — VANILLA RUNS
##############################################
cd "$APP_SOURCE_DIR"

for N_CORES in ${CORES_CONFIG}; do
    echo ""
    echo "===== Running VANILLA on ${N_CORES} cores ====="

    CPU_LIST=$(build_cpu_list "$N_CORES")
    echo "[INFO] Using CPU list: $CPU_LIST"

    sudo rm -f /tmp/dsm_exec_time_sec
    t_start=$(date +%s.%N)

    # Run locally with taskset (NO DSM)
    export DSM=$APP_THREADS
    taskset -c "$CPU_LIST"  "./${APP_EXEC}" ${APP_ARGS}

    t_end=$(date +%s.%N)
    exec_wall=$(echo "$t_end - $t_start" | bc -l)

    # Or use the app-internal printed time
    internal=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo 0)

    echo "Wall time : $exec_wall"
    echo "Internal  : $internal"

    echo "${N_CORES},${internal},${exec_wall}" >> "$CSV"
done

echo ""
echo "=== DONE. Results in $CSV ==="
