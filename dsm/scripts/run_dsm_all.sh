#!/usr/bin/env bash
set -euo pipefail

#############################
# USER CONFIGURATION
#############################

APP="histogram-dsm"
THREADS=64
INPUT="/users/EdoDale/phoenix/phoenix-2.0/tests/input/histogram_datafiles/large.bmp"
ARG="100"

CLIENTS=("dsm_client" "dsm_client2")
APP_DIR="$HOME/$APP"
IMAGES_DIR="$APP_DIR/images"
BACKUP_DIR="$APP_DIR/backup"

OUT_CSV="dsm_results.csv"

# The app will write execution time here
APP_EXEC_TIME="/tmp/dsm_exec_time_sec"

#############################
# CONFIGURATION LIST
#############################

CONFIGS=(
  "base_tcp     0-63    -       0   tcp"
  "base_rdma    0-63    -       0   rdma"

  "split32_tcp  0-31   32-63    1   tcp"
  "split32_rdma 0-31   32-63    1   rdma"

  "split16_tcp  0-15   16-63    1   tcp"
  "split16_rdma 0-15   16-63    1   rdma"

  "split20_tcp  0-19   20-63    1   tcp"
  "split20_rdma 0-19   20-63    1   rdma"
)

#############################
# HELPER FUNCTIONS
#############################

now() { date +%s.%N; }
elapsed() { echo "$2 - $1" | bc; }

run_cmd() {
    echo ""
    echo ">>> CMD: $*"
    bash -c "$*"   # ensures no tty contamination
}

ssh_bg() {
    # ssh without tty, background
    local node="$1"
    shift
    echo ">>> SSH BG: $node -- $*"
    ssh -T "$node" "nohup bash -c \"$*\" </dev/null >/dev/null 2>&1 &" &
    PIDS+=($!)
}

#############################
# 1. DUMP PHASE (NO TTY)
#############################

run_dump() {
    echo "=== [1] Dumping ==="

    local start=$(now)

    # Run the application detached WITHOUT A TTY
    echo "[dump] launch app without TTY"
    nohup bash -c "DSM=$THREADS $APP_DIR/$APP $INPUT $ARG" \
        </dev/null >/dev/null 2>&1 &

    sleep 1

    # Perform the dump
    echo "[dump] running criu dump"
    sudo criu dump --shell-job -D "$IMAGES_DIR" -o dump.log

    local end=$(now)
    elapsed "$start" "$end"
}

#############################
# 2. DISTRIBUTE IMAGES
#############################

distribute() {
    echo "=== [2] Distributing images ==="

    local start=$(now)

    for C in "${CLIENTS[@]}"; do
        echo "[scp] to $C"
        ssh "$C" "rm -rf $APP_DIR && mkdir -p $APP_DIR"
        scp -r "$APP_DIR" "$C:$HOME/"
    done

    local end=$(now)
    elapsed "$start" "$end"
}

#############################
# 3. RESTORE SERVER (BG)
#############################

start_server_restore() {
    local range="$1"
    local ncli="$2"
    local flags="$3"

    echo ">>> Starting SERVER restore (bg)"
    nohup bash -c "cd $APP_DIR && sudo criu restore --shell-job --dsm_server $ncli $flags </dev/null >/dev/null 2>&1" &
    SERVER_PID=$!
}

#############################
# 4. START CLIENT RESTORES
#############################

start_client_restore() {
    local node="$1"
    local range="$2"
    local flags="$3"

    echo ">>> Starting CLIENT restore on $node"
    ssh_bg "$node" "cd $APP_DIR && sudo criu restore --shell-job --dsm_client $range $flags"
}

#############################
# 5. RUN ONE CONFIG
#############################

run_config() {
    local label="$1"
    local S_RANGE="$2"
    local C_RANGE="$3"
    local NCLIENTS="$4"
    local proto="$5"

    echo ""
    echo "======== CONFIG: $label ========"

    FLAGS="-v"
    [[ "$proto" == "rdma" ]] && FLAGS="$FLAGS --dsm-rdma-enable"

    echo "[reset] restoring clean images"
    rm -rf "$IMAGES_DIR"
    cp -r "$BACKUP_DIR" "$IMAGES_DIR"

    for ((i=0; i<NCLIENTS; i++)); do
        node="${CLIENTS[$i]}"
        ssh "$node" "rm -rf $IMAGES_DIR && cp -r $BACKUP_DIR $IMAGES_DIR"
    done

    rm -f "$APP_EXEC_TIME"

    local t_start=$(now)

    # SERVER first (background)
    start_server_restore "$S_RANGE" "$NCLIENTS" "$FLAGS"

    # CLIENTS
    PIDS=()
    if [[ "$NCLIENTS" -ge 1 ]]; then
        start_client_restore "${CLIENTS[0]}" "$C_RANGE" "$FLAGS"
    fi
    if [[ "$NCLIENTS" -ge 2 ]]; then
        start_client_restore "${CLIENTS[1]}" "$C_RANGE" "$FLAGS"
    fi

    # WAIT
    echo "[wait] server pid=$SERVER_PID"
    wait "$SERVER_PID"

    if (( ${#PIDS[@]} > 0 )); then
        echo "[wait] client pids: ${PIDS[*]}"
        wait "${PIDS[@]}"
    fi

    local t_end=$(now)
    local t_total=$(elapsed "$t_start" "$t_end")

    # get exec time from app
    local t_exec="-1"
    if [[ -f "$APP_EXEC_TIME" ]]; then
        t_exec=$(cat "$APP_EXEC_TIME")
    fi

    local t_restore="-1"
    if [[ "$t_exec" != "-1" ]]; then
        t_restore=$(echo "$t_total - $t_exec" | bc)
    fi

    echo "$label,$t_total,$t_exec,$t_restore" >> "$OUT_CSV"
}

#############################
# MAIN
#############################

echo "app,label,t_total,t_exec,t_restore" > "$OUT_CSV"

echo "[MASTER] Dump phase"
T_DUMP=$(run_dump)

echo "[MASTER] Distribution phase"
T_SCP=$(distribute)

echo "[MASTER] Running configs..."
for cfg in "${CONFIGS[@]}"; do
    read -r LABEL S_RANGE C_RANGE NCLIENTS PROTO <<< "$cfg"
    run_config "$LABEL" "$S_RANGE" "$C_RANGE" "$NCLIENTS" "$PROTO"
done

echo ""
echo "=== DONE ==="
echo "Results → $OUT_CSV"
