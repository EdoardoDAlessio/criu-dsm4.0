#!/usr/bin/env bash
set -e

##############################################
### 0) ARGUMENT PARSING
##############################################
if [ $# -ne 1 ]; then
    echo "Usage: $0 <app-name>"
    exit 1
fi

APP="$1"
CONFIG_DIR="$SCRIPTS/config"
CONFIG_FILE="${APP}_config"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Missing config file: $CONFIG_FILE"
    exit 1
fi

# Load ALL app-specific information
source "$CONFIG_FILE"

# Threads come from config
THREADS="$APP_THREADS"

# CSV output depends on app
CSV="$SCRIPTS/results/dsm_results_${APP}.csv"

##############################################
### UTILS
##############################################
run_cmd() { echo ">>> CMD: $*"; eval "$*"; }

# CSV header
echo "config,dump_s,scp_s,filter_s,restore_s,exec_s" > "$CSV"

echo "=== Clean previous runs ==="
sudo pkill -9 -f "criu" || true

##############################################
### 1) DUMP PHASE (INLINE)
##############################################
echo "=== Dump (inline) ==="
t0=$(date +%s.%N)

# --- CLEAN temp ---
sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt
rm -rf ~/"${APP}"
mkdir -p ~/"${APP}/images"

# --- COPY APPLICATION FROM CONFIG ---
cp "${APP_SOURCE_DIR}/${APP_EXEC}" ~/"${APP}/"

# Copy extra data if defined
if [[ ${#APP_EXTRA_FILES[@]} -gt 0 ]]; then
    for f in "${APP_EXTRA_FILES[@]}"; do
        cp "${APP_SOURCE_DIR}/${f}" ~/"${APP}/" 2>/dev/null || true
    done
fi

cd ~/"${APP}"

# --- RUN APPLICATION ---
echo "🚀 Launching $APP with DSM=$THREADS"
sudo rm -f /tmp/criu-restored.pid /tmp/haltcode

DSM=$THREADS ./${APP_EXEC} ${APP_ARGS} &
app_pid=$!
echo "APP PID = $app_pid"
sleep "$APP_WARMUP"

# --- CRIU DUMP ---
echo "📦 Dumping with CRIU..."
sudo ~/criu/criu/criu dump -t "$app_pid" --images-dir ~/"${APP}/images" \
     --shell-job -v || true

# --- COPY METADATA ---
cp /tmp/ranges.txt ~/"${APP}/images/" 2>/dev/null || true
cp /tmp/dsm_barrier_pages.txt ~/"${APP}/images/" 2>/dev/null || true
cp /tmp/dsm_mutex.txt ~/"${APP}/images/" 2>/dev/null || true

# --- BACKUP ---
cp -r ~/"${APP}/images" ~/"${APP}/backup"
#exit
t1=$(date +%s.%N)
dump_time=$(echo "$t1 - $t0 - $APP_WARMUP" | bc -l)

##############################################
### 2) SCP PHASE
##############################################
echo "=== SCP ==="
t2=$(date +%s.%N)

for client in "${CLIENTS[@]}"; do
    echo "[SCP] → $client"
    ssh -o StrictHostKeyChecking=no "$client" "sudo rm -rf ~/${APP}"
    scp -r ~/"${APP}" "$client":~/
done

t3=$(date +%s.%N)
scp_time=$(echo "$t3 - $t2" | bc -l)


##############################################
### 3) RESTORE CONFIGS LOOP
##############################################
echo "=== Running configs ==="

sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt
PIDS=()

for cfg in "${CONFIGS[@]}"; do
    read -r LABEL S_RANGE C_RANGE N_CLIENTS PROTO <<< "$cfg"

    echo ""
    echo "=========== $LABEL ==============="

    #FLAGCLIENT="--verbose"
    #FLAGSERVER="--verbose"
    FLAGSERVER=""
    FLAGCLIENT=""
    [[ "$PROTO" == "rdma" ]] && FLAGSERVER="$FLAGSERVER --dsm-rdma-enable"
    [[ "$PROTO" == "rdma" ]] && FLAGCLIENT="$FLAGCLIENT --rdma"

    ##########################################
    ### FILTER IMAGES
    ##########################################
    echo "[SERVER] Filtering images..."
    t3a=$(date +%s.%N)

    sudo rm -rf ~/"$APP"/images/
    cp -r ~/"$APP"/backup/ ~/"$APP"/images/

    cd ~/"$APP"/images
    python3 "$THREAD_FILTER" "$S_RANGE"

    t3b=$(date +%s.%N)
    filter_time=$(echo "$t3b - $t3a" | bc -l)

    ##########################################
    ### RESTORE
    ##########################################
    t4=$(date +%s.%N)

    echo "[SERVER] Inline restore..."

    sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt \
            /tmp/criu-restored.pid /tmp/dsm_exec_time_sec \
            /tmp/restored_threads.txt /tmp/authorized_barrier_thread.txt

    first=$(echo "$S_RANGE" | cut -d'-' -f1)
    second=$(echo "$S_RANGE" | cut -d'-' -f2)
    gap=$((second - first + 1))

    echo "$gap"   | sudo tee /tmp/restored_threads.txt >/dev/null
    echo "$first" | sudo tee /tmp/authorized_barrier_thread.txt >/dev/null

    cp ranges.txt /tmp/ranges.txt 2>/dev/null || true
    cp dsm_barrier_pages.txt /tmp/dsm_barrier_pages.txt 2>/dev/null || true
    cp dsm_mutex.txt /tmp/dsm_mutex.txt 2>/dev/null || true

    unset DSM
    export DSM=0

    touch /tmp/.restore_flag
    touch /tmp/haltcode
    RESTORE_CMD="sudo ~/criu/criu/criu restore --shell-job --dsm_server $N_CLIENTS"
    [[ "$PROTO" == "rdma" ]] && RESTORE_CMD+=" --dsm-rdma-enable"
    #RESTORE_CMD+=" -v"

    script -q -c "$RESTORE_CMD" /dev/null &
    RESTORE_PID=$!

    ##############################################
    ### 3) LAUNCH CLIENT SIDE IF NEEDED
    ##############################################
    PIDS=()
    if [[ "$N_CLIENTS" -ge 1 ]]; then
        C1="${CLIENTS[0]}"
        echo "[CLIENT] Starting restore on $C1..."

       ssh -tt "$C1" "
    cd ~/criu/dsm/scripts || exit 1
    source ~/venv-criu/bin/activate || true
    ./restorer.sh $APP $C_RANGE $FLAGCLIENT
" &

        PIDS+=($!)
    fi

    wait $RESTORE_PID
    t5=$(date +%s.%N)

    for p in "${PIDS[@]}"; do wait "$p"; done

    exec_time=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo "0.0")
    restore_total=$(echo "$t5 - $t4" | bc -l)
    restore_overhead=$(echo "$restore_total - $exec_time" | bc -l)

    echo "RESTORE OVERHEAD = $restore_overhead"
    echo "EXEC TIME        = $exec_time"

    run_cmd "sudo sh -c 'echo \"$LABEL,$dump_time,$scp_time,$filter_time,$restore_overhead,$exec_time\" >> \"$CSV\"'"

    echo ">>> Finished $LABEL"
done

echo "=== ALL DONE ==="
