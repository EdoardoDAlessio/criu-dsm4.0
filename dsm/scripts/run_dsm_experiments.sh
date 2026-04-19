#!/usr/bin/env bash
set -e

##############################################
### PHASE FLAGS — set to 1 to run, 0 to skip
##############################################
SKIP_ALL=0
DO_VANILLA=1
DO_DUMP=1
DO_SCP=1
DO_RESTORE_SERVER=1
DO_RESTORE_CLIENTS=1
SERVER_VERBOSE=0
CLIENT_VERBOSE=0

if [[ "$SKIP_ALL" -eq 1 ]]; then
    DO_VANILLA=0
    DO_DUMP=0
    DO_SCP=0
    DO_RESTORE_SERVER=0
    DO_RESTORE_CLIENTS=0FLAGCLIENT="$FLAGCLIENT --rdma"
fi
##############################################

##############################################
### SIGNAL HANDLER — MAKE CTRL+C WORK
##############################################
cleanup() {
    echo ""
    echo "=== Ctrl+C received → Cleaning up ==="
    jobs -p | xargs -r kill -9 2>/dev/null || true
    sudo pkill -9 -f "criu"      2>/dev/null || true
    pkill -9 -f "$APP_EXEC"      2>/dev/null || true
    sudo pkill -9 -f "criu restore" 2>/dev/null || true
    pkill -9 -f "restorer.sh"    2>/dev/null || true
    pkill -9 -f "thread_filter"  2>/dev/null || true
    pkill -9 ssh                 2>/dev/null || true
    echo "=== Cleanup complete, exiting ==="
    exit 1
}

trap cleanup INT

##############################################
### 0) ARGUMENT PARSING
##############################################
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <app-name> <num-cores> [suffix]"
    exit 1
fi

APP="$1"
N_CORES="$2"
SUFFIX="${3:-}"
CONFIG_DIR="$(dirname "$0")/config"
CONFIG_FILE="$CONFIG_DIR/${APP}_config"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Missing config file: $CONFIG_FILE"
    exit 1
fi

source "$CONFIG_FILE"

##############################
# PARSE CONFIG LINE
##############################
read -ra TOK <<< "${CONFIGS[0]}"

CONF_NAME="${TOK[0]}"
N_CLIENTS="${TOK[1]}"
MODE="${TOK[-1]}"
MAIN_RANGE="${TOK[2]}"

C_RANGE=()
for ((i=0; i<N_CLIENTS; i++)); do
    C_RANGE+=("${TOK[$((3 + i))]}")
done

FLAGCLIENT="$MODE"

echo "======================================"
echo " Loaded config: $CONFIG_FILE"
echo "======================================"
echo "CONF_NAME   = $CONF_NAME"
echo "N_CLIENTS   = $N_CLIENTS"
echo "MAIN_RANGE  = $MAIN_RANGE"
echo "C_RANGE     = ${C_RANGE[*]}"
echo "MODE        = $MODE"
echo "FLAGCLIENT  = $FLAGCLIENT"
echo ""
echo "--- Phases ---"
echo "DO_VANILLA        = $DO_VANILLA"
echo "DO_DUMP           = $DO_DUMP"
echo "DO_SCP            = $DO_SCP"
echo "DO_RESTORE_SERVER = $DO_RESTORE_SERVER"
echo "SERVER_VERBOSE    = $SERVER_VERBOSE"
echo "DO_RESTORE_CLIENTS= $DO_RESTORE_CLIENTS"
echo "CLIENT_VERBOSE    = $CLIENT_VERBOSE"
echo "======================================"
sleep 1

THREADS="$APP_THREADS"

mkdir -p "$SCRIPTS/results/${APP}/"
CSV="$SCRIPTS/results/${APP}/dsm_results_${APP}_${N_CORES}_cores${SUFFIX:+_$SUFFIX}.csv"

MAX_PHYSICAL=28
CPU_LIST="0"

for ((i=1; i<N_CORES && i<MAX_PHYSICAL; i++)); do
    CPU_LIST+=",$((i*2))"
done

if (( N_CORES > MAX_PHYSICAL )); then
    extra=$((N_CORES - MAX_PHYSICAL))
    for ((j=0; j<extra; j++)); do
        CPU_LIST+=",$((j*2+1))"
    done
fi

echo "[INFO] Using CPU list: $CPU_LIST"

##############################################
### UTILS
##############################################
run_cmd() { echo ">>> CMD: $*"; eval "$*"; }

echo "cores,config,transport,dump,scp_s,filter,restore,exec" > "$CSV"

echo "=== Clean previous runs ==="
sudo pkill -9 -f "criu" || true


##############################################
### VANILLA
##############################################
if [[ "$DO_VANILLA" -eq 1 ]]; then
    echo "=== Running VANILLA (no DSM) ==="

    cd "$APP_SOURCE_DIR"

    sudo rm -f /tmp/dsm_exec_time_sec
    touch /tmp/haltcode

    echo "$THREADS" | sudo tee /tmp/restored_threads.txt >/dev/null
    t_van_start=$(date +%s.%N)

    #DSM=$THREADS ./${APP_EXEC} ${APP_ARGS}
    t_van_end=$(date +%s.%N)

    exec_internal=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo "0")
    exec_total=$(echo "$t_van_end - $t_van_start" | bc -l)

    echo "VANILLA internal exec = $exec_internal"
    echo "VANILLA total time    = $exec_total"

    echo "$N_CORES,vanilla,0,0,0,0,$exec_total,$exec_internal" >> "$CSV"
    echo "=== Vanilla done ==="
    echo ""
    sleep 1
else
    echo "=== [SKIP] VANILLA ==="
fi


##############################################
### DUMP PHASE
##############################################
if [[ "$DO_DUMP" -eq 1 ]]; then
    echo "=== Dump (inline) ==="
    t_init=$(date +%s.%N)

    sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt
    rm -rf /users/EdoDale/"${APP}"
    mkdir -p /users/EdoDale/"${APP}/images"

    cp "${APP_SOURCE_DIR}/${APP_EXEC}" /users/EdoDale/"${APP}/"

    if [[ ${#APP_EXTRA_FILES[@]} -gt 0 ]]; then
        for f in "${APP_EXTRA_FILES[@]}"; do
            cp "${APP_SOURCE_DIR}/${f}" /users/EdoDale/"${APP}/" 2>/dev/null || true
        done
    fi

    cd /users/EdoDale/"${APP}"

    echo "🚀 Launching $APP with DSM=$THREADS"
    sudo rm -f /tmp/criu-restored.pid /tmp/haltcode

    DSM=$THREADS ./${APP_EXEC} ${APP_ARGS} &
    app_pid=$!
    echo "APP PID = $app_pid"
    sleep "$APP_WARMUP"
    t0=$(date +%s.%N)

    echo "📦 Dumping with CRIU..."
    sudo /users/EdoDale/criu/criu/criu dump -t "$app_pid" --images-dir /users/EdoDale/"${APP}/images" --shell-job -v || true

    cp /tmp/ranges.txt /users/EdoDale/"${APP}/images/" 2>/dev/null || true
    cp /tmp/dsm_barrier_pages.txt /users/EdoDale/"${APP}/images/" 2>/dev/null || true
    cp /tmp/dsm_mutex.txt /users/EdoDale/"${APP}/images/" 2>/dev/null || true

    cp -r /users/EdoDale/"${APP}/images" /users/EdoDale/"${APP}/backup"

    t1=$(date +%s.%N)
    dump_time=$(echo "$t1 - $t0" | bc -l)
    init_time=$(echo "$t0 - $t_init - $APP_WARMUP" | bc -l)
    echo "=== Dump done (dump_time=$dump_time) ==="
else
    echo "=== [SKIP] DUMP ==="
    # If dump was skipped, assume times are zero (restore will use existing images)
    dump_time=0
    init_time=0
fi


##############################################
### SCP PHASE
##############################################
if [[ "$DO_SCP" -eq 1 ]]; then
    echo "=== SCP ==="
    t2=$(date +%s.%N)

    for client in "${CLIENTS[@]}"; do
        echo "[SCP] → $client"
        ssh -o StrictHostKeyChecking=no "$client" "sudo rm -rf /users/EdoDale/${APP}"
        scp -r /users/EdoDale/"${APP}" "$client":/users/EdoDale/
    done

    t3=$(date +%s.%N)
    scp_time=$(echo "$t3 - $t2" | bc -l)
    echo "=== SCP done (scp_time=$scp_time) ==="
else
    echo "=== [SKIP] SCP ==="
    scp_time=0
fi


##############################################
### RESTORE CONFIGS LOOP
##############################################
echo "=== Running configs ==="

sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt
PIDS=()

for cfg in "${CONFIGS[@]}"; do

    read -ra TOK <<< "$cfg"

    CONF_NAME="${TOK[0]}"
    N_CLIENTS="${TOK[1]}"
    MAIN_RANGE="${TOK[2]}"
    MODE="${TOK[-1]}"

    C_RANGE=()
    for ((i=0; i<N_CLIENTS; i++)); do
        C_RANGE+=("${TOK[$((3 + i))]}")
    done

    FLAGSERVER=""
    FLAGCLIENT=""
    [[ "$CLIENT_VERBOSE" == 1 ]] && FLAGCLIENT="--verbose"
    [[ "$MODE" == "rdma" ]] && FLAGSERVER="$FLAGSERVER --dsm-rdma-enable"
    [[ "$MODE" == "rdma" ]] && FLAGCLIENT="$FLAGCLIENT --rdma"

    echo ""
    echo "=========== $CONF_NAME ==============="
    echo "N_CLIENTS   = $N_CLIENTS"
    echo "MAIN_RANGE  = $MAIN_RANGE"
    echo "C_RANGE     = ${C_RANGE[*]}"
    echo "MODE        = $MODE"
    echo ""

    ##########################################
    ### FILTER IMAGES
    ##########################################
    echo "[SERVER] Filtering images..."
    t3a=$(date +%s.%N)

    sudo rm -rf /users/EdoDale/"$APP"/images/
    cp -r /users/EdoDale/"$APP"/backup/ /users/EdoDale/"$APP"/images/

    cd /users/EdoDale/"$APP"/images
    "$PYTHON_PATH" "$THREAD_FILTER" "$MAIN_RANGE"

    t3b=$(date +%s.%N)
    filter_time=$(echo "$t3b - $t3a" | bc -l)

    ##########################################
    ### RESTORE — SERVER
    ##########################################
    if [[ "$DO_RESTORE_SERVER" -eq 1 ]]; then
        echo "[SERVER] Inline restore..."

        sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt \
                /tmp/criu-restored.pid /tmp/dsm_exec_time_sec \
                /tmp/restored_threads.txt /tmp/authorized_barrier_thread.txt

        first=$(echo "$MAIN_RANGE" | cut -d'-' -f1)
        second=$(echo "$MAIN_RANGE" | cut -d'-' -f2)
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

        RESTORE_CMD="sudo /users/EdoDale/criu/criu/criu restore --shell-job --dsm_server $N_CLIENTS -o /tmp/criu_restore.log"
        [[ "$MODE" == "rdma" ]] && RESTORE_CMD+=" --dsm-rdma-enable"
        [[ "$SERVER_VERBOSE"  -eq 1     ]] && RESTORE_CMD+=" -v"
        echo "Restore command: $RESTORE_CMD"

        t4=$(date +%s.%N)
        script -q -c "$RESTORE_CMD" /dev/null &
        RESTORE_PID=$!
    else
        echo "=== [SKIP] RESTORE_SERVER ==="
        t4=$(date +%s.%N)
        RESTORE_PID=""
    fi

    ##########################################
    ### RESTORE — CLIENTS
    ##########################################
    PIDS=()

    if [[ "$DO_RESTORE_CLIENTS" -eq 1 ]] && (( N_CLIENTS > 0 )); then
        for (( cid=0; cid<N_CLIENTS; cid++ )); do
            CLIENT_HOST="${CLIENTS[$cid]}"
            echo "[CLIENT-$cid] Starting restore on $CLIENT_HOST..., $FLAGCLIENT"

            ssh "$CLIENT_HOST" "
                cd /users/EdoDale/criu/dsm/scripts || exit 1
                source /users/EdoDale/venv-criu/bin/activate || true
                taskset -c $CPU_LIST sudo ./restorer.sh $APP ${C_RANGE[$cid]} $FLAGCLIENT
            " 2>&1 | tee /tmp/client_${cid}_${CONF_NAME}.log &

            PIDS+=($!)
        done
    else
        echo "=== [SKIP] RESTORE_CLIENTS ==="
    fi

    [[ -n "$RESTORE_PID" ]] && wait $RESTORE_PID
    t5=$(date +%s.%N)

    for p in "${PIDS[@]}"; do wait "$p"; done

    # Pull client CRIU logs back
    if [[ "$DO_RESTORE_CLIENTS" -eq 1 ]] && (( N_CLIENTS > 0 )); then
        for (( cid=0; cid<N_CLIENTS; cid++ )); do
            scp "${CLIENTS[$cid]}:/tmp/criu_client_restore.log" \
                "/tmp/criu_client_${cid}_${CONF_NAME}.log" 2>/dev/null || true
        done
    fi

    exec_time=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo "0.0")
    restore_total=$(echo "$t5 - $t4" | bc -l)
    restore_overhead=$(echo "$restore_total - $exec_time" | bc -l)

    echo "RESTORE OVERHEAD = $restore_overhead"
    echo "EXEC TIME        = $exec_time"

    run_cmd "sudo sh -c 'echo \"$N_CORES,$CONF_NAME,$MODE,$dump_time,$scp_time,$filter_time,$restore_overhead,$exec_time\" >> \"$CSV\"'"

    touch /tmp/page_test_times.csv
    cp /tmp/page_test_times.csv "/tmp/page_test_times_${MODE}.csv"

    echo ">>> Finished $CONF_NAME"
done

echo "=== ALL DONE ==="

paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga