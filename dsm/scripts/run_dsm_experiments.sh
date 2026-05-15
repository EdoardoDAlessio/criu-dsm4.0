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
CLIENT_OUTPUT_FILE=1

if [[ "$SKIP_ALL" -eq 1 ]]; then
    DO_VANILLA=0
    DO_DUMP=0
    DO_SCP=0
    DO_RESTORE_SERVER=0
    DO_RESTORE_CLIENTS=0
fi
##############################################
### SIGNAL HANDLER — MAKE CTRL+C WORK
##############################################
cleanup() {
    echo ""
    echo "=== Ctrl+C received → Cleaning up ==="

    # Kill all local background jobs started inside THIS script
    jobs -p | xargs -r kill -9 2>/dev/null || true

    # Kill CRIU processes
    sudo pkill -9 -f "criu"      2>/dev/null || true

    # Kill your app (dump target)
    pkill -9 -f "$APP_EXEC"      2>/dev/null || true

    # Kill restore processes
    sudo pkill -9 -f "criu restore" 2>/dev/null || true

    # Kill script subprocesses
    pkill -9 -f "restorer.sh"    2>/dev/null || true
    pkill -9 -f "thread_filter"  2>/dev/null || true

    # Kill remote SSH clients launched by this script
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
SUFFIX="${3:-}"    # empty if not provided
CONFIG_DIR="$(dirname "$0")/config"
CONFIG_FILE="$CONFIG_DIR/${APP}_config"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Missing config file: $CONFIG_FILE"
    exit 1
fi

# Load ALL app-specific information
source "$CONFIG_FILE"


##############################
# PARSE CONFIG LINE (NEW FORMAT)
##############################

# Tokenize the first config line
read -ra TOK <<< "${CONFIGS[0]}"

# Format:
#   NAME  N_CLIENTS  MAIN_RANGE  CLIENT_RANGES...  MODE
#
# Example:
#   split4_2_2_tcp  2 0-3 4-5 6-7 tcp

CONF_NAME="${TOK[0]}"
N_CLIENTS="${TOK[1]}"

MODE="${TOK[-1]}"   # last token

MAIN_RANGE="${TOK[2]}"

# Extract client ranges dynamically
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
echo "CLIENT_OUTPUT_FILE    = $CLIENT_OUTPUT_FILE"
echo "======================================"
sleep 1

# Threads come from config
THREADS="$APP_THREADS"

# CSV output depends on app
CSV="$SCRIPTS/results/${APP}/dsm_results_${APP}_${N_CORES}_cores${SUFFIX:+_$SUFFIX}.csv"

MAX_PHYSICAL=28
CPU_LIST="0"

#
# 1) Physical cores first → even CPU IDs (0,2,4,...)
#
for ((i=1; i<N_CORES && i<MAX_PHYSICAL; i++)); do
    CPU_LIST+=",$((i*2))"
done

#
# 2) SMT siblings if more cores requested → odd IDs (1,3,5,...)
#
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

# CSV header
touch "$CSV"
echo "cores,config,transport,dump,scp_s,filter,restore,exec" > "$CSV"

echo "=== Clean previous runs ==="
sudo pkill -9 -f "criu" || true


##############################################
### (0) RUN VANILLA LOCAL EXECUTION
##############################################
echo "=== Running VANILLA (no DSM) ==="

cd "$APP_SOURCE_DIR"

sudo rm -f /tmp/dsm_exec_time_sec
touch /tmp/haltcode

echo "$THREADS" | sudo tee /tmp/restored_threads.txt >/dev/null
t_van_start=$(date +%s.%N)

#DSM=$THREADS ./${APP_EXEC} ${APP_ARGS}
t_van_end=$(date +%s.%N)

# internal exec time (from benchmark)
exec_internal=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo "0")

# total wall-clock time
exec_total=$(echo "$t_van_end - $t_van_start" | bc -l)

echo "VANILLA internal exec = $exec_internal"
echo "VANILLA total time    = $exec_total"

# write CSV line:
# columns: config,init,dump_s,scp_s,filter_s,restore_s,exec_s
echo "$N_CORES,vanilla,0,0,0,0,$exec_total,$exec_internal" >> "$CSV"

echo "=== Vanilla done ==="
echo ""
sleep 1



##############################################
### 1) DUMP PHASE (INLINE)
##############################################
if [[ "$DO_DUMP" -eq 1 ]]; then
echo "=== Dump (inline) ==="
t_init=$(date +%s.%N)

# --- CLEAN temp ---
sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt
rm -rf $DIRECTORY/"${APP}"
mkdir -p $DIRECTORY/"${APP}/images"

# --- COPY APPLICATION FROM CONFIG ---
cp "${APP_SOURCE_DIR}/${APP_EXEC}" $DIRECTORY/"${APP}/"

# Copy extra data if defined
if [[ ${#APP_EXTRA_FILES[@]} -gt 0 ]]; then
    for f in "${APP_EXTRA_FILES[@]}"; do
        cp "${APP_SOURCE_DIR}/${f}" $DIRECTORY/"${APP}/" 2>/dev/null || true
    done
fi

cd $DIRECTORY/"${APP}"

# --- RUN APPLICATION ---
echo "🚀 Launching $APP with DSM=$THREADS"
sudo rm -f /tmp/criu-restored.pid /tmp/haltcode

DSM=$THREADS ./${APP_EXEC} ${APP_ARGS} &
app_pid=$!
echo "APP PID = $app_pid"
sleep "$APP_WARMUP"
t0=$(date +%s.%N)
# --- CRIU DUMP ---
echo "📦 Dumping with CRIU..."
sudo $DIRECTORY/criu/criu/criu dump -t "$app_pid" --images-dir $DIRECTORY/"${APP}/images" \
     --shell-job -v || true

# --- COPY METADATA ---
cp /tmp/ranges.txt $DIRECTORY/"${APP}/images/" 2>/dev/null || true
cp /tmp/dsm_barrier_pages.txt $DIRECTORY/"${APP}/images/" 2>/dev/null || true
cp /tmp/dsm_mutex.txt $DIRECTORY/"${APP}/images/" 2>/dev/null || true

# --- BACKUP ---
cp -r $DIRECTORY/"${APP}/images" $DIRECTORY/"${APP}/backup"
#exit
t1=$(date +%s.%N)
dump_time=$(echo "$t1 - $t0" | bc -l)
init_time=$(echo "$t0 - $t_init - $APP_WARMUP" | bc -l)

fi
##############################################
### 2) SCP PHASE
##############################################
if [[ "$DO_SCP" -eq 1 ]]; then
    echo "=== SCP ==="
    t2=$(date +%s.%N)

    for client in "${CLIENTS[@]}"; do
        echo "[SCP] → $client"
        ssh -o StrictHostKeyChecking=no "$client" "sudo rm -rf $DIRECTORY/${APP}"
        scp -r $DIRECTORY/"${APP}" "$client":$DIRECTORY/
    done

    t3=$(date +%s.%N)
    scp_time=$(echo "$t3 - $t2" | bc -l)
fi

##############################################
### 3) RESTORE CONFIGS LOOP
##############################################
echo "=== Running configs ==="

sudo rm -f /tmp/ranges.txt /tmp/dsm_barrier_pages.txt /tmp/dsm_mutex.txt
PIDS=()

for cfg in "${CONFIGS[@]}"; do
    ##########################################
    ### PARSE CONFIG LINE (NEW FORMAT)
    ##########################################

    # Tokenize line
    read -ra TOK <<< "$cfg"

    # Format:
    #   NAME  N_CLIENTS  MAIN_RANGE  C0 C1 ...  MODE
    #
    # Example:
    #   split4_2_2_tcp  2 0-3 4-5 6-7 tcp

    CONF_NAME="${TOK[0]}"
    N_CLIENTS="${TOK[1]}"
    MAIN_RANGE="${TOK[2]}"
    MODE="${TOK[-1]}"   # last token

    # Extract client ranges
    C_RANGE=()
    for ((i=0; i<N_CLIENTS; i++)); do
        C_RANGE+=("${TOK[$((3 + i))]}")
    done

    FLAGSERVER=""
    FLAGCLIENT=""
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

    sudo rm -rf $DIRECTORY/"$APP"/images/
    cp -r $DIRECTORY/"$APP"/backup/ $DIRECTORY/"$APP"/images/

    cd $DIRECTORY/"$APP"/images
    "$PYTHON_FILE" "$THREAD_FILTER" "$MAIN_RANGE"

    t3b=$(date +%s.%N)
    filter_time=$(echo "$t3b - $t3a" | bc -l)

    ##########################################
    ### RESTORE
    ##########################################
    

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
    
    RESTORE_CMD="sudo $DIRECTORY/criu/criu/criu restore --shell-job --dsm_server $N_CLIENTS"
    [[ "$MODE" == "rdma" ]] && RESTORE_CMD+=" --dsm-rdma-enable"
    [[ "$SERVER_VERBOSE"  -eq 1 ]] && RESTORE_CMD+=" -v"
    [[ "$CLIENT_VERBOSE"  -eq 1 ]] && FLAGCLIENT=" --verbose"


    echo "Restore command: $RESTORE_CMD"
    t4=$(date +%s.%N)
    script -q -c "$RESTORE_CMD" /dev/null &
    RESTORE_PID=$!
    #exit

    ##############################################
    ### 3) LAUNCH CLIENT SIDE IF NEEDED
    ##############################################


    PIDS=()
    
    
    if [[ "$DO_RESTORE_CLIENTS" -eq 1 ]] && (( N_CLIENTS > 0 )); then
        for (( cid=0; cid<N_CLIENTS; cid++ )); do
            CLIENT_HOST="${CLIENTS[$cid]}"
            echo "[CLIENT-$cid] Starting restore on $CLIENT_HOST, ${C_RANGE[$cid]}, $FLAGCLIENT"

            if [[ "$CLIENT_OUTPUT_FILE" -eq 1 ]]; then
                ssh "$CLIENT_HOST" "
                    cd $DIRECTORY/criu/dsm/scripts || exit 1
                    source $DIRECTORY/venv-criu/bin/activate || true
                    taskset -c $CPU_LIST sudo ./restorer.sh $APP ${C_RANGE[$cid]} $FLAGCLIENT
                " 2>&1 | tr -d '\r' > /tmp/client_${cid}_${CONF_NAME}.log &
            else
                ssh "$CLIENT_HOST" "
                    cd $DIRECTORY/criu/dsm/scripts || exit 1
                    source $DIRECTORY/venv-criu/bin/activate || true
                    taskset -c $CPU_LIST sudo ./restorer.sh $APP ${C_RANGE[$cid]} $FLAGCLIENT
                " 2>&1 | tr -d '\r' &
            fi
            PIDS+=($!)

        done
    else
        echo "=== [SKIP] RESTORE_CLIENTS ==="
    fi


    wait $RESTORE_PID
    t5=$(date +%s.%N)

    for p in "${PIDS[@]}"; do wait "$p"; done

    exec_time=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo "0.0")
    restore_total=$(echo "$t5 - $t4" | bc -l)
    restore_overhead=$(echo "$restore_total - $exec_time" | bc -l)

    echo "RESTORE OVERHEAD = $restore_overhead"
    echo "EXEC TIME        = $exec_time"

    run_cmd "sudo sh -c 'echo \"$N_CORES,$CONF_NAME,$MODE,$dump_time,$scp_time,$filter_time,$restore_overhead,$exec_time\" >> \"$CSV\"'"

    cp /tmp/page_test_times.csv "/tmp/page_test_times_${MODE}.csv"
#echo "cores,config,transport,dump,scp_s,filter,restore,execute" > "$CSV"

    echo ">>> Finished $CONF_NAME"
done

echo "=== ALL DONE ==="
