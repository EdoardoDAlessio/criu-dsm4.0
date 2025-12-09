#!/usr/bin/env bash
set -e

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

echo "======================================"
sleep 1

# Threads come from config
THREADS="$APP_THREADS"

# CSV output depends on app
CSV="$SCRIPTS/results/dsm_results_${APP}_${N_CORES}_cores${SUFFIX:+_$SUFFIX}.csv"

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
echo "config,init,dump_s,scp_s,filter_s,restore_s,exec_s" > "$CSV"

echo "=== Clean previous runs ==="
sudo pkill -9 -f "criu" || true


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

 
    #FLAGSERVER="--verbose"
    FLAGSERVER=""
    FLAGCLIENT=""
    #FLAGCLIENT="--verbose"
    [[ "$PROTO" == "rdma" ]] && FLAGSERVER="$FLAGSERVER --dsm-rdma-enable"
    [[ "$PROTO" == "rdma" ]] && FLAGCLIENT="$FLAGCLIENT --rdma"

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

    sudo rm -rf ~/"$APP"/images/
    cp -r ~/"$APP"/backup/ ~/"$APP"/images/

    cd ~/"$APP"/images
    python3 "$THREAD_FILTER" "$MAIN_RANGE"

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
    
    RESTORE_CMD="sudo ~/criu/criu/criu restore --shell-job --dsm_server $N_CLIENTS"
    [[ "$PROTO" == "rdma" ]] && RESTORE_CMD+=" --dsm-rdma-enable"
    #RESTORE_CMD+=" -v"
    t4=$(date +%s.%N)
    script -q -c "$RESTORE_CMD" /dev/null &
    RESTORE_PID=$!

    ##############################################
    ### 3) LAUNCH CLIENT SIDE IF NEEDED
    ##############################################
    PIDS=()
    
    if (( N_CLIENTS > 0 )); then
        for (( cid=0; cid<N_CLIENTS; cid++ )); do
            CLIENT_HOST="${CLIENTS[$cid]}"
            echo "[CLIENT-$cid] Starting restore on $CLIENT_HOST..."

            ssh -tt "$CLIENT_HOST" "
                cd ~/criu/dsm/scripts || exit 1
                source ~/venv-criu/bin/activate || true
                taskset -c $CPU_LIST ./restorer.sh $APP ${C_RANGE[$cid]} $FLAGCLIENT
            " &

            PIDS+=($!)
        done
    fi


    wait $RESTORE_PID
    t5=$(date +%s.%N)

    for p in "${PIDS[@]}"; do wait "$p"; done

    exec_time=$(cat /tmp/dsm_exec_time_sec 2>/dev/null || echo "0.0")
    restore_total=$(echo "$t5 - $t4" | bc -l)
    restore_overhead=$(echo "$restore_total - $exec_time" | bc -l)

    echo "RESTORE OVERHEAD = $restore_overhead"
    echo "EXEC TIME        = $exec_time"

    run_cmd "sudo sh -c 'echo \"$CONF_NAME,$init_time,$dump_time,$scp_time,$filter_time,$restore_overhead,$exec_time\" >> \"$CSV\"'"

    echo ">>> Finished $CONF_NAME"
done

echo "=== ALL DONE ==="
