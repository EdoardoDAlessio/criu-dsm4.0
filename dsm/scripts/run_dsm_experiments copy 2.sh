#!/usr/bin/env bash

APP="histogram-dsm"
THREADS=32

CLIENTS=("dsm_client")

CONFIGS=(
    "base 0-31 - 0 tcp"
    "split16_16_tcp  0-15     16-31    1   tcp"
    "split16_16_rdma  0-15    16-31    1   rdma"
    #"split8_24_tcp  0-7     8-31    1   tcp"
)

SCRIPTS="$HOME/criu/dsm/scripts"
CSV="$SCRIPTS/results/dsm_results_${APP}.csv"
PHOENIX="$SCRIPTS/phoenix.sh"
SCP="$SCRIPTS/dsm_scp.sh"
SERVER_RES="$SCRIPTS/main_restore.sh"
CLIENT_RES="$SCRIPTS/restorer.sh"
THREAD_FILTER="$SCRIPTS/thread_filter_ranged.py"

run_cmd() {
    echo ">>> CMD: $*"
    eval "$*"
}

# Create CSV header
echo "config,dump_s,scp_s,filter_s,restore_s,exec_s" > "$CSV"

echo "=== Clean previous runs ==="
sudo pkill -9 -f "criu"

##############################################
###            1) DUMP (timed)             ###
##############################################
echo "=== Dump ==="
t0=$(date +%s.%N)
"$PHOENIX" "$APP" "${CLIENTS[0]}" "$THREADS" \
    "/users/EdoDale/phoenix/phoenix-2.0/tests/input/histogram_datafiles/large.bmp" "100"
t1=$(date +%s.%N)

dump_time=$(echo "$t1 - $t0 - 8" | bc -l)

##############################################
###            2) SCP (timed)              ###
##############################################
echo "=== SCP ==="
t2=$(date +%s.%N)

for client in "${CLIENTS[@]}"; do
    echo "[SCP] Syncing $APP to $client"

    ssh -o StrictHostKeyChecking=no "$client" "rm -rf ~/${APP}"
    scp -r ~/"${APP}" "$client":~/
done

t3=$(date +%s.%N)
scp_time=$(echo "$t3 - $t2" | bc -l)


##############################################
###            RUN CONFIGS                 ###
##############################################

echo "=== Running configs ==="

sudo rm -f /tmp/ranges.txt
sudo rm -f /tmp/dsm_barrier_pages.txt
sudo rm -f /tmp/dsm_mutex.txt
PIDS=()

for cfg in "${CONFIGS[@]}"; do
    read -r LABEL S_RANGE C_RANGE N_CLIENTS PROTO <<< "$cfg"

    echo ""
    echo "=========== $LABEL ==============="

    FLAGCLIENT="--verbose"
    FLAGSERVER="--verbose"
    [[ "$PROTO" == "rdma" ]] && FLAGSERVER="$FLAGSERVER --dsm-rdma-enable"
    [[ "$PROTO" == "rdma" ]] && FLAGCLIENT="$FLAGCLIENT --rdma"
    ##############################################
    ### 3) FILTER IMAGES ON SERVER (timed)     ###
    ##############################################
        echo "[SERVER] Thread filter..."
    t3a=$(date +%s.%N)

    #exit(1)
    # Ensure images/ exists and is empty
    sudo rm -rf ~/"$APP"/images/ || { echo "rm images!"; exit 1; }

    # Copy fresh dump
    cp -r ~/"$APP"/backup/ ~/"$APP"/images/ || { echo "cp backup images!"; exit 1; }

    cd ~/"$APP"/images || { echo "No images directory!"; exit 1; }

    python3 "$THREAD_FILTER" "$S_RANGE"

    t3b=$(date +%s.%N)
    filter_time=$(echo "$t3b - $t3a" | bc -l)
  
    ##############################################
    ### 4-5) RESTORE (server + client)        ###
    ##############################################
    t4=$(date +%s.%N)

    echo "[SERVER] Starting inline restore..."

    # 1) PREP ENVIRONMENT (formerly main_restore.sh)
    sudo rm -f /tmp/ranges.txt \
            /tmp/dsm_barrier_pages.txt \
            /tmp/dsm_mutex.txt \
            /tmp/criu-restored.pid \
            /tmp/dsm_exec_time_sec \
            /tmp/restored_threads.txt \
            /tmp/authorized_barrier_thread.txt

    first=$(echo "$S_RANGE" | cut -d'-' -f1)
    second=$(echo "$S_RANGE" | cut -d'-' -f2)
    gap=$((second - first + 1))

    echo "$gap" | sudo tee /tmp/restored_threads.txt >/dev/null
    echo "$first" | sudo tee /tmp/authorized_barrier_thread.txt >/dev/null

    # Copy images metadata into /tmp (was done by main_restore.sh)
    cp ~/"$APP"/images/ranges.txt /tmp/ranges.txt 2>/dev/null || true
    cp ~/"$APP"/images/dsm_barrier_pages.txt /tmp/dsm_barrier_pages.txt 2>/dev/null || true
    cp ~/"$APP"/images/dsm_mutex.txt /tmp/dsm_mutex.txt 2>/dev/null || true

    unset DSM
    export DSM=0

    touch /tmp/.restore_flag
    touch /tmp/haltcode

    ##############################################
    ### RESTORE COMMAND
    ##############################################
   # Build restore command as a string (for script -c)
    RESTORE_CMD="sudo ~/criu/criu/criu restore --shell-job --dsm_server $N_CLIENTS"

    [[ "$PROTO" == "rdma" ]] && RESTORE_CMD+=" --dsm-rdma-enable"
    [[ "$FLAGSERVER" == *"--verbose"* ]] && RESTORE_CMD+=" -v"

    echo "[SERVER] Running restore (via script): $RESTORE_CMD"

    # Run CRIU under script so it has a TTY for --shell-job
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
    exit[]
        PIDS+=($!)
    fi

    ##############################################
    ### 4) WAIT FOR SERVER RESTORE
    ##############################################
    echo "Waiting on $RESTORE_PID"
    wait $RESTORE_PID
    t5=$(date +%s.%N)
    echo "[SERVER] CRIU restore finished."
    ##############################################
    ### 5) WAIT FOR CLIENTS
    ##############################################
    if (( ${#PIDS[@]} > 0 )); then
        for p in "${PIDS[@]}"; do wait "$p"; done
    fi
    ##############################################
    ### 6) APP EXECUTION TIME (in-app output)   ###
    ##############################################
    exec_time="0.0"
    if [[ -f /tmp/dsm_exec_time_sec ]]; then
        exec_time=$(cat /tmp/dsm_exec_time_sec)
    fi
    restore_total=$(echo "$t5 - $t4" | bc -l)

    ##############################################
    ### 7) compute restore overhead            ###
    ##############################################
    restore_overhead=$(echo "$restore_total - $exec_time" | bc -l)

    echo "RESTORE OVERHEAD = $restore_overhead s"
    echo "EXEC TIME        = $exec_time s"
   
   run_cmd "sudo sh -c 'echo \"$LABEL,$dump_time,$scp_time,$filter_time,$restore_overhead,$exec_time\" >> \"$CSV\"'"

    echo ">>> Finished $LABEL"
done

echo "=== ALL DONE ==="
