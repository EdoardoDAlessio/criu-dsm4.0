#!/usr/bin/env bash

APP="histogram-dsm"
THREADS=32

CLIENTS=("dsm_client")

CONFIGS=(
    "base 0-31 - 0 tcp"
    #"split32_tcp  0-15     16-31    1   tcp"
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

dump_time=$(echo "$t1 - $t0" | bc -l)

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

    ##############################################
    ### 3) FILTER IMAGES ON SERVER (timed)     ###
    ##############################################
        echo "[SERVER] Thread filter..."
    t3a=$(date +%s.%N)

    #exit(1)
    # Ensure images/ exists and is empty
    sudo rm -rf ~/"$APP"/images/ || { echo "rm images!"; exit 1; }

    # Copy fresh dump
    sudo cp -r ~/"$APP"/backup/ ~/"$APP"/images/ || { echo "cp backup images!"; exit 1; }

    cd ~/"$APP"/images || { echo "No images directory!"; exit 1; }

    python3 "$THREAD_FILTER" "$S_RANGE"

    t3b=$(date +%s.%N)
    filter_time=$(echo "$t3b - $t3a" | bc -l)

    ##############################################
    ### 4-5) RESTORE SERVER + CLIENT (timed)   ###
    ##############################################
    t4=$(date +%s.%N)

    echo "[SERVER] Starting restore..."

    sudo script -q -c "$SERVER_RES $APP $S_RANGE $N_CLIENTS $FLAGSERVER" &
    SERVER_PID=$!

    sleep 5  # Let server bind and wait for clients

    if [[ "$N_CLIENTS" -ge 1 ]]; then
        C1="${CLIENTS[0]}"
        echo "[CLIENT] Starting restore on $C1..."

        ssh -tt "$C1" "
            cd ~/criu/dsm/scripts || exit 1;
            source ~/venv-criu/bin/activate || true;
            ./restorer.sh $APP $C_RANGE $FLAGCLIENT
        " &
        PIDS+=($!)
    fi

    wait $SERVER_PID
    if (( ${#PIDS[@]} > 0 )); then
        for p in "${PIDS[@]:-}"; do wait "$p"; done
    fi
    unset PIDS

    t5=$(date +%s.%N)

    restore_total=$(echo "$t5 - $t4" | bc -l)

    ##############################################
    ### 6) APP EXECUTION TIME (in-app output)   ###
    ##############################################
    exec_time="0.0"
    if [[ -f /tmp/dsm_exec_time_sec ]]; then
        exec_time=$(cat /tmp/dsm_exec_time_sec)
    fi

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
