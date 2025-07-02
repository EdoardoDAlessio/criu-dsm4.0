#!/bin/bash

APP="./dsm_write"             # ← your application path
NUM_THREADS=2            # ← threads created in your app
CRIU_DUMP_DIR="images"   # ← where to store CRIU dump

# Start the app with thread trapper preload
LD_PRELOAD=./trap_threads.so $APP $NUM_THREADS &
APP_PID=$!

echo "🧪 Started app with PID $APP_PID"

# Wait until all threads are visible in /proc
EXPECTED_THREADS=$((NUM_THREADS + 1))  # N threads + main 
echo "⏳ Waiting for $EXPECTED_THREADS threads..."

while true; do
    THREADS=$(ls /proc/$APP_PID/task/ 2>/dev/null | wc -l)
    if [[ "$THREADS" -eq "$EXPECTED_THREADS" ]]; then
        echo "✅ All $THREADS threads created"
        break
    fi
    sleep 0.1
done

# Stop the main thread
echo "🛑 Stopping main thread..."
kill -STOP $APP_PID

# Show thread states
echo "🔍 Thread states:"
for tid in $(ls /proc/$APP_PID/task); do
    echo -n "Thread $tid: "
    grep State /proc/$APP_PID/task/$tid/status
done

# Dump
echo "📦 Dumping with CRIU..."
criu dump -t $APP_PID -D $CRIU_DUMP_DIR --shell-job --tcp-established -vv || {
    echo "❌ CRIU dump failed"
    exit 1
}

echo "✅ Dump completed"

