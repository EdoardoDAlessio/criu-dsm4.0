#!/bin/bash

# CRIU DSM Server Toggle Script
# Toggles ENABLE_SERVER between 0 and 1 in dsm.h and recompiles CRIU
# Usage: ./criu_toggle_server.sh [0|1|toggle] [--clean]

DSM_HEADER="/users/EdoDale/criu/criu/include/dsm.h"
CRIU_DIR="/users/EdoDale/criu"

# Parse arguments
CLEAN_BUILD=false
SERVER_MODE=""

for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        0|1|toggle)
            SERVER_MODE="$arg"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [0|1|toggle] [--clean]"
            echo ""
            echo "Arguments:"
            echo "  0        Set ENABLE_SERVER to 0 (client mode)"
            echo "  1        Set ENABLE_SERVER to 1 (server mode)"
            echo "  toggle   Toggle current value (default)"
            echo ""
            echo "Options:"
            echo "  --clean  Run 'make clean' before compilation (slower, more thorough)"
            echo "  --help   Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Toggle server mode (fast build)"
            echo "  $0 1                  # Enable server mode (fast build)"
            echo "  $0 0 --clean          # Disable server mode (clean build)"
            echo "  $0 toggle --clean     # Toggle server mode (clean build)"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $arg"
            echo "Usage: $0 [0|1|toggle] [--clean]"
            echo "Use --help for detailed usage information"
            exit 1
            ;;
    esac
done

# Default to toggle if no server mode specified
if [ -z "$SERVER_MODE" ]; then
    SERVER_MODE="toggle"
fi

if [ ! -f "$DSM_HEADER" ]; then
    echo "ERROR: DSM header file not found at $DSM_HEADER"
    exit 1
fi

# Function to get current ENABLE_SERVER value
get_current_value() {
    grep "#define ENABLE_SERVER" "$DSM_HEADER" | awk '{print $3}'
}

# Function to set ENABLE_SERVER value
set_server_value() {
    local new_value=$1
    sed -i "s/#define ENABLE_SERVER [01]/#define ENABLE_SERVER $new_value/" "$DSM_HEADER"
}

# Get current value
CURRENT_VALUE=$(get_current_value)

echo "=== CRIU DSM Server Toggle Script ==="
echo "Current ENABLE_SERVER value: $CURRENT_VALUE"

# Show build mode
if [ "$CLEAN_BUILD" = true ]; then
    echo "Build mode: Clean build (make clean && make)"
else
    echo "Build mode: Fast build (make only)"
fi

# Determine new value
if [ "$SERVER_MODE" = "toggle" ]; then
    # Toggle mode (default)
    if [ "$CURRENT_VALUE" = "1" ]; then
        NEW_VALUE=0
    else
        NEW_VALUE=1
    fi
    echo "Mode: Toggle"
elif [ "$SERVER_MODE" = "0" ]; then
    NEW_VALUE=0
    echo "Mode: Set to 0 (disable server)"
elif [ "$SERVER_MODE" = "1" ]; then
    NEW_VALUE=1
    echo "Mode: Set to 1 (enable server)"
fi

# Check if change is needed
if [ "$CURRENT_VALUE" = "$NEW_VALUE" ]; then
    echo "ENABLE_SERVER is already set to $NEW_VALUE. No change needed."
    echo "Skipping compilation."
    exit 0
fi

# Make the change
echo "Changing ENABLE_SERVER from $CURRENT_VALUE to $NEW_VALUE..."
set_server_value $NEW_VALUE

# Verify the change
UPDATED_VALUE=$(get_current_value)
if [ "$UPDATED_VALUE" != "$NEW_VALUE" ]; then
    echo "ERROR: Failed to update ENABLE_SERVER value"
    exit 1
fi

echo "✓ Successfully changed ENABLE_SERVER to $NEW_VALUE"
echo ""

# Show the relevant line
echo "Updated line in $DSM_HEADER:"
grep -n "#define ENABLE_SERVER" "$DSM_HEADER"
echo ""

# Compile CRIU
echo "Starting CRIU compilation..."
if [ "$CLEAN_BUILD" = true ]; then
    echo "Running clean build (this may take several minutes)..."
else
    echo "Running fast build (incremental compilation)..."
fi
echo "=========================================="

cd "$CRIU_DIR"
if [ "$CLEAN_BUILD" = true ]; then
    MAKE_CMD="make clean && make"
else
    MAKE_CMD="make"
fi

if eval "$MAKE_CMD"; then
    echo "=========================================="
    echo "✓ CRIU compilation successful!"
    echo "✓ ENABLE_SERVER is now set to: $NEW_VALUE"
    
    # Show what this means
    if [ "$NEW_VALUE" = "1" ]; then
        echo "✓ DSM Server mode is ENABLED"
        echo "  - CRIU will act as DSM server"
        echo "  - Manages distributed shared memory"
        echo "  - IT WILL WAIT FOR A CLIENT TO CONNECT"
    else
        echo "✓ DSM Server mode is DISABLED" 
        echo "  - Practically a DEBUG MODE because it can run without waiting for a client to connect"
    fi
else
    echo "=========================================="
    echo "✗ CRIU compilation FAILED!"
    echo "Check the error messages above for details"
    exit 1
fi

echo ""
echo "Script completed successfully."
