#!/bin/bash
# CRIU DSM RDMA Toggle Script
# Toggles RDMA_ENABLE between 0 and 1 in dsm.h and recompiles CRIU
# Usage: ./criu_toggle_rdma.sh [0|1|toggle] [--clean]

DSM_HEADER="/users/EdoDale/criu/criu/include/dsm.h"
CRIU_DIR="/users/EdoDale/criu"

# Parse arguments
CLEAN_BUILD=false
RDMA_MODE=""

for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        0|1|toggle)
            RDMA_MODE="$arg"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [0|1|toggle] [--clean]"
            echo ""
            echo "Arguments:"
            echo "  0        Set RDMA_ENABLE to 0 (disable RDMA)"
            echo "  1        Set RDMA_ENABLE to 1 (enable RDMA)"
            echo "  toggle   Toggle current value (default)"
            echo ""
            echo "Options:"
            echo "  --clean  Run 'make clean' before compilation (slower, more thorough)"
            echo "  --help   Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                    # Toggle RDMA mode (fast build)"
            echo "  $0 1                  # Enable RDMA mode (fast build)"
            echo "  $0 0 --clean          # Disable RDMA mode (clean build)"
            echo "  $0 toggle --clean     # Toggle RDMA mode (clean build)"
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

# Default to toggle if not specified
if [ -z "$RDMA_MODE" ]; then
    RDMA_MODE="toggle"
fi

if [ ! -f "$DSM_HEADER" ]; then
    echo "ERROR: DSM header file not found at $DSM_HEADER"
    exit 1
fi

# Function to get current RDMA_ENABLE value
get_current_value() {
    grep "#define RDMA_ENABLE" "$DSM_HEADER" | awk '{print $3}'
}

# Function to set RDMA_ENABLE value
set_rdma_value() {
    local new_value=$1
    sed -i "s/#define RDMA_ENABLE [01]/#define RDMA_ENABLE $new_value/" "$DSM_HEADER"
}

CURRENT_VALUE=$(get_current_value)

echo "=== CRIU DSM RDMA Toggle Script ==="
echo "Current RDMA_ENABLE value: $CURRENT_VALUE"

# Show build mode
if [ "$CLEAN_BUILD" = true ]; then
    echo "Build mode: Clean build (make clean && make)"
else
    echo "Build mode: Fast build (make only)"
fi

# Determine new value
if [ "$RDMA_MODE" = "toggle" ]; then
    if [ "$CURRENT_VALUE" = "1" ]; then
        NEW_VALUE=0
    else
        NEW_VALUE=1
    fi
    echo "Mode: Toggle"
elif [ "$RDMA_MODE" = "0" ]; then
    NEW_VALUE=0
    echo "Mode: Set to 0 (disable RDMA)"
elif [ "$RDMA_MODE" = "1" ]; then
    NEW_VALUE=1
    echo "Mode: Set to 1 (enable RDMA)"
fi

# Check if change is needed
if [ "$CURRENT_VALUE" = "$NEW_VALUE" ]; then
    echo "RDMA_ENABLE is already set to $NEW_VALUE. No change needed."
    echo "Skipping compilation."
    exit 0
fi

# Apply the change
echo "Changing RDMA_ENABLE from $CURRENT_VALUE to $NEW_VALUE..."
set_rdma_value $NEW_VALUE

# Verify
UPDATED_VALUE=$(get_current_value)
if [ "$UPDATED_VALUE" != "$NEW_VALUE" ]; then
    echo "ERROR: Failed to update RDMA_ENABLE value"
    exit 1
fi

echo "✓ Successfully changed RDMA_ENABLE to $NEW_VALUE"
echo ""
echo "Updated line in $DSM_HEADER:"
grep -n "#define RDMA_ENABLE" "$DSM_HEADER"
echo ""

# Compile CRIU
echo "Starting CRIU compilation..."
if [ "$CLEAN_BUILD" = true ]; then
    echo "Running clean build..."
    MAKE_CMD="make clean && make"
else
    echo "Running fast build..."
    MAKE_CMD="make"
fi

cd "$CRIU_DIR"
if eval "$MAKE_CMD"; then
    echo "=========================================="
    echo "✓ CRIU compilation successful!"
    echo "✓ RDMA_ENABLE is now set to: $NEW_VALUE"
    
    if [ "$NEW_VALUE" = "1" ]; then
        echo "✓ RDMA support is ENABLED"
        echo "  - CRIU DSM will use RDMA fast path for page transfers"
        echo "  - Ensure RDMA devices (mlx4, mlx5, etc.) are configured"
    else
        echo "✓ RDMA support is DISABLED"
        echo "  - CRIU DSM will use TCP fallback path for data exchange"
    fi
else
    echo "=========================================="
    echo "✗ CRIU compilation FAILED!"
    echo "Check the logs above for details."
    exit 1
fi

echo ""
echo "Script completed successfully."
