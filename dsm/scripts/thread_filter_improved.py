#!/usr/bin/env python3
import sys
import os
import json
import pycriu

# Parse the target thread index
TARGET_THREAD = int(sys.argv[1])
print(f"Thread filter: selecting thread at index {TARGET_THREAD}")

# Correctly open files for pycriu.images.load
with open('pstree.img', 'rb') as f:
    pstree_object = pycriu.images.load(f)

threads_list = pstree_object['entries'][0]['threads']
print("Available threads:")
for i, tid in enumerate(threads_list):
    marker = " <-- SELECTED" if i == TARGET_THREAD else ""
    thread_type = "Main" if i == 0 else f"Worker {i}"
    print(f"  Index {i}: TID {tid} ({thread_type}){marker}")

# Validate target thread index
if TARGET_THREAD >= len(threads_list):
    print(f"❌ Error: Target thread index {TARGET_THREAD} >= available threads {len(threads_list)}")
    print(f"   Valid range: 0 to {len(threads_list) - 1}")
    sys.exit(1)

if TARGET_THREAD == 0:
    print("❌ Error: Cannot select main thread (index 0) as target")
    print("   Please select a worker thread (index 1 or higher)")
    sys.exit(1)

# Create new list with only main thread
new_list = []
new_list.append(threads_list[0])  # Always keep main thread

print(f"\nFiltered threads (keeping only main thread):")
print(f"  Index 0: TID {threads_list[0]} (Main)")

# Update pstree with filtered thread list (only main thread)
pstree_object['entries'][0]['threads'] = new_list

# Save modified pstree
with open('pstree.img', 'wb') as f:
    pycriu.images.dump(pstree_object, f)

# Get thread info
MAIN_PID = threads_list[0]
TARGET_TID = threads_list[TARGET_THREAD]

print(f"\nProcessing:")
print(f"  Main thread PID: {MAIN_PID}")
print(f"  Target thread TID: {TARGET_TID} (index {TARGET_THREAD})")

# Load main thread's core image to get TC values
try:
    with open(f'core-{MAIN_PID}.img', 'rb') as f:
        core_main_object = pycriu.images.load(f)
    tc_object = core_main_object['entries'][0]['tc']  # TC values from main thread
    print("  ✅ Loaded main thread TC values")
except Exception as e:
    print(f"  ❌ Error loading main thread core: {e}")
    sys.exit(1)

# Load target thread's core image
try:
    with open(f'core-{TARGET_TID}.img', 'rb') as f:
        core_thread_object = pycriu.images.load(f)
    print(f"  ✅ Loaded target thread core-{TARGET_TID}.img")
except Exception as e:
    print(f"  ❌ Error loading target thread core: {e}")
    sys.exit(1)

# Replace TC values with main thread's TC
core_thread_object['entries'][0]['tc'] = tc_object

# Save modified core image (overwrites main core with target thread + main TC)
try:
    with open(f'core-{MAIN_PID}.img', 'wb') as f:
        pycriu.images.dump(core_thread_object, f)
    print(f"  ✅ Updated core-{MAIN_PID}.img with target thread data + main TC")
except Exception as e:
    print(f"  ❌ Error saving modified core: {e}")
    sys.exit(1)

print(f"\n✅ Thread filtering complete!")
print(f"   - Selected thread {TARGET_THREAD} (TID {TARGET_TID}) as the single worker thread")
print(f"   - Updated pstree.img to contain only main thread")
print(f"   - Replaced main core with selected thread data + main thread TC values")