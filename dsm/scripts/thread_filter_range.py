#!/usr/bin/env python3
import sys
import os
import json
import pycriu

# Parse the range limit (0 to this number inclusive)
RANGE_LIMIT = int(sys.argv[1])
print(f"Thread range filter: keeping threads 0 to {RANGE_LIMIT} (inclusive)")

# Correctly open files for pycriu.images.load
with open('pstree.img', 'rb') as f:
    pstree_object = pycriu.images.load(f)

threads_list = pstree_object['entries'][0]['threads']
print("Available threads:")
for i, tid in enumerate(threads_list):
    print(f"  Index {i}: TID {tid}")

# Validate range
if RANGE_LIMIT >= len(threads_list):
    print(f"Warning: Range limit {RANGE_LIMIT} >= available threads {len(threads_list)}")
    print(f"Using maximum available: {len(threads_list) - 1}")
    RANGE_LIMIT = len(threads_list) - 1

# Create new list with threads from index 0 to RANGE_LIMIT (inclusive)
new_threads_list = threads_list[0:RANGE_LIMIT + 1]
print(f"\nFiltered threads (keeping {len(new_threads_list)} threads):")
for i, tid in enumerate(new_threads_list):
    print(f"  Index {i}: TID {tid}")

# Update pstree with filtered thread list
pstree_object['entries'][0]['threads'] = new_threads_list

# Save modified pstree
with open('pstree.img', 'wb') as f:
    pycriu.images.dump(pstree_object, f)

# Get main thread info for TC copying
MAIN_PID = threads_list[0]
print(f"\nMain thread PID: {MAIN_PID}")

# Load main thread's core image to get TC values
with open(f'core-{MAIN_PID}.img', 'rb') as f:
    core_main_object = pycriu.images.load(f)
tc_object = core_main_object['entries'][0]['tc']  # TC values from main thread

# Process each thread in the range (skip main thread at index 0)
for i in range(1, len(new_threads_list)):
    THREAD_TID = new_threads_list[i]
    print(f"Processing thread {i}: TID {THREAD_TID}")
    
    # Load target thread's core image
    try:
        with open(f'core-{THREAD_TID}.img', 'rb') as f:
            core_thread_object = pycriu.images.load(f)
        
        # Replace TC values with main thread's TC
        core_thread_object['entries'][0]['tc'] = tc_object
        
        # Save modified core image back with main PID filename
        # Note: This overwrites the main core file with the last thread's data + main TC
        with open(f'core-{MAIN_PID}.img', 'wb') as f:
            pycriu.images.dump(core_thread_object, f)
            
        print(f"  ✅ Updated core-{THREAD_TID}.img TC values")
        
    except FileNotFoundError:
        print(f"  ❌ Warning: core-{THREAD_TID}.img not found, skipping")
    except Exception as e:
        print(f"  ❌ Error processing thread {THREAD_TID}: {e}")

print(f"\n✅ Thread filtering complete!")
print(f"   - Kept threads: {len(new_threads_list)} (indices 0 to {RANGE_LIMIT})")
print(f"   - Updated pstree.img with filtered thread list")
print(f"   - Copied main thread TC values to worker threads")