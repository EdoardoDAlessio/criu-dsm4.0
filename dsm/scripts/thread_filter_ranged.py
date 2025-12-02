#!/usr/bin/env python3
import sys
import os
import pycriu
import shutil

if os.path.exists("filter"):
    print("Filter file already exists. Exiting.")
    sys.exit(0)

if len(sys.argv) < 2:
    print("Usage: python3 thread_filter.py <start-end> | <end>")
    sys.exit(1)

range_arg = sys.argv[1]
if "-" in range_arg:
    start_str, end_str = range_arg.split("-", 1)
    RANGE_START = int(start_str)
    RANGE_END = int(end_str)
else:
    RANGE_START = 0
    RANGE_END = int(range_arg)

# --- Load pstree ---
with open("pstree.img", "rb") as f:
    pstree_object = pycriu.images.load(f)

threads_list = pstree_object['entries'][0]['threads']
n_threads = len(threads_list)
# Exit if full-range restore
if RANGE_START == 0 and RANGE_END >= n_threads - 1:
    print(f"[INFO] Full restore requested ({n_threads} threads). Skipping filtering.")
    sys.exit(0)
# Clamp range
if RANGE_START < 0:
    RANGE_START = 0
if RANGE_END >= n_threads:
    RANGE_END = n_threads - 1
if RANGE_END < RANGE_START:
    RANGE_END = RANGE_START

selected_threads = threads_list[RANGE_START:RANGE_END+1]
print(f"Selected threads (indices {RANGE_START}-{RANGE_END}): {selected_threads}")

# --- Get original and new main PIDs ---
old_main_pid = pstree_object['entries'][0]['pid']
new_main_pid = selected_threads[0]
print(f"Old main PID: {old_main_pid}")
print(f"New main PID: {new_main_pid}")

# --- 1. Extract TC from old main core ---
with open(f"core-{old_main_pid}.img", "rb") as f:
    core_main = pycriu.images.load(f)
main_tc = core_main['entries'][0]['tc']

# --- 2. Load new main core and inject TC ---
with open(f"core-{new_main_pid}.img", "rb") as f:
    core_new_main = pycriu.images.load(f)

core_new_main['entries'][0]['tc'] = main_tc

# Save patched new main core back to its original name
with open(f"core-{new_main_pid}.img", "wb") as f:
    pycriu.images.dump(core_new_main, f)

# --- 3. Rename patched core to old main filename ---
print(f"✅ Injected TC from {old_main_pid} into {new_main_pid}")

# --- 4. Update pstree: pid + threads ---
pstree_object['entries'][0]['pid'] = new_main_pid
pstree_object['entries'][0]['threads'] = selected_threads
with open("pstree.img", "wb") as f:
    pycriu.images.dump(pstree_object, f)
print("✅ Updated pstree.img with new main PID and filtered threads")

# --- 5. Rename mm/fs/ids/pagemap to match new main PID ---
pid_dependent = ["mm", "ids", "fs", "pagemap"]
for prefix in pid_dependent:
    old_name = f"{prefix}-{old_main_pid}.img"
    new_name = f"{prefix}-{new_main_pid}.img"
    if os.path.exists(old_name):
        shutil.move(old_name, new_name)
        print(f"Renamed {old_name} -> {new_name}")

# --- 6. Remove unused core files ---
for tid in threads_list:
    if tid not in selected_threads and tid != new_main_pid:
        fname = f"core-{tid}.img"
        if os.path.exists(fname):
            os.remove(fname)
            print(f"Removed unused {fname}")

# --- 7. Guard file ---
with open("filter", "w") as f:
    f.write("done\n")

print("\n✅ Done.")
print(f"   - New main: {new_main_pid} (core-{old_main_pid}.img)")
print(f"   - Threads kept: {selected_threads}")
print(f"   - Renamed PID-dependent files")
print(f"   - Injected TC from old main into new main")
