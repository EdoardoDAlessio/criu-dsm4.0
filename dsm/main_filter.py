import sys
import pycriu
import os

# Get target thread index
if len(sys.argv) < 2:
    print("Usage: python modify.py <TARGET_THREAD_INDEX>")
    sys.exit(1)

TARGET_INDEX = int(sys.argv[1])
print("Target thread index in list: ", TARGET_INDEX)

# Load pstree
with open('pstree.img', 'rb') as f:
    pstree_object = pycriu.images.load(f)

threads_list = pstree_object['entries'][0]['threads']
print(f"Available threads: {threads_list}")

if TARGET_INDEX >= len(threads_list):
    print(f"Index {TARGET_INDEX} is out of bounds for thread list of size {len(threads_list)}")
    sys.exit(1)

MAIN_TID = threads_list[0]
TARGET_TID = threads_list[TARGET_INDEX]
print(f"Selected thread TID: {TARGET_TID} (Index {TARGET_INDEX})")

# Modify pstree to contain only the selected thread
pstree_object['entries'][0]['threads'] = [TARGET_TID]

# Save modified pstree
with open('pstree.img', 'wb') as f:
    pycriu.images.dump(pstree_object, f)

# Load main thread's core image to extract tc
with open(f'core-{MAIN_TID}.img', 'rb') as f:
    core_main = pycriu.images.load(f)

main_tc = core_main['entries'][0]['tc']

# Load target thread's core image
with open(f'core-{TARGET_TID}.img', 'rb') as f:
    core_target = pycriu.images.load(f)

# Replace target's tc with main's tc
core_target['entries'][0]['tc'] = main_tc

# Save modified target thread's core image (can overwrite or rename)
with open(f'core-{TARGET_TID}.img', 'wb') as f:
    pycriu.images.dump(core_target, f)

print(f"Replaced thread {TARGET_TID}'s TC with thread {MAIN_TID}'s TC.")

