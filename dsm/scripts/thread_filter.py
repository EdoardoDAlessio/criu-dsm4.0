import sys
import os
import json
import pycriu

TARGET_THREAD = int(sys.argv[1])
print("Target child thread: ", TARGET_THREAD)

# Correctly open files for pycriu.images.load
with open('pstree.img', 'rb') as f:
    pstree_object = pycriu.images.load(f)

threads_list = pstree_object['entries'][0]['threads']
print("available threads\n")
print(threads_list)

new_list = []
new_list.append(threads_list[0])

# Copy only the main thread ID
pstree_object['entries'][0]['threads'] = new_list
print(pstree_object)

# Correctly open files for pycriu.images.dump
with open('pstree.img', 'wb') as f:
    pycriu.images.dump(pstree_object, f)

PID = threads_list[0]

# Load main thread's core image
with open(f'core-{PID}.img', 'rb') as f:
    core_main_object = pycriu.images.load(f)
tc_object = core_main_object['entries'][0]['tc']  # TC values from main thread

TID = threads_list[TARGET_THREAD]
# Load target thread's core image
with open(f'core-{TID}.img', 'rb') as f:
    core_thread_object = pycriu.images.load(f)
# Replace TC values
core_thread_object['entries'][0]['tc'] = tc_object

# Save modified core image
with open(f'core-{PID}.img', 'wb') as f:
    pycriu.images.dump(core_thread_object, f)