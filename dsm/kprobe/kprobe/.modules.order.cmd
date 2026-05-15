cmd_/proj/popcornlinux-PG0/edo/kprobe/modules.order := {   echo /proj/popcornlinux-PG0/edo/kprobe/pmadvise_swap_kprobe.ko; :; } | awk '!x[$$0]++' - > /proj/popcornlinux-PG0/edo/kprobe/modules.order
