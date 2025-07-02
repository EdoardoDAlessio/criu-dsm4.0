# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Wno-implicit-function-declaration -Wno-unused-but-set-variable
LDFLAGS = -lpthread

# Shared object for LD_PRELOAD
TRAP_SO = trap_threads.so

# dsm_write-specific sources and binary
DSM_SRCS = dsm_write.c radix.c time.c
DSM_OBJS = $(DSM_SRCS:.c=.o)
DSM_BIN = dsm_write

# Automatically detect other .c files (excluding special ones)
ALL_SRCS = $(wildcard *.c)
GENERIC_SRCS = $(filter-out trap_threads.c dsm_write.c radix.c time.c,$(ALL_SRCS))
GENERIC_BINS = $(GENERIC_SRCS:.c=)

.PHONY: all clean

all: $(GENERIC_BINS) $(DSM_BIN) $(TRAP_SO)

# Generic rule for standalone .c binaries
%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# dsm_write rule
$(DSM_BIN): $(DSM_OBJS)
	$(CC) $(CFLAGS) $(DSM_OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# trap_threads.so rule
$(TRAP_SO): trap_threads.c
	$(CC) -Wall -fPIC -shared -o $@ $< -ldl

clean:
	rm -f $(GENERIC_BINS) $(DSM_BIN) $(DSM_OBJS) $(TRAP_SO)
