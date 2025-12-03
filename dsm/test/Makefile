CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -pthread
LDFLAGS := -pthread -libverbs

SRC     := join.c mutex.c mutex_dsm.c page_test.c rdma_poc.c rdma_uffd_madv_dontneed_demo.c
BIN     := $(SRC:.c=)

all: $(BIN)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
