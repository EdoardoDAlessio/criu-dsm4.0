// test_process_madvise.c
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

int main(void) {
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    struct iovec iov = {
        .iov_base = mem,
        .iov_len  = 4096
    };

    int pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0) {
        perror("pidfd_open");
        return 1;
    }

    printf("Calling process_madvise(..., MADV_DONTNEED)...\n");
    long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
    printf("Returned: %ld\n", ret);

    close(pidfd);
    return 0;
}

