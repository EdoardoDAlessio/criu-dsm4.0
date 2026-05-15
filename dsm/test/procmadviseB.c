#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/procmadvise_info.txt", "r");
    if (!f) { perror("fopen"); exit(1); }

    pid_t pid;
    void *addr;
    if (fscanf(f, "%d %p", &pid, &addr) != 2) {
        fprintf(stderr, "failed to parse info file\n"); exit(1);
    }
    fclose(f);

    printf("[B] target pid=%d addr=%p\n", pid, addr);

    // open pidfd
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd == -1) { perror("pidfd_open"); exit(1); }
    printf("[B] pidfd=%d\n", pidfd);

    // process_madvise MADV_DONTNEED
    struct iovec iov = { .iov_base = addr, .iov_len = 4096 };
    long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
    if (ret == -1) { perror("process_madvise"); exit(1); }

    printf("[B] ✅ process_madvise(MADV_DONTNEED) done (ret=%ld)\n", ret);
    printf("[B] now press enter in A to trigger second read\n");

    return 0;
}