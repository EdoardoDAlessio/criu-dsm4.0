#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#define PAGE_SIZE 4096

int uffd;
void *page;

static void *handler(void *arg) {
    struct pollfd pfd = { .fd = uffd, .events = POLLIN };
    struct uffd_msg msg;

    printf("[handler] waiting for fault...\n");
    fflush(stdout);

    while (1) {
        poll(&pfd, 1, -1);
        read(uffd, &msg, sizeof(msg));
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        unsigned long addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        int is_wp      = !!(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP);
        int is_write   = !!(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE);
        int is_missing = !is_wp;  // if not WP, it's a missing fault

        printf("[handler] FAULT at 0x%lx | WP=%d WRITE=%d MISSING=%d\n",
               addr, is_wp, is_write, is_missing);
        fflush(stdout);

        if (is_missing) {
            unsigned char buf[PAGE_SIZE];
            memset(buf, 0xAB, PAGE_SIZE);
            struct uffdio_copy copy = {
                .src  = (unsigned long)buf,
                .dst  = addr,
                .len  = PAGE_SIZE,
                .mode = 0,
            };
            if (ioctl(uffd, UFFDIO_COPY, &copy) == -1)
                perror("UFFDIO_COPY");
            else
                printf("[handler] filled 0xAB via UFFDIO_COPY\n");
        } else {
            // WP fault — just disable WP
            struct uffdio_writeprotect wp = {
                .range = { .start = addr, .len = PAGE_SIZE },
                .mode  = 0,  // disable WP
            };
            if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
                perror("UFFDIO_WRITEPROTECT disable");
            else
                printf("[handler] WP disabled\n");
        }
        fflush(stdout);
    }
    return NULL;
}

int main(void) {
    pid_t pid = getpid();

    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd == -1) { perror("pidfd_open"); exit(1); }

    uffd = (int)syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1) { perror("userfaultfd"); exit(1); }

    struct uffdio_api api = {
        .api      = UFFD_API,
        .features = UFFD_FEATURE_PAGEFAULT_FLAG_WP,
    };
    if (ioctl(uffd, UFFDIO_API, &api) == -1) { perror("UFFDIO_API"); exit(1); }

    // NO MAP_POPULATE
    page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); exit(1); }
    printf("[main] page at %p\n", page);

    struct uffdio_register reg = {
        .range = { .start = (unsigned long)page, .len = PAGE_SIZE },
        .mode  = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
    };
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) { perror("UFFDIO_REGISTER"); exit(1); }
    printf("[main] registered (ioctls=0x%llx)\n", reg.ioctls);

    pthread_t tid;
    pthread_create(&tid, NULL, handler, NULL);
    usleep(50000);  // let handler start

    // --- step 1: first read, expect MISSING fault ---
    printf("\n[main] step1: first read\n"); fflush(stdout);
    unsigned char val = ((volatile unsigned char *)page)[0];
    printf("[main] val=0x%02x (expect 0xAB)\n\n", val); fflush(stdout);

    // --- step 2: process_madvise DONTNEED ---
    printf("[main] step2: process_madvise(MADV_DONTNEED)\n"); fflush(stdout);
    struct iovec iov = { .iov_base = page, .iov_len = PAGE_SIZE };
    long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
    if (ret == -1) { perror("process_madvise"); exit(1); }
    printf("[main] process_madvise done\n\n"); fflush(stdout);

    // --- step 3: check if still registered ---
    struct uffdio_register reg2 = {
        .range = { .start = (unsigned long)page, .len = PAGE_SIZE },
        .mode  = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
    };
    int rc = ioctl(uffd, UFFDIO_REGISTER, &reg2);
    if (rc == -1 && errno == EBUSY)
        printf("[main] ✅ still registered after madvise (EBUSY)\n\n");
    else if (rc == 0)
        printf("[main] ❌ registration was LOST after madvise (re-registered now)\n\n");
    else
        perror("UFFDIO_REGISTER check");
    fflush(stdout);

    // --- step 4: second read, expect MISSING fault again ---
    printf("[main] step3: second read after madvise\n"); fflush(stdout);
    val = ((volatile unsigned char *)page)[0];
    printf("[main] val=0x%02x (expect 0xAB, got 0x00 = kernel zero-fill bypassed uffd)\n", val);
    fflush(stdout);

    sleep(1);
    close(pidfd);
    return 0;
}