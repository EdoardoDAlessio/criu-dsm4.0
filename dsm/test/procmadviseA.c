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

    printf("[A:handler] waiting for faults...\n"); fflush(stdout);

    while (1) {
        poll(&pfd, 1, -1);
        read(uffd, &msg, sizeof(msg));
        if (msg.event != UFFD_EVENT_PAGEFAULT) continue;

        unsigned long addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        int is_wp    = !!(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP);
        int is_write = !!(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE);

        printf("[A:handler] FAULT at 0x%lx | WP=%d WRITE=%d MISSING=%d\n",
               addr, is_wp, is_write, !is_wp);
        fflush(stdout);

        if (!is_wp) {
            unsigned char buf[PAGE_SIZE];
            memset(buf, 0xAB, PAGE_SIZE);
            struct uffdio_copy copy = {
                .src  = (unsigned long)buf,
                .dst  = addr,
                .len  = PAGE_SIZE,
                .mode = 0,
            };
            if (ioctl(uffd, UFFDIO_COPY, &copy) == -1)
                perror("[A:handler] UFFDIO_COPY");
            else
                printf("[A:handler] filled 0xAB\n");
        } else {
            struct uffdio_writeprotect wp = {
                .range = { .start = addr, .len = PAGE_SIZE },
                .mode  = 0,
            };
            ioctl(uffd, UFFDIO_WRITEPROTECT, &wp);
            printf("[A:handler] WP disabled\n");
        }
        fflush(stdout);
    }
    return NULL;
}

static void print_result(unsigned char val) {
    printf("[A] val=0x%02x → ", val);
    if      (val == 0xCD) printf("NOT madvised (page still in memory)\n");
    else if (val == 0x00) printf("madvised, kernel zero-filled (uffd BYPASSED)\n");
    else if (val == 0xAB) printf("madvised, uffd MISSING fault fired ✅\n");
    else                  printf("unexpected value\n");
    fflush(stdout);
}

int main(void) {
    pid_t pid = getpid();

    // pidfd for self (used in test 3)
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

    struct uffdio_register reg = {
        .range = { .start = (unsigned long)page, .len = PAGE_SIZE },
        .mode  = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
    };
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) { perror("UFFDIO_REGISTER"); exit(1); }

    printf("[A] pid=%d page=%p uffd=%d\n", pid, page, uffd);

    FILE *f = fopen("/tmp/procmadvise_info.txt", "w");
    if (!f) { perror("fopen"); exit(1); }
    fprintf(f, "%d %p\n", pid, page);
    fclose(f);

    pthread_t tid;
    pthread_create(&tid, NULL, handler, NULL);
    usleep(50000);

    // ── step 1: first read triggers MISSING fault, handler fills 0xAB ──
    printf("\n[A] step1: first read (expect MISSING fault → 0xAB)\n"); fflush(stdout);
    unsigned char val = ((volatile unsigned char *)page)[0];
    printf("[A] val=0x%02x (expect 0xAB)\n", val); fflush(stdout);

    // reset to 0xCD
    memset(page, 0xCD, PAGE_SIZE);
    printf("[A] reset to 0xCD, current=0x%02x\n\n",
           ((volatile unsigned char *)page)[0]);
    fflush(stdout);

    // ══════════════════════════════════════════════════════
    // TEST 1: process_madvise from another process (B)
    // ══════════════════════════════════════════════════════
    printf("========================================\n");
    printf("[A] TEST 1: process_madvise from process B\n");
    printf("[A] run B now, then press enter here\n");
    printf("========================================\n"); fflush(stdout);
    getchar();

    printf("[A] reading after B's process_madvise...\n"); fflush(stdout);
    val = ((volatile unsigned char *)page)[0];
    print_result(val);

    // reset to 0xCD
    memset(page, 0xCD, PAGE_SIZE);
    printf("[A] reset to 0xCD, current=0x%02x\n\n",
           ((volatile unsigned char *)page)[0]);
    fflush(stdout);

    // ══════════════════════════════════════════════════════
    // TEST 2: madvise from self
    // ══════════════════════════════════════════════════════
    printf("========================================\n");
    printf("[A] TEST 2: madvise(MADV_DONTNEED) from self\n");
    printf("========================================\n"); fflush(stdout);

    if (madvise(page, PAGE_SIZE, MADV_DONTNEED) == -1)
        perror("madvise");
    else
        printf("[A] madvise done\n");
    fflush(stdout);

    printf("[A] reading after self madvise...\n"); fflush(stdout);
    val = ((volatile unsigned char *)page)[0];
    print_result(val);

    // reset to 0xCD
    memset(page, 0xCD, PAGE_SIZE);
    printf("[A] reset to 0xCD, current=0x%02x\n\n",
           ((volatile unsigned char *)page)[0]);
    fflush(stdout);

    // ══════════════════════════════════════════════════════
    // TEST 3: process_madvise from self via pidfd
    // ══════════════════════════════════════════════════════
    printf("========================================\n");
    printf("[A] TEST 3: process_madvise from self via pidfd\n");
    printf("========================================\n"); fflush(stdout);

    struct iovec iov = { .iov_base = page, .iov_len = PAGE_SIZE };
    long ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
    if (ret == -1)
        perror("process_madvise self");
    else
        printf("[A] process_madvise self done (ret=%ld)\n", ret);
    fflush(stdout);

    printf("[A] reading after self process_madvise...\n"); fflush(stdout);
    val = ((volatile unsigned char *)page)[0];
    print_result(val);

    sleep(1);
    close(pidfd);
    return 0;
}