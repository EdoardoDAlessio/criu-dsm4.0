#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <infiniband/verbs.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

static size_t PGSZ;

struct uffd_ctx {
    int uffd;
    void *base;
    size_t len;
};

static void die(const char *msg) {
    perror(msg);
    exit(1);
}
#include <sys/types.h>
#include <sys/stat.h>

/* Returns PFN via /proc/self/pagemap. Requires root or CAP_SYS_ADMIN on new kernels. */
static unsigned long virt_to_pfn(void *addr) {
    unsigned long pfn = 0;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) { perror("open pagemap"); return 0; }
    off_t off = ((uintptr_t)addr / sysconf(_SC_PAGESIZE)) * 8ULL;
    if (lseek(fd, off, SEEK_SET) == (off_t)-1) { perror("lseek pagemap"); close(fd); return 0; }
    uint64_t entry = 0;
    if (read(fd, &entry, 8) != 8) { perror("read pagemap"); close(fd); return 0; }
    close(fd);
    if (!(entry & (1ULL << 63))) return 0; /* not present */
    pfn = entry & ((1ULL << 55) - 1);
    return pfn;
}

/* Simple UFFD missing-fault handler: zero-fills the missing page */
static void *uffd_thread(void *arg) {
    struct uffd_ctx *ctx = (struct uffd_ctx *)arg;
    struct pollfd pfd = { .fd = ctx->uffd, .events = POLLIN };
    for (;;) {
        int pr = poll(&pfd, 1, -1);
        if (pr < 0) die("poll uffd");
        if (!(pfd.revents & POLLIN)) continue;

        struct uffd_msg msg;
        ssize_t n = read(ctx->uffd, &msg, sizeof(msg));
        if (n == 0) continue;
        if (n < 0) die("read uffd");
        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "[UFFD] non-fault event %u\n", msg.event);
            continue;
        }

        void *fault_addr = (void *)(msg.arg.pagefault.address & ~(PGSZ - 1));
        uint64_t flags = msg.arg.pagefault.flags;

        fprintf(stderr,
                "[UFFD] Missing fault at %p (flags=0x%llx, write=%d)\n",
                fault_addr,
                (unsigned long long)flags,
                !!(flags & UFFD_PAGEFAULT_FLAG_WRITE));

        /* Resolve with zeropage so the faulting thread can continue */
        struct uffdio_zeropage zp = {
            .range.start = (unsigned long)fault_addr,
            .range.len   = PGSZ,
            .mode        = 0
        };
        if (ioctl(ctx->uffd, UFFDIO_ZEROPAGE, &zp) == -1)
            die("UFFDIO_ZEROPAGE");
    }
    return NULL;
}

int main(void) {
    PGSZ = (size_t)sysconf(_SC_PAGESIZE);

    /* --- Map 3 pages contiguously --- */
    size_t len = 3 * PGSZ;
    void *base = mmap(NULL, len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) die("mmap");
    void *A = base;             // RDMA + UFFD (will MADV_DONTNEED)
    void *B = (char*)base + PGSZ;  // RDMA + UFFD (no MADV)
    void *C = (char*)base + 2*PGSZ; // UFFD only (will MADV_DONTNEED)

    /* Pre-touch */
    memset(A, 0xAA, PGSZ);
    memset(B, 0xBB, PGSZ);
    memset(C, 0xCC, PGSZ);

    printf("[SETUP] Mapped pages:\n"
           "  A=%p (RDMA+UFFD)   B=%p (RDMA+UFFD)   C=%p (UFFD only)\n", A, B, C);

    /* --- Set up userfaultfd --- */
    int uffd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1) die("userfaultfd");
    struct uffdio_api api = { .api = UFFD_API, .features = 0 };
    if (ioctl(uffd, UFFDIO_API, &api) == -1) die("UFFDIO_API");

    struct uffdio_register reg = {
        .range = { .start = (unsigned long)base, .len = len },
        .mode  = UFFDIO_REGISTER_MODE_MISSING
    };
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) die("UFFDIO_REGISTER");
    printf("[SETUP] UFFD registered over [%p, %zu bytes]\n", base, len);

    struct uffd_ctx uctx = { .uffd = uffd, .base = base, .len = len };
    pthread_t thr;
    if (pthread_create(&thr, NULL, uffd_thread, &uctx) != 0) die("pthread_create");

    /* --- RDMA: open first device, alloc PD, register MR over A+B --- */
    int rdma_ok = 0;
    struct ibv_device **dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        perror("[RDMA] ibv_get_device_list failed");
    } else if (!dev_list[0]) {
        fprintf(stderr, "[RDMA] No RDMA devices found\n");
    } else {
        struct ibv_context *ctx = ibv_open_device(dev_list[0]);
        if (!ctx) {
            perror("[RDMA] ibv_open_device failed");
        } else {
            struct ibv_pd *pd = ibv_alloc_pd(ctx);
            if (!pd) {
                perror("[RDMA] ibv_alloc_pd failed");
            } else {
                void *rdma_region = A;
                size_t rdma_len = 2 * PGSZ; /* A+B */
                int access = IBV_ACCESS_LOCAL_WRITE; /* enough to pin */
                struct ibv_mr *mr = ibv_reg_mr(pd, rdma_region, rdma_len, access);
                if (!mr) {
                    perror("[RDMA] ibv_reg_mr failed (are hugepage/permissions ok?)");
                } else {
                    rdma_ok = 1;
                    printf("[RDMA] Registered MR over [%p .. %p) len=%zu rkey=0x%x\n",
                           rdma_region, (char*)rdma_region + rdma_len, rdma_len, mr->rkey);
                    
                    printf("[PFN] A before MADV: %lu\n", virt_to_pfn(A));
                    printf("[PFN] C before MADV: %lu\n", virt_to_pfn(C));

                    /* --- Do the experiment --- */
                    printf("\n[TEST] Calling madvise(DONTNEED) on A and C...\n");
                    if (madvise(A, PGSZ, MADV_DONTNEED) == -1)
                        perror("[TEST] madvise A failed");
                    if (madvise(C, PGSZ, MADV_DONTNEED) == -1)
                        perror("[TEST] madvise C failed");

                    printf("[PFN] A after MADV (before touch): %lu (likely 0: not present)\n", virt_to_pfn(A));
                    printf("[PFN] C after MADV (before touch): %lu (likely 0)\n", virt_to_pfn(C));

                    printf("[TEST] Accessing C (no RDMA): should trigger UFFD missing fault\n");
                    volatile uint8_t c_before = *((volatile uint8_t*)C);
                    (void)c_before;
                    printf("[TEST] C access done.\n");

                    printf("[TEST] Accessing A (RDMA-pinned): if MADV was ignored due to pin, "
                           "no UFFD fault will appear and read succeeds immediately.\n");
                    volatile uint8_t a_before = *((volatile uint8_t*)A);
                    (void)a_before;
                    printf("[TEST] A access done.\n");
                   
                    printf("[PFN] A after UFFD resolve: %lu\n", virt_to_pfn(A));
                    printf("[PFN] C after UFFD resolve: %lu\n", virt_to_pfn(C));
                    /* Clean up MR */
                    if (ibv_dereg_mr(mr) != 0) perror("[RDMA] ibv_dereg_mr");
                }
                if (ibv_dealloc_pd(pd) != 0) perror("[RDMA] ibv_dealloc_pd");
            }
            if (ibv_close_device(ctx) != 0) perror("[RDMA] ibv_close_device");
        }
        ibv_free_device_list(dev_list);
    }

    if (!rdma_ok) {
        fprintf(stderr,
            "\n[WARN] RDMA MR registration did not happen. "
            "The A-page is NOT pinned. For comparison, running the same test without RDMA:\n");

        if (madvise(A, PGSZ, MADV_DONTNEED) == -1)
            perror("[TEST] madvise A failed (no RDMA)");
        if (madvise(C, PGSZ, MADV_DONTNEED) == -1)
            perror("[TEST] madvise C failed (no RDMA)");

        printf("[TEST] Accessing C (no RDMA): expect UFFD missing fault\n");
        volatile uint8_t c_before = *((volatile uint8_t*)C);
        (void)c_before;
        printf("[TEST] C access done.\n");

        printf("[TEST] Accessing A (no RDMA): expect UFFD missing fault as well\n");
        volatile uint8_t a_before = *((volatile uint8_t*)A);
        (void)a_before;
        printf("[TEST] A access done.\n");
    }

    /* Give the UFFD thread time to print */
    usleep(200*1000);

    /* Tidy up */
    pthread_cancel(thr);
    pthread_join(thr, NULL);
    munmap(base, len);
    close(uffd);

    printf("\n[RESULT] If you saw a UFFD missing fault for C but NOT for A (when RDMA was active), "
           "MADV_DONTNEED was effectively ignored on the RDMA-pinned page.\n");
    return 0;
}

