#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#define PAGE_SIZE 4096
#define OFFSET 0x300
char *shared_page;
uint64_t raw_variable_offset;

void *fault_handler_thread(void *arg) {
    int uffd = *(int *)arg;
    struct pollfd pollfd = { .fd = uffd, .events = POLLIN };
    struct uffd_msg msg;

    printf("[handler] Waiting for page fault...\n");

    while (poll(&pollfd, 1, -1) > 0) {
        if (read(uffd, &msg, sizeof(msg)) != sizeof(msg)) {
            perror("read userfaultfd");
            exit(1);
        }

        printf("[handler] Raw fault address: 0x%llx\n", (unsigned long long)msg.arg.pagefault.address);
        printf("[handler] Page-aligned address: 0x%llx\n", (unsigned long long)(msg.arg.pagefault.address & ~(PAGE_SIZE - 1)));
        printf("[handler] Offset in page: 0x%llx\n", (unsigned long long)(msg.arg.pagefault.address % PAGE_SIZE));

        // Fill page with zeros to resolve the fault
        char *page = malloc(PAGE_SIZE);
        memset(page, 0x42, PAGE_SIZE);

        struct uffdio_copy copy = {
            .dst = msg.arg.pagefault.address & ~(PAGE_SIZE - 1),
            .src = (unsigned long)page,
            .len = PAGE_SIZE,
            .mode = 0
        };

        if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) {
            perror("ioctl-UFFDIO_COPY");
            exit(1);
        }

        free(page);
        break;
    }

    return NULL;
}

int main() {
    int uffd;
    pthread_t thr;

    // Create memory region and protect it
    shared_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shared_page == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Protect the page
    if (madvise(shared_page, PAGE_SIZE, MADV_DONTNEED) == -1) {
        perror("madvise");
        exit(1);
    }

    // Set up userfaultfd
    uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1) {
        perror("userfaultfd");
        exit(1);
    }

    struct uffdio_api api = { .api = UFFD_API };
    if (ioctl(uffd, UFFDIO_API, &api) == -1) {
        perror("ioctl-UFFDIO_API");
        exit(1);
    }

    struct uffdio_register reg = {
        .range = {
            .start = (unsigned long)shared_page,
            .len = PAGE_SIZE
        },
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };

    if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
        perror("ioctl-UFFDIO_REGISTER");
        exit(1);
    }

    // Launch the handler
    pthread_create(&thr, NULL, fault_handler_thread, &uffd);

    // FAULT on a variable at offset
    raw_variable_offset = 0x80;
    volatile char val = shared_page[OFFSET];  // This should fault

    printf("[main] Read variable: 0x%x\n", val);
    pthread_join(thr, NULL);
    return 0;
}

