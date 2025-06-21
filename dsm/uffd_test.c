#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define PAGE_SIZE 4096

int main() {
	int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd == -1) {
		perror("userfaultfd syscall");
		exit(1);
	}

	struct uffdio_api api = {
		.api = UFFD_API,
		.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP
	};

	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		perror("UFFDIO_API");
		exit(1);
	}

	if (!(api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP))
		printf("⚠️  UFFD write-protect not supported\n");

	void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	struct uffdio_register reg = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP
	};

	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		perror("UFFDIO_REGISTER");
		exit(1);
	}

	printf("✅ Successfully registered %p with userfaultfd %d\n", addr, uffd);
	return 0;
}

