#pragma once

#include <linux/types.h>
#include <linux/userfaultfd.h>  // ✅ Always include the official header first

#ifndef __MY_UFFD_USER_HEADER__
#define __MY_UFFD_USER_HEADER__

/*
// Only define struct if missing
struct uffdio_range {
	__u64 start;
	__u64 len;
};*/

struct uffdio_writeprotect {
	struct uffdio_range range;
	__u64 mode;
};

// Patch missing macros safely
#ifndef UFFDIO_WRITEPROTECT_MODE_WP
#define UFFDIO_WRITEPROTECT_MODE_WP		((__u64)1<<0)
#endif

#ifndef UFFDIO_WRITEPROTECT_MODE_DONTWAKE
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE	((__u64)1<<1)
#endif

#ifndef _UFFDIO_WRITEPROTECT
#define _UFFDIO_WRITEPROTECT		(0x06)
#endif

#ifndef UFFDIO_WRITEPROTECT
#define UFFDIO_WRITEPROTECT	_IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, \
				      struct uffdio_writeprotect)
#endif

#ifndef UFFDIO_COPY_MODE_WP
#define UFFDIO_COPY_MODE_WP		((__u64)1<<1)
#endif

#endif // __MY_UFFD_USER_HEADER__

