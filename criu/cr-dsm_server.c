#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

/*COMPILE ERRORS*/
#include "pstree.h"

#define DGB 0
#define COMMAND_LOOP 0
#define ENABLE_SERVER 1
#define BACKLOG 1
#define SIGMAX 64

#define err_and_ret(msg) do { fprintf(stderr, msg);  return -1; } while (0)
//#include "../compel/include/infect-priv.h" needed if  low-level register access or context setup manually.
#include "util-pie.h"
#include "asm/types.h"
#include "vma.h" 
#include <compel/infect.h> //for compel_parasite_args
#include <compel/ptrace.h>
#include "compel/plugins/std/fds.h"
#include "compel/include/uapi/infect-util.h"
//USERFAULTFD HEADERS
#include <sys/types.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>	
//#undef uffdio_range
#include "user.h"

#include "parsemap.h"
#define HANDSHAKE_MSG "READY"

#define PORT_HANDLER 7777
#define PORT_COMMAND 7778

//INFECTION
#include "pie/parasite-blob.h"
#include "parasite-syscall.h"
#include "parasite.h"
extern pid_t dsm_pid;
extern struct parasite_ctl *dsm_ctl;
int dsm_ready = 0;
extern volatile bool g_vma_list_ready;
struct vm_area_list* my_vm_area_list;

//#define PAGE_SIZE 4096
#include "page.h" //this takes the page size

#define ACK_WRITE_PROTECT_EXPIRED 0x11
#define GLOBAL_PAGE 0x7fffffffe000  // page-aligned address of `global`

// Setup global variable address 
unsigned long global_addr = 0x7fffffffe5dc;
unsigned long aligned = 0x7fffffffe5dc & ~(PAGE_SIZE - 1);

int restored_pid;
int uffd;
struct msg_info{
	int msg_type;
	long page_addr;
	int page_size;
	long msg_id;
};


enum msg_type{
	MSG_GET_PAGE_LIST,
	MSG_GET_PAGE_DATA,
	MSG_INVALIDATE_PAGE,
	MSG_INVALIDATE_ACK,
	MSG_GET_PAGE_DATA_INVALID,
	MSG_SEND_INVALIDATE,
	MSG_WAKE_THREAD,
	MSG_STOP_THREAD,
	MSG_HANDSHAKE,
	MSG_ACK,
};


struct thread_param {
    int uffd;
    int server_pipe;      // read end for handler
    int uffd_pipe;  // write end for handler
	int fd_handler;
};

/*********************************** VMA RECONSTRUCTION ********************* */
#define VMA_REC 0
#include "vma.h"
#include "mem.h"       // Required for xmalloc()
#include "cr_options.h"
struct vm_area_list *g_vm_area_list;

void print_vm_area_list(struct vm_area_list *list) {
    struct vma_area *vma;
   list_for_each_entry(vma, &list->h, list) {
		pr_info("VMA: 0x%lx-0x%lx prot=%x\n",
			vma->e->start, vma->e->end, vma->e->prot);
	}
}

static struct vma_area *vma_area_alloc(void)
{
    struct vma_area *vma;
    vma = xmalloc(sizeof(*vma));
    if (!vma) return NULL;
    INIT_LIST_HEAD(&vma->list);
    vma->e = xmalloc(sizeof(VmaEntry));
    if (!vma->e) {
        xfree(vma);
        return NULL;
    }
    memset(vma->e, 0, sizeof(VmaEntry));
    return vma;
}
/*
static void add_vma(struct vm_area_list *list, unsigned long start, unsigned long end)
{
    struct vma_area *vma = vma_area_alloc();
    if (!vma) return;
    vma->e->start = start;
    vma->e->end = end;
    list_add_tail(&vma->list, &list->h);  // Append to the vm_area_list
    list->nr++;                           // Increment the count of VMAs
}*/
void reconstruct_vm_area_list(struct vm_area_list *list) {
    char path[64];
    char line[512];
	FILE *fp;
	int prot = 0;
    unsigned long start, end;
	struct vma_area * vma;
    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);
    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return;
    }
	while (fgets(line, sizeof(line), fp)) {
		char perms[5] = {0};
		vma = vma_area_alloc();
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
			if (perms[0] == 'r') prot |= PROT_READ;
			if (perms[1] == 'w') prot |= PROT_WRITE;
			if (perms[2] == 'x') prot |= PROT_EXEC;
			if (!vma)
				continue;

			vma->e->start = start;
			vma->e->end = end;
			vma->e->prot = prot;

			list_add_tail(&vma->list, &list->h);
			list->nr++;
		}
	}
	//Save global vma for future infection
	g_vm_area_list = list;
    fclose(fp);
}


struct parasite_ctl *g_parasite_ctl;

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_proc_maps(void) {
    char path[64];
	FILE *fp;
	char line[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);

    fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to open /proc/<pid>/maps");
        return;
    }

    printf("=== Memory Map of PID %d ===\n", restored_pid);
    
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }

    fclose(fp);
}

/***********************************END VMA RECONSTRUCTION ********************* */


/******************************** USERFAULT ****************************/
int init_userfaultfd_api(int uffd) {
	struct uffdio_api uffdio_api;
	uffdio_api.api = UFFD_API;
	uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;

	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
		perror("ioctl/UFFDIO_API");
		return -1;
	}

	if (uffdio_api.api != UFFD_API) {
		fprintf(stderr, "Unsupported userfaultfd API version (got %llu, expected %llu)\n",
		        uffdio_api.api, UFFD_API);
		return -1;
	}

	if (!(uffdio_api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
		fprintf(stderr, "UFFDIO_WRITEPROTECT feature not supported by kernel\n");
		return -1;
	}

	printf("✅ userfaultfd API initialized with WP support\n");
	return 0;
}	

void register_page(void *addr) {
	struct uffdio_register reg = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode =  UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MISSING
	};

	unsigned char test;
	test = *((unsigned char *)addr);
	printf("Read test byte: %02x\n", test);


	printf("Registering addr = %p (aligned = %ld)\n", addr, (unsigned long)addr % PAGE_SIZE);
	printf("UFFD REGISTER: %d\n", uffd);

	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		perror("UFFDIO_REGISTER");
		exit(1);
	}
}

void enable_wp(void *addr)
{
	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = UFFDIO_WRITEPROTECT_MODE_WP
	};

	printf("UFFD enable: %d\n", uffd);

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
		perror("UFFDIO_WRITEPROTECT (enable)");
	else
		printf("Successfully protected global page at %p\n", addr);
}	

void disable_wp(void *addr)
{
	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = 0  // no WP flag
	};

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
		perror("UFFDIO_WRITEPROTECT (disable)");
	else
		printf("Successfully disabled write protection on page at %p\n", addr);
}

/******************************** END USERFAULT ****************************/


/********************************INFECTION CODE*******************************/
static struct parasite_ctl *g_ctl = NULL;
int g_state;
int start_infection(pid_t pid) {
	int state = compel_stop_task(pid);
	struct infect_ctx *ictx;
	if (!(g_ctl = compel_prepare(pid))) return -1;

	parasite_setup_c_header(g_ctl);
	ictx = compel_infect_ctx(g_ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(g_ctl, 1, sizeof(long)) < 0) {
		xfree(g_ctl);
		return -1;
	}

	return state;
}

void stop_infection(pid_t pid, int state) {
	if (compel_stop_daemon(g_ctl)) pr_err("Can't stop daemon\n");
	if (compel_cure(g_ctl)) pr_err("Can't cure\n");
	if (compel_resume_task(pid, state, state)) pr_err("Can't resume\n");
	xfree(g_ctl);
	g_ctl = NULL;
}


#if 1

int infection_test(void)
{
	struct parasite_ctl *ctl = NULL;
	struct infect_ctx *ictx;
	int state;

	printf("\n=== [TEST] Single Infection Test ===\n");

	// Stop the target task
	state = compel_stop_task(restored_pid);
	printf("Stopped task, state=%d\n", state);

	// Prepare parasite control context
	ctl = compel_prepare(restored_pid);
	if (!ctl) {
		fprintf(stderr, "❌ compel_prepare failed\n");
		return -1;
	}

	// Set up the RPC interface
	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	// Inject the parasite
	if (compel_infect(ctl, 1, 0) < 0) {
		fprintf(stderr, "❌ compel_infect failed\n");
		goto fail;
	}

	// Run a test RPC command
	if (compel_rpc_call_sync(PARASITE_CMD_TEST_PRINT, ctl) < 0) {
		fprintf(stderr, "❌ RPC TEST_PRINT failed\n");
		goto fail;
	}

	printf("✅ Infection and RPC successful\n");

	// Clean up parasite and resume target
	if (compel_stop_daemon(ctl))
		fprintf(stderr, "⚠️ Failed to stop daemon\n");

	if (compel_cure(ctl))
		fprintf(stderr, "⚠️ Failed to cure\n");

	if (compel_resume_task(restored_pid, state, state))
		fprintf(stderr, "⚠️ Failed to resume task\n");

	//xfree(ctl);
	return 0;

fail:
	if (ctl) {
		if (compel_stop_daemon(ctl)) fprintf(stderr, "⚠️ Failed to stop daemon\n");
		if (compel_cure(ctl)) fprintf(stderr, "⚠️ Failed to cure\n");
		//xfree(ctl);
	}
	compel_resume_task(restored_pid, state, state);
	return -1;
}

int stealUFFD(void)
{
	int state, uffd = -1;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	(void) state;

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))){
		printf("Can't prepare for infection\n");
		return -1;
	} 
	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;
	parasite_setup_c_header(ctl);

	if (compel_infect(ctl, 1, sizeof(int)) < 0) {
		printf("Failed infection steal UFFD\n");
		xfree(ctl);
		return -1;
	}	
	if (compel_rpc_call(PARASITE_CMD_STEAL_UFFD, ctl) < 0) {
		pr_err("❌ RPC call to steal UFFD failed\n");
		goto fail;
	}
	if (compel_util_recv_fd(ctl, &uffd) < 0) {
		pr_err("❌ Failed to receive UFFD from parasite\n");
		goto fail;
	}
	if (compel_rpc_sync(PARASITE_CMD_STEAL_UFFD, ctl) < 0) {
		pr_err("❌ Failed to sync\n");
		goto fail;
	}
	pr_info("✅ UFFD = %d\n", uffd);

	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	else printf("Daemon stopped (stealUFFD)\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	else printf("Cured! (stealUFFD)\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	else printf("Resumed post stealUFFD\n");

	return uffd;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
	return -1;
}

int read_invalidate(void *addr)
{
	int state, uffd = -1;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *args;
	(void) state;
	(void) args;

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))) return -1;

	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(ctl, 1, sizeof(int)) < 0) {
		xfree(ctl);
		return -1;
	}

	//test
	if (compel_rpc_call_sync(PARASITE_CMD_TEST_PRINT, ctl) < 0)	pr_err("RPC test failed\n");
	
	
	//Prepare the addr to pass
	args = compel_parasite_args(ctl, long);
	*args = (long)addr;

	if (compel_rpc_call(PARASITE_CMD_INVALIDATE_PAGE, ctl) < 0) {
		pr_err("❌ RPC call to READ INVALIDATE failed\n");
		goto fail;
	}

	if (compel_rpc_sync(PARASITE_CMD_INVALIDATE_PAGE, ctl) < 0) {
		pr_err("❌ Failed to sync on read invalidate\n");
		goto fail;
	}

	//ioctl_test
	//if (compel_rpc_call_sync(PARASITE_CMD_REGISTER_GLOBAL, ctl) < 0)	pr_err("parasite register global failed\n");


	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	else printf("Daemon stopped (stealUFFD)\n");

	if (compel_cure(ctl)) pr_err("Can't cure\n");
	else printf("Cured! (stealUFFD)\n");


	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	else printf("Resumed post stealUFFD\n");

	xfree(ctl); //freeing to be able to reinfect!
	printf("ctl freed post stealUFFD\n");

	return uffd;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
	xfree(ctl);
	return -1;
}

int runMADVISE(void *addr){
	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *args;
	(void) state;
	(void) args;

	printf("[DSM] Sending remote madvise(MADV_DONTNEED) request...\n");

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))){
		pr_err("❌ Compel prepare failed\n");
		return -1;
	} 

	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(ctl, 1, sizeof(long)) < 0) {
		xfree(ctl);
		return -1;
	}

	//Prepare the addr to pass
	args = compel_parasite_args(ctl, long);
	*args = (long)addr;

	
	if (compel_rpc_call(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
		pr_err("❌ RPC call to run MADVISE failed\n");
		goto fail;
	}
	
	if (compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
		pr_err("❌ Failed to sync back from MADVISE\n");
		goto fail;
	}
	
	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	

	return 0;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
	
	return -1;
}
#if 1
int handle_page_data_request(int sk, struct msg_info *dsm_msg) {
    int state, value, p[2];
    long *args;
    unsigned char page_content[4096];
    size_t offset;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    printf("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    // Send page to requesting client
    send(sk, page_content, 4096, 0);
    printf("✅ Page_transfer_complete to client\n");

    // Show value at global_addr for debugging
    offset = global_addr - GLOBAL_PAGE;
    if (offset >= 4096 - sizeof(int)) {
        fprintf(stderr, "Offset out of bounds\n");
    } else {
        memcpy(&value, &page_content[offset], sizeof(int));
        printf("[DSM] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);
    }

    // Handle invalidation or write protection
    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        printf("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n");
        if (compel_rpc_call_sync(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
            fprintf(stderr, "❌ MADV_DONTNEED failed\n");
        }
    } else {
        printf("Message is GET_PAGE → Enable WP to SHARED\n");
        enable_wp((void *)dsm_msg->page_addr);
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);

    return 0;
}
#endif
int test_page_content(struct msg_info *dsm_msg) {
    int state, value, p[2];
    long *args;
    unsigned char page_content[4096];
	size_t offset;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    printf("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    // Set the page address for the parasite
    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

	 if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    // ✅ Extract and print the value at GLOBAL_ADDR
    offset = global_addr - GLOBAL_PAGE;
	if (offset >= 4096 - sizeof(int)) {
		fprintf(stderr, "Offset out of bounds\n");
	} else {
		memcpy(&value, &page_content[offset], sizeof(int));
		printf("[DSM] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);
	}

   
    // Handle invalidation or WP
    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        printf("Message is GET_PAGE_INVALIDATE -> Drop the page to INVALIDATE\n");
        if (compel_rpc_call_sync(PARASITE_CMD_TEST_PRINT, ctl) < 0) {
            fprintf(stderr, "❌ MADV_DONTNEED failed\n");
        }
    } else {
		printf("Message is GET_PAGE -> Enable wp to SHARED \n");
		enable_wp((void *)dsm_msg->page_addr);
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);

    return 0;
}
#endif
/********************************END INFECTION CODE*******************************/

int save_page_to_file(void *addr, const char *filepath) {
	ssize_t written;
	int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open (write)");
		return -1;
	}

	written = write(fd, addr, PAGE_SIZE);
	if (written != PAGE_SIZE) {
		perror("write");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}


#if 1
static void *handler(void *arg) {
    struct thread_param *p = arg;
    struct uffd_msg msg;
    struct pollfd pollfd[1] = {
        { .fd = p->uffd, .events = POLLIN }
    };
	unsigned long addr;
	unsigned char ack = 0;
	unsigned char page_data[PAGE_SIZE] = {0}; 
	struct uffdio_copy copy;

    printf("[handler] started, uffd = %d\n", p->uffd);

    while (1) {
        int pollres = poll(pollfd, 1, -1);
        if (pollres == -1) {
            perror("poll/userfaultfd");
            continue;
        }

        if (!(pollfd[0].revents & POLLIN)) continue;

        if (read(p->uffd, &msg, sizeof(msg)) != sizeof(msg)) {
            perror("read/userfaultfd");
            continue;
        }

        if (!(msg.event & UFFD_EVENT_PAGEFAULT)) continue;

        addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        printf("[handler] page fault at 0x%lx (flags: %llx)\n", addr, msg.arg.pagefault.flags);

        if (addr != GLOBAL_PAGE) {
            printf("[handler] ignoring fault at non-target page\n");
            continue;
        }

        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
            printf("[handler] WRITE-PROTECT fault on global page\n");

            // Notify remote to invalidate or update data
            //send_page_invalidate_msg(addr, p->);

			printf("Simulating sending GET_PAGE, wainting for ack\n");
            //ack = 0;
			ack = ACK_WRITE_PROTECT_EXPIRED;
            //read(p->server_pipe, &ack, 1);
            printf("[handler] ACK received: 0x%x\n", ack);

            if (ack == ACK_WRITE_PROTECT_EXPIRED) {
				//DEMO Remove write protection
				disable_wp( (void *) aligned);
            } else {
                struct uffdio_writeprotect wp = {
                    .range = { .start = addr, .len = PAGE_SIZE },
                    .mode = 0
                };
                ioctl(p->uffd, UFFDIO_WRITEPROTECT, &wp);
            }
        } else {
			printf("[handler] MISSING fault on global page\n");

			memset(page_data, 0, PAGE_SIZE); 
			
			copy.src = (unsigned long)page_data;
			copy.dst = addr;
			copy.len = PAGE_SIZE;
			copy.mode = UFFDIO_COPY_MODE_WP;

			if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1)
				perror("ioctl/copy (missing)");
		}

        printf("[handler] done handling fault at 0x%lx\n", addr);
    }

    return NULL;
}
#endif

void send_sigcont(void){
	// Resume the stopped process
	if (kill(restored_pid, SIGCONT) != 0) {
		perror("kill(SIGCONT)");
		exit(EXIT_FAILURE);
	}
	printf("[DSM Server] Sent SIGCONT to PID %d.\n", restored_pid);
}

void send_sigstop(void){
	// Resume the stopped process
	if (kill(restored_pid, SIGSTOP) != 0) {
		perror("kill(SIGSTOP)");
		exit(EXIT_FAILURE);
	}
	printf("[DSM Server] Sent SIGSTOP to PID %d.\n", restored_pid);
}

void kill_and_exit(void){
	// Resume the stopped process
	if (kill(restored_pid, 9) != 0) {
		perror("kill(9)");
		exit(EXIT_FAILURE);
	}
	printf("[DSM Server] Sent kill -9 to PID %d.\n", restored_pid);
	// exit
	exit(0);
}

void command_loop(void) {
	long *args;
	struct msg_info dsm_msg;
	int bin;
	(void) bin;
	(void) args;	
	(void) dsm_msg;
    while (1) {
        int choice;
        printf("\n[DSM] Enter command:\n");
        printf("  0 = reapply write-protection\n");
        printf("  1 = remote madvise(MADV_DONTNEED)\n> ");
		printf("  2 = restart process (send SIGCONT)\n> ");
		printf("  3 = restart process (send compel cure)\n> ");
		printf("  4 = exit\n> ");
		printf("  5 = simple infection test\n> ");
		printf("  6 = test vmsplice\n> ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input\n");
            while (getchar() != '\n'); // flush
            continue;
        }

        if (choice == 0) {
        	printf("[DSM] Reapplying write-protection on global page...\n");
        	enable_wp((void *) aligned);
        } else if (choice == 1) {

			// Save the page content before madvise removes it
			unsigned char *page_ptr = (unsigned char *)GLOBAL_PAGE;
			int fd = open("/tmp/global-page.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
			if (fd < 0) {
				perror("open /tmp/global-page.bin");
			} else {
				if (write(fd, page_ptr, PAGE_SIZE) != PAGE_SIZE) {
					perror("write global page");
				}
				close(fd);
				printf("[cmd] Global page content saved to /tmp/global-page.bin\n");
			}
			printf("[DSM] Sending remote madvise(MADV_DONTNEED) request...\n");
		
			if( runMADVISE( (void *) aligned) )
				perror("runMADVISE command loop");
			else
				printf("Successfully run madvise on page at %p\n", (void *) aligned);

            
        } else if (choice == 2){
			send_sigcont();
		} else if( choice == 3 ) {
			// Resume the stopped process
			if (compel_resume_task(restored_pid, g_state, g_state)) pr_err("Can't resume\n");
			printf("[DSM Server] Sent compel resume to PID %d.\n", restored_pid);
		} else if( choice == 4 ) {
			kill_and_exit();
			
		} else if( choice == 5 ) {
			//Infection test
			printf("Do infection test\n");
			infection_test();			
		} else if( choice == 6 ){
			//vmsplice test
			printf("Do vmsplice test at %p\n", (void *)aligned);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_GET_PAGE_DATA;
			dsm_msg.page_addr = aligned;
			printf("Do vmsplice test at %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_page_content(&dsm_msg);
		}
		else {
            printf("[DSM] Unknown command: %d\n", choice);
        }
    }
}


procmaps_iterator* maps;
struct params {
    int uffd;
    long page_size;
    int client_send_socket;
};
int total_pages;
static volatile int stop;
int page_size = 4096;


struct dsm_connection {
    int fd_handler;  // used by page fault handler thread
    int fd_command;  // used by listener thread
};



int create_server_socket(int port) {
    int fd, opt = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, BACKLOG) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}


int wait_for_connection(int listen_fd) {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    int conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (conn_fd < 0) {
        perror("accept");
        return -1;
    }
    return conn_fd;
}


int dsm_setup_dual_connections(struct dsm_connection *conn) {
    int fd_handler_listen = create_server_socket(PORT_HANDLER);
    int fd_command_listen = create_server_socket(PORT_COMMAND);

    if (fd_handler_listen < 0 || fd_command_listen < 0)
        return -1;

    printf("[DSM Server] Waiting for handler thread connection on port %d...\n", PORT_HANDLER);
    conn->fd_handler = wait_for_connection(fd_handler_listen);
    if (conn->fd_handler < 0) return -1;

    printf("[DSM Server] Waiting for command thread connection on port %d...\n", PORT_COMMAND);
    conn->fd_command = wait_for_connection(fd_command_listen);
    if (conn->fd_command < 0) return -1;

    close(fd_handler_listen);
    close(fd_command_listen);

    printf("[DSM Server] Connections established:\n");
    printf("  fd_handler = %d\n", conn->fd_handler);
    printf("  fd_command = %d\n", conn->fd_command);

    return 0;
}

void dsm_command_main_loop(int fd_command) {
    struct msg_info msg;
    ssize_t n;

    while (1) {
        printf("[DSM Server] (fd=%d) Waiting for command message...\n", fd_command);

        n = recv(fd_command, &msg, sizeof(msg), 0);
        if (n <= 0) {
            perror("[DSM Server] recv failed or connection closed");
            break;
        } else if (n != sizeof(msg)) {
            fprintf(stderr, "[DSM Server] Incomplete message received (got %zd bytes)\n", n);
            continue;
        }

        printf("[DSM Server] Received message: type=%d, addr=0x%lx, id=%ld\n",
               msg.msg_type, msg.page_addr, msg.msg_id);

        switch (msg.msg_type) {
			case MSG_WAKE_THREAD:
				send_sigcont();
				break;
			case MSG_STOP_THREAD:
				send_sigstop();
				break;
			case MSG_GET_PAGE_DATA:
            case MSG_GET_PAGE_DATA_INVALID:
                printf("→ Handling GET_PAGE_DATA/GET_PAGE_DATA_INVALID\n");
                handle_page_data_request(fd_command, &msg);
                break;
            case MSG_SEND_INVALIDATE:
                printf("→ Handling SEND_INVALIDATE\n");
                printf("[DSM] Sending madvise(MADV_DONTNEED) request...\n");
                if (runMADVISE((void *) msg.page_addr))
                    perror("runMADVISE command loop");
                else
                    printf("Successfully ran madvise on page at %p\n", (void *) msg.page_addr);
                break;

            case MSG_HANDSHAKE:
                printf("[DSM Server] Test handshake message received, ignoring.\n");
                continue;

            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n", msg.msg_type);
                kill_and_exit();  // shutdown the server on protocol error
                break;
        }
    }
}


void read_pid(void)
{
	FILE *f = fopen("/tmp/criu-restored.pid", "r");
	// 4. Read PID and send SIGCONT
	if (!f || fscanf(f, "%d", &restored_pid) != 1) {
		perror("fscanf");
		//close(sockfd);
		exit(EXIT_FAILURE);
	}
	fclose(f);
}

int perform_struct_handshake(int send_fd, int recv_fd, bool is_sender) {
    struct msg_info msg_in, msg_out;
    ssize_t sent, received;

    if (is_sender) {
        // 1. Send handshake message
        msg_out.msg_type = MSG_HANDSHAKE;
        msg_out.page_addr = 0xdeadbeef;
        msg_out.page_size = 4096;
        msg_out.msg_id = 12345;

        sent = send(send_fd, &msg_out, sizeof(msg_out), 0);
        if (sent != sizeof(msg_out)) {
            perror("[HANDSHAKE] Failed to send handshake");
            return -1;
        }

        printf("[HANDSHAKE] Sent MSG_HANDSHAKE on fd %d\n", send_fd);

        // 2. Receive ACK
        received = recv(recv_fd, &msg_in, sizeof(msg_in), 0);
        if (received != sizeof(msg_in)) {
            perror("[HANDSHAKE] Failed to receive ACK");
            return -1;
        }

        if (msg_in.msg_type != MSG_ACK) {
            fprintf(stderr, "[HANDSHAKE] Invalid ACK type: %d\n", msg_in.msg_type);
            return -1;
        }

        printf("[HANDSHAKE] Received MSG_ACK from fd %d\n", recv_fd);
    } else {
        // 1. Receive handshake
        received = recv(recv_fd, &msg_in, sizeof(msg_in), 0);
        if (received != sizeof(msg_in)) {
            perror("[HANDSHAKE] Failed to receive handshake");
            return -1;
        }

        if (msg_in.msg_type != MSG_HANDSHAKE) {
            fprintf(stderr, "[HANDSHAKE] Unexpected message type: %d\n", msg_in.msg_type);
            return -1;
        }

        printf("[HANDSHAKE] Received MSG_HANDSHAKE from fd %d\n", recv_fd);

        // 2. Send ACK
        msg_out.msg_type = MSG_ACK;
        msg_out.page_addr = 0;
        msg_out.page_size = 0;
        msg_out.msg_id = 0;

        sent = send(send_fd, &msg_out, sizeof(msg_out), 0);
        if (sent != sizeof(msg_out)) {
            perror("[HANDSHAKE] Failed to send ACK");
            return -1;
        }

        printf("[HANDSHAKE] Sent MSG_ACK to fd %d\n", send_fd);
    }

    return 0; // success
}

void start_dsm_server(void)
{
	struct vm_area_list vmas = { .nr = 0};
	int server_fd=0, client_fd=0;
	int bin;
	struct dsm_connection conn;
	pthread_t uffd_thread;
	struct thread_param param;
	
	//struct uffdio_register uffdio_register;
#if 0
	struct uffdio_writeprotect wp;
	struct uffdio_api uffdio_api;
#endif
	int fds[2], custom_fd_local, custom_fd_remote; //server-parasite pipes
	int server_pipe[2], uffd_pipe[2]; 
	// server writes server_pipe[1], reads from uffd_pipe[0]
	// uffd writes uffd_pipe[1], reads from server_pipe[0]

	(void) custom_fd_remote; //avoiding unused variable warning WERROR
	(void) custom_fd_local; //avoiding unused variable warning WERROR
	(void) bin; //avoiding unused variable warning WERROR
	vm_area_list_init(&vmas); // CRIU macro

	

	printf("Aligned %p\n", (void*) aligned);
	
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		perror("socketpair");
		exit(1);
	}

	custom_fd_local = fds[0];   // for server-side use
	custom_fd_remote = fds[1];  // to be sent into parasite

	
	
	conn.fd_handler = 0;
#if ENABLE_SERVER
	if (dsm_setup_dual_connections(&conn) < 0) {
		fprintf(stderr, "Failed to set up DSM connections\n");
		exit(EXIT_FAILURE);
	}

	printf("Checking connection as RECEIVER on COMMAND\n");
	perform_struct_handshake(conn.fd_command, conn.fd_command, false);
	printf("Checking connection as SENDEE on COMMAND\n");
	perform_struct_handshake(conn.fd_command, conn.fd_command, true);
#endif 


	read_pid();

#if VMA_REC	
	read_proc_maps();

    reconstruct_vm_area_list(&vmas);
    //print_vm_area_list(&vmas);
#endif
	//Start infection
	uffd = 0;
	uffd = stealUFFD();
	//runMADVISE( (void *) aligned );
	
	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n");
		exit(EXIT_FAILURE);
	}

	register_page( (void *) aligned );/*
	enable_wp( (void *) aligned);
	disable_wp( (void *) aligned);
	enable_wp( (void *) aligned);*/

	//read_invalidate( (void *) aligned);

	//Creating pipes 
	if (pipe(server_pipe) == -1 || pipe(uffd_pipe) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	//Start UFFD thread
	param.uffd = uffd;               // from stealUFFD()
	param.server_pipe = server_pipe[0];    // read end for handler
	param.uffd_pipe = uffd_pipe[1];  // write end for handler
	param.fd_handler = conn.fd_handler;
	//Spawn handler thread
	pthread_create(&uffd_thread, NULL, handler, &param);
	


#if COMMAND_LOOP
	command_loop();
#else
	printf("[DSM Server] Connections established. Entering main loop...\n");
    dsm_command_main_loop(conn.fd_command);
#endif
	if( client_fd )	close(client_fd);
	if( server_fd ) close(server_fd);
	

	//Freeing vmas
	free_mappings(&vmas); 
}
