#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#define HANDSHAKE_MSG "READY"
#define PORT_HANDLER 7778
#define PORT_COMMAND 7777
int restored_pid, uffd;

/***************** INFECTION HEADERS ************************/
#include "pie/parasite-blob.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "util.h" //xfree
#include <compel/infect.h> //for compel_parasite_args
#include <compel/ptrace.h>
#include "compel/plugins/std/fds.h"
#include "compel/include/uapi/infect-util.h"
int dsm_ready = 0;
struct vm_area_list* my_vm_area_list;
int g_state;
/***************** END INFECTION HEADERS ************************/

/***************** USERFAULTFD HEADERS ************************/
#include <sys/types.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>	
#include "user.h"
#include "page.h" //this takes the page size
#define ACK_WRITE_PROTECT_EXPIRED 0x11
// Setup global variable address 
#define GLOBAL_PAGE 0x7fffffffe000  // page-aligned address of `global`
unsigned long global_addr = 0x7fffffffe5dc;
unsigned long aligned = 0x7fffffffe5dc & ~(PAGE_SIZE - 1);
/***************** END USERFAULTFD HEADERS ************************/

/*DSM LOGIC*/
struct thread_param {
    int uffd;
    int server_pipe;      // read end for handler
    int uffd_pipe;  // write end for handler
	int fd_handler;
};

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

struct dsm_connection {
    int fd_handler;  // used by page fault handler thread
    int fd_command;  // used by listener thread
};
/******************************** USERFAULT FUNCTIONS ****************************/

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
	int fd;

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

			fd = open("/tmp/global-page.bin", O_RDONLY);
			if (fd >= 0) {
				if (read(fd, page_data, PAGE_SIZE) != PAGE_SIZE)
					perror("read global-page.bin");
				close(fd);
			} else {
				perror("open global-page.bin");
			}

			
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


/******************************** END USERFAULT FUNCTIONS ****************************/

/******************************** INFECTION FUNCTIONS *******************************/

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

	return 0;
fail:
	if (ctl) {
		if (compel_stop_daemon(ctl)) fprintf(stderr, "⚠️ Failed to stop daemon\n");
		if (compel_cure(ctl)) fprintf(stderr, "⚠️ Failed to cure\n");
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
	else printf("Daemon stopped (steal UFFD)\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	else printf("Cured! (steal UFFD)\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	else printf("Resumed post steal UFFD\n");

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
	else printf("Daemon stopped (read)\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	else printf("Cured! (read)\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	else printf("Resumed post read\n");

	printf("ctl freed post read\n");

	return uffd;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
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


int send_get_page(struct msg_info dsm_msg, int fd_handler) {
    unsigned char page_content[4096];
    size_t offset, n;
    int value;
	
    // 1. Send the message to the handler socket
    if (send(fd_handler, &dsm_msg, sizeof(dsm_msg), 0) != sizeof(dsm_msg)) {
        perror("[CLIENT] Failed to send MSG_GET_PAGE_DATA");
        return -1;
    }

    printf("[CLIENT] Sent MSG_GET_PAGE_DATA to server (fd=%d)\n", fd_handler);

    // 2. Receive 4096 bytes (1 page) from server
    n = recv(fd_handler, page_content, 4096, MSG_WAITALL);
    if (n != 4096) {
        fprintf(stderr, "[CLIENT] Failed to receive full page (got %zd bytes)\n", n);
        return -1;
    }

    // 3. Compute offset and print value at global_addr
    offset = global_addr - GLOBAL_PAGE;
    if (offset >= 4096 - sizeof(int)) {
        fprintf(stderr, "[CLIENT] Offset out of bounds (offset=%zu)\n", offset);
        return -1;
    }

    memcpy(&value, &page_content[offset], sizeof(int));
    printf("[CLIENT] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);

    return 0;
}


/******************************** END INFECTION FUNCTIONS *******************************/

/********************************* TESTING FUNCTIONS ***************************************/


void command_loop(struct dsm_connection* conn) {
	long *args;
	int bin;
	struct msg_info dsm_msg = {0};
	(void) bin;
	(void) args;	
	(void) dsm_msg;	
    while (1) {
        int choice;
        printf("\n[DSM] Enter command:\n");
        printf("  0 = reapply write-protection\n");
        printf("  1 = remote madvise(MADV_DONTNEED)\n> ");
		printf("  21 = restart process (send SIGCONT)\n> ");
		printf("  22 = stop process (send SIGSTOP)\n> ");
		printf("  3 = restart process (send compel cure)\n> ");
		printf("  4 = exit\n> ");
		printf("  5 = simple infection test\n> ");
		printf("  6 = test vmsplice\n> ");

		printf("  7 = SIMULATE GET_PAGE_DATA\n> ");
		printf("  8 = SIMULATE GET_PAGE_DATA_AND_INVALIDATE\n> ");
		printf("  9 = SIMULATE INVALIDATE\n> ");
		printf("  10 = WAKE UP REMOTE THREAD\n> ");
		printf("  11 = STOP REMOTE THREAD\n> ");
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
			printf("[DSM] Sending remote madvise(MADV_DONTNEED) request...\n");
			
			if( runMADVISE( (void *) aligned) )
				perror("runMADVISE command loop");
			else
				printf("Successfully run madvise on page at %p\n", (void *) aligned);
        } else if (choice == 21){
			// Resume the stopped process
			if (kill(restored_pid, SIGCONT) != 0) {
				perror("kill(SIGCONT)");
				exit(EXIT_FAILURE);
			}
			printf("[DSM Server] Sent SIGCONT to PID %d.\n", restored_pid);
		} else if (choice == 22){
			// Stop the resumed process
			if (kill(restored_pid, SIGSTOP) != 0) {
				perror("kill(SIGSTOP)");
				exit(EXIT_FAILURE);
			}
			printf("[DSM Server] Sent SIGSTOP to PID %d.\n", restored_pid);
		}else if( choice == 3 ) {
			// Resume the stopped process
			if (compel_resume_task(restored_pid, g_state, g_state)) pr_err("Can't resume\n");
			printf("[DSM Server] Sent compel resume to PID %d.\n", restored_pid);
		} else if( choice == 4 ) {
			// Resume the stopped process
			if (kill(restored_pid, 9) != 0) {
				perror("kill(9)");
				exit(EXIT_FAILURE);
			}
			printf("[DSM Server] Sent kill -9 to PID %d.\n", restored_pid);
			// exit
			exit(0);
			
		} else if( choice == 5 ) {
			//Infection test
			printf("Do infection test\n");
			infection_test();			
		}else if( choice == 6 ){
			//vmsplice test
			printf("Do vmsplice test at %p\n", (void *)aligned);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			printf("Do vmsplice test at %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_page_content(&dsm_msg);
		}else if (choice == 7) {
			// SIMULATE GET_PAGE_DATA
			dsm_msg.msg_type = MSG_GET_PAGE_DATA;
			dsm_msg.page_addr = GLOBAL_PAGE;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
			send_get_page(dsm_msg, conn->fd_handler);
		} else if (choice == 8) {
			// SIMULATE GET_PAGE_DATA_AND_INVALIDATE
			dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
			dsm_msg.page_addr = GLOBAL_PAGE;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
			send_get_page(dsm_msg, conn->fd_handler);
			printf("[CLIENT] Sent MSG_GET_PAGE_DATA_INVALID to server.\n");
		} else if (choice == 9) {
			// SIMULATE INVALIDATE
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = GLOBAL_PAGE;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			printf("[CLIENT] Sent MSG_SEND_INVALIDATE to server.\n");
		}else if (choice == 10) {
			dsm_msg.msg_type = MSG_WAKE_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			printf("[CLIENT] Sent MSG_WAKE_THREAD to server.\n");
		}else if (choice == 11) {
			dsm_msg.msg_type = MSG_STOP_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			printf("[CLIENT] Sent MSG_STOP_THREAD to server.\n");
		}else {
            printf("[DSM] Unknown command: %d\n", choice);
        }
    }
}

/********************************* END TESTING FUNCTIONS ***************************************/

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

/********************************* CONNECTION FUNCTIONS ***************************************/
int connect_to_port(const char *server_ip, int port)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
		fprintf(stderr, "[DSM Client] Invalid IP: %s\n", server_ip);
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Client] Connecting to %s:%d...\n", server_ip, port);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("connect");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

int dsm_client_dual_connect(struct dsm_connection *conn, const char *server_ip) {
	conn->fd_command = connect_to_port(server_ip, PORT_COMMAND);
	conn->fd_handler = connect_to_port(server_ip, PORT_HANDLER);

	if (conn->fd_command < 0 || conn->fd_handler < 0) {
		perror("[DSM Client] Failed to connect to server ports");
		if (conn->fd_command >= 0) close(conn->fd_command);
		if (conn->fd_handler >= 0) close(conn->fd_handler);
		return -1;
	}

	/*
	// Perform handshake on each connection to verify both are alive and valid
	if (perform_struct_handshake(conn->fd_command, conn->fd_command, true) < 0) {
		fprintf(stderr, "[DSM Client] Command connection handshake failed\n");
		close(conn->fd_command);
		close(conn->fd_handler);
		return -1;
	}

	if (perform_struct_handshake(conn->fd_handler, conn->fd_handler, true) < 0) {
		fprintf(stderr, "[DSM Client] Handler connection handshake failed\n");
		close(conn->fd_command);
		close(conn->fd_handler);
		return -1;
	}*/

	printf("[DSM Client] fd_command = %d, fd_handler = %d\n", conn->fd_command, conn->fd_handler);
	printf("[DSM Client] Dual connection established successfully.\n");

	return 0;
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

/********************************* END CONNECTION FUNCTIONS ***************************************/


/********************************* MAIN ***************************************/
void start_dsm_client(const char *server_ip)
{
	struct dsm_connection conn;
	pthread_t uffd_thread;
	struct thread_param param;
	int client_pipe[2], uffd_pipe[2]; 

	if (dsm_client_dual_connect(&conn, server_ip) < 0) {
		fprintf(stderr, "DSM client connection failed\n");
		exit(EXIT_FAILURE);
	}

	printf("Checking connection as SENDER on HANDLER\n");
	perform_struct_handshake(conn.fd_handler, conn.fd_handler, true);
	printf("Checking connection as RECEIVER on HANDLER\n");
	perform_struct_handshake(conn.fd_handler, conn.fd_handler, false);

	read_pid();

	uffd = stealUFFD();

	//Creating pipes 
	if (pipe(client_pipe) == -1 || pipe(uffd_pipe) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}
	//Start UFFD thread
	param.uffd = uffd;               // from stealUFFD()
	//param.server_pipe = server_pipe[0];    // read end for handler
	//param.uffd_pipe = uffd_pipe[1];  // write end for handler
	param.fd_handler = conn.fd_handler;
	//Spawn handler thread
	pthread_create(&uffd_thread, NULL, handler, &param);
	

	


	command_loop(&conn);

}
