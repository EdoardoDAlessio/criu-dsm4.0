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


#define SIGMAX 64
/*
typedef void rt_signalfn_t(int, siginfo_t *, void *);
typedef rt_signalfn_t *rt_sighandler_t;

typedef void rt_restorefn_t(void);
typedef rt_restorefn_t *rt_sigrestore_t;

#define _KNSIG          64
#define _NSIG_BPW       64
#define _KNSIG_WORDS    (_KNSIG / _NSIG_BPW)

typedef struct {
    unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

typedef struct {
    rt_sighandler_t rt_sa_handler;
    unsigned long   rt_sa_flags;
    rt_sigrestore_t rt_sa_restorer;
    k_rtsigset_t    rt_sa_mask;
} rt_sigaction_t;

typedef struct {
    unsigned long entry;
    unsigned long desc[3];
} tls_t;*/
//#include "types.h"

#include <compel/infect.h> //for compel_parasite_args

#include <compel/ptrace.h>
//#include "../compel/include/infect-priv.h" needed if  low-level register access or context setup manually.
#include "util-pie.h"
#include "asm/types.h"

#include "parasite.h"

#include "vma.h" 
struct vm_area_list *g_vma_area_list;

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

//#include "parsemap.h" //for parse_vmas


#define HANDSHAKE_MSG "READY"
#define PORT 7777


//#define PAGE_SIZE 4096
#include "page.h" //this takes the page size

#define ACK_WRITE_PROTECT_EXPIRED 0x11
#define GLOBAL_PAGE 0x555555558000  // page-aligned address of `global`

int uffd;
struct msg_info{
	int msg_type;
	long page_addr;
	int page_size;
	long msg_id;
};

struct thread_param {
    int uffd;
    int server_pipe;      // read end for handler
    int uffd_pipe;  // write end for handler
};


struct parasite_ctl *g_parasite_ctl;
struct parasite_ctl *parasite_infect_seized(pid_t pid, struct pstree_item *item, struct vm_area_list *vma_area_list);


int stealUFFD(int pid, struct pstree_item *item) {
	int uffd;

	// Inject parasite once
	g_parasite_ctl = parasite_infect_seized(pid, item, g_vma_area_list);
	if (!g_parasite_ctl) {
		fprintf(stderr, "Can't infect (pid: %d) with parasite\n", pid);
		return -1;
	}

	// Send RPC to ask for UFFD
	if (compel_rpc_call(PARASITE_CMD_STEAL_UFFD, g_parasite_ctl) || 
	    compel_util_recv_fd(g_parasite_ctl, &uffd) || 
	    compel_rpc_sync(PARASITE_CMD_STEAL_UFFD, g_parasite_ctl)) {
		fprintf(stderr, "Failed to steal UFFD\n");
		return -1;
	}

	/* Resume the process — parasite stays resident
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
		perror("PTRACE_CONT");
		return -1;
	}*/

	printf("[DSM] UFFD stolen successfully: %d\n", uffd);
	return uffd;
}


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

            ack = 0;
            read(p->server_pipe, &ack, 1);
            printf("[handler] ACK received: 0x%x\n", ack);

            if (ack == ACK_WRITE_PROTECT_EXPIRED) {
                unsigned char page_data[PAGE_SIZE] = {0};
                //uffd_int_get_page_data_from_remote(p->, , addr, page_data);

                struct uffdio_copy copy = {
                    .src = (unsigned long)page_data,
                    .dst = addr,
                    .len = PAGE_SIZE,
                    .mode = 0
                };
                if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1)
                    perror("ioctl/copy (wp expired)");
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

void command_loop(void) {
	struct uffdio_writeprotect wp;
	long *args;
    while (1) {
        int choice;
        printf("\n[DSM] Enter command:\n");
        printf("  0 = reapply write-protection\n");
        printf("  1 = remote madvise(MADV_DONTNEED)\n> ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input\n");
            while (getchar() != '\n'); // flush
            continue;
        }

        if (choice == 0) {
            printf("[DSM] Reapplying write-protection on global page...\n");

            wp.range.start = GLOBAL_PAGE;
            wp.range.len = PAGE_SIZE;
            wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
            

            if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1) {
                perror("UFFDIO_WRITEPROTECT");
            } else {
                printf("[DSM] Write-protection reapplied.\n");
            }

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

            args = compel_parasite_args(g_parasite_ctl, long);
            *args = GLOBAL_PAGE;

            if (compel_rpc_call(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl) ||
                compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, g_parasite_ctl)) {
                fprintf(stderr, "[DSM] Failed to issue remote madvise\n");
            } else {
                printf("[DSM] Remote madvise triggered on global page.\n");
            }

        } else {
            printf("[DSM] Unknown command: %d\n", choice);
        }
    }
}

#define DGB 0

void start_dsm_server(struct pstree_item *item)
{
	int server_fd=0, client_fd=0;
	int restored_pid, bin, uffd;
#if DBG 
	struct sockaddr_in addr;
	char buffer[64] = {0};
	socklen_t addrlen = sizeof(addr);
	int n, opt = 1;
#endif
	FILE *f;
	struct uffdio_api uffdio_api;	
	struct uffdio_register uffdio_register;
	struct uffdio_writeprotect wp;
	struct thread_param param;
	pthread_t uffd_thread;

	// Setup global variable address 
	unsigned long global_addr = 0x555555558080;
	unsigned long aligned = global_addr & ~(PAGE_SIZE - 1);

	int server_pipe[2], uffd_pipe[2]; 
	// server writes server_pipe[1], reads from uffd_pipe[0]
	// uffd writes uffd_pipe[1], reads from server_pipe[0]

	(void) bin; //avoiding unused variable warning WERROR

#if DBG
	// 1. Set up TCP server socket
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, 1) < 0) {
		perror("listen");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Server] Waiting for client on port %d...\n", PORT);

	client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
	if (client_fd < 0) {
		perror("accept");
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	// 2. Receive handshake
	n = read(client_fd, buffer, sizeof(buffer) - 1);
	if (n <= 0) {
		perror("read");
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	buffer[n] = '\0';
	if (strcmp(buffer, HANDSHAKE_MSG) != 0) {
		fprintf(stderr, "[DSM Server] Invalid handshake: %s\n", buffer);
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Server] Handshake received. Resuming process.\n");
#endif 
	// 3. Read PID from file
	f = fopen("/tmp/criu-restored.pid", "r");
	if (!f || fscanf(f, "%d", &restored_pid) != 1) {
		perror("fscanf");
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}
	fclose(f);

	
	//4. Get the vma area list
	g_vma_area_list = malloc(sizeof(struct vm_area_list));
	if (!g_vma_area_list) {
		perror("malloc g_vma_area_list");
		exit(1);
	}

	f = fopen("/tmp/vma_list.bin", "rb");
	if (!f) {
		perror("fopen vma_list.bin");
		exit(1);
	}
	if (fread(g_vma_area_list, sizeof(struct vm_area_list), 1, f) != 1) {
		perror("fread vma_list");
		exit(1);
	}
	fclose(f);


	// 5. Steal UFFD with Compel infection
	uffd = stealUFFD(restored_pid, item);

	
	// 7. Initialize userfaultfd API
	uffdio_api.api = UFFD_API;
	uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;

	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
		perror("ioctl/uffdio_api");
		exit(1);
	}

	if (!(uffdio_api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
		fprintf(stderr, "UFFD write-protect not supported\n");
		exit(1);
	}

	// 8. Register the global page
	uffdio_register.range.start = aligned;
	uffdio_register.range.len = PAGE_SIZE;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;

	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
		perror("ioctl/uffdio_register");
		exit(1);
	}

	// 9. Enable write-protection
	wp.range.start = aligned;
	wp.range.len = PAGE_SIZE;
	wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1) {
		perror("ioctl/uffdio_writeprotect");
		exit(1);
	}

	printf("Successfully registered and protected global page at %lx\n", aligned);


	//Creating pipes 
	if (pipe(server_pipe) == -1 || pipe(uffd_pipe) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	param.uffd = uffd;               // from stealUFFD()
	param.server_pipe = server_pipe[0];    // read end for handler
	param.uffd_pipe = uffd_pipe[1];  // write end for handler


	//Spawn handler thread
	pthread_create(&uffd_thread, NULL, handler, &param);






	// 4. Resume the stopped process
	if (kill(restored_pid, SIGCONT) != 0) {
		perror("kill(SIGCONT)");
		close(client_fd);
		close(server_fd);
		exit(EXIT_FAILURE);
	}

	printf("[DSM Server] Sent SIGCONT to PID %d.\n", restored_pid);


	command_loop();


	bin = compel_stop_daemon(g_parasite_ctl);
	bin = compel_cure(g_parasite_ctl);

	if( client_fd )	close(client_fd);
	if( server_fd ) close(server_fd);

}
