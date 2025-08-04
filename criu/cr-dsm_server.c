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

#define VMA_REC 1
#define SIGMAX 64


pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#define err_and_ret(msg) do { fprintf(stderr, msg);  return -1; } while (0)
//#include "../compel/include/infect-priv.h" needed if  low-level register access or context setup manually.
#include "util-pie.h"
#include "asm/types.h"
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

//#include "parsemap.h"


//INFECTION
#include "pie/parasite-blob.h"
#include "parasite-syscall.h"
#include "parasite.h"
struct vm_area_list* my_vm_area_list;

//#define PAGE_SIZE 4096
#include "page.h" //this takes the page size



// Setup global variable address 
extern unsigned long global_addr;
extern unsigned long aligned;

int restored_pid;
int uffd;

#include "dsm.h"



#if 1
static void *handler(void *arg) {
    struct thread_param *p = arg;
    struct uffd_msg msg;
	struct msg_info dsm_msg;
    struct pollfd pollfd[1] = {
        { .fd = p->uffd, .events = POLLIN }
    };
	unsigned long addr;
	unsigned char ack = 0;
	unsigned char page_data[PAGE_SIZE] = {0}; 
	struct uffdio_copy copy;
	size_t n;
    PRINT("[handler] started, uffd = %d\n", p->uffd);

	sleep(5);
	if(!DBG) send_sigcont(restored_pid);

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
        PRINT("[handler] page fault at 0x%llx, page:0x%lx (flags: %llx)\n", msg.arg.pagefault.address, addr, msg.arg.pagefault.flags);


        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
            PRINT("[handler] WRITE-PROTECT fault on global page\n");
			//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
			// to make SERVER issue the drop page to all 
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = addr;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;

			// Send invalidate request
			if (send(p->fd_handler[0 ], &dsm_msg, sizeof(dsm_msg), 0) != sizeof(dsm_msg)) {
				perror("[CLIENT] Failed to send MSG_SEND_INVALIDATE");
				return NULL;
			}
			PRINT("[CLIENT] Sent MSG_SEND_INVALIDATE to server. With address:0x%lx\n", addr);

			n = recv(p->fd_handler[0 ], &ack, 1, MSG_WAITALL);
			if (n != 1) {
				fprintf(stderr, "[CLIENT] Failed to receive ACK (got %zd bytes)\n", n);
				return NULL;
			}
			if (ack != MSG_INVALIDATE_ACK) {
				fprintf(stderr, "[CLIENT] Unexpected ACK value: 0x%x\n", ack);
				return NULL;
			}
			PRINT("[CLIENT] Received MSG_INVALIDATE_ACK on INVALIDATION\n");

			// Now you can safely disable WP
    		disable_wp(uffd, (void *)addr);
        } else {
			PRINT("[handler] MISSING fault on tracked page\n");

			dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
			dsm_msg.page_addr = addr;
			dsm_msg.page_size = PAGE_SIZE;
			dsm_msg.msg_id = 1001;

			if (send_get_page(dsm_msg, p->fd_handler[0 ], page_data) == 0) {
				print_global_value_from_page(page_data, sizeof(page_data));
			}else if (send_get_page(dsm_msg, p->fd_handler[0 ], page_data) < 0) {
				fprintf(stderr, "[handler] Failed to fetch page from remote\n");
				continue;
			}
			copy.src  = (unsigned long)page_data;
			copy.dst  = addr;
			copy.len  = PAGE_SIZE;
			copy.mode = UFFDIO_COPY_MODE_WP;

			if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1)
				perror("ioctl/copy (missing)");

			PRINT("[handler] Page copied back to missing region\n");
		}
        PRINT("[handler] done handling fault at 0x%lx\n", addr);
    }

    return NULL;
}
#endif

struct params {
    int uffd;
    long page_size;
    int client_send_socket;
};
int total_pages;
static volatile int stop;
int page_size = 4096;


#if ENABLE_SERVER
void dsm_command_main_loop(int fd_command) {
    struct msg_info msg;
    ssize_t n;
	unsigned char ack;

    while (1) {
        PRINT("[DSM Server] (fd=%d) Waiting for command message...\n", fd_command);

        n = recv(fd_command, &msg, sizeof(msg), 0);
        if (n <= 0) {
            perror("[DSM Server] recv failed or connection closed");
            break;
        } else if (n != sizeof(msg)) {
            fprintf(stderr, "[DSM Server] Incomplete message received (got %zd bytes)\n", n);
            continue;
        }

        PRINT("[DSM Server] Received message: type=%d, addr=0x%lx, id=%ld\n",
               msg.msg_type, msg.page_addr, msg.msg_id);

        switch (msg.msg_type) {
			case MSG_WAKE_THREAD:
				send_sigcont(restored_pid);
				break;
			case MSG_STOP_THREAD:
				send_sigstop(restored_pid);
				break;
			case MSG_GET_PAGE_DATA:
            case MSG_GET_PAGE_DATA_INVALID:
                PRINT("→ Handling GET_PAGE_DATA/GET_PAGE_DATA_INVALID\n");
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
                break;
            case MSG_SEND_INVALIDATE:
				PRINT("→ Handling SEND_INVALIDATE\n");
				PRINT("[DSM] Sending madvise(MADV_DONTNEED) request...\n");

				if (runMADVISE(restored_pid, (void *)msg.page_addr, 4096)) {
					perror("runMADVISE command loop");
				} else {
					PRINT("Successfully ran madvise on page at %p\n", (void *)msg.page_addr);

					ack = MSG_INVALIDATE_ACK;
					if (send(fd_command, &ack, 1, 0) != 1) {
						perror("send MSG_INVALIDATE_ACK");
					} else {
						PRINT("[SERVER] Sent MSG_INVALIDATE_ACK to client.\n");
					}
				}
				break;

            case MSG_HANDSHAKE:
                PRINT("[DSM Server] Test handshake message received, ignoring.\n");
                continue;

            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
    }
}
#endif
#if COMMAND_THREAD
struct command_thread_args {
    int restored_pid;
    int uffd;
    struct dsm_connection conn;
};

void* command_thread_func_server(void* arg) {
    struct command_thread_args* args = arg;
    command_loop(args->restored_pid, args->uffd, &args->conn);
    return NULL;
}

#endif


void start_dsm_server(void)
{
	struct vm_area_list vmas = { .nr = 0};
	int server_fd=0, client_fd=0;
	int bin, i;
	struct dsm_connection conn[NUM_THREADS];
	pthread_t uffd_thread;
	struct thread_param param;
	unsigned long base_address;
	
    
#if COMMAND_THREAD

	pthread_attr_t attr;
	pthread_t command_thread;
	struct command_thread_args* args;
#endif
	unsigned long page;
	int fds[2], custom_fd_local, custom_fd_remote; //server-parasite pipes
	int server_pipe[2], uffd_pipe[2]; 
	// server writes server_pipe[1], reads from uffd_pipe[0]
	// uffd writes uffd_pipe[1], reads from server_pipe[0]

	(void) page;
	(void) custom_fd_remote; //avoiding unused variable warning WERROR
	(void) custom_fd_local; //avoiding unused variable warning WERROR
	(void) bin; //avoiding unused variable warning WERROR
	(void) i;
	vm_area_list_init(&vmas); // CRIU macro

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		perror("socketpair");
		exit(1);
	}

	custom_fd_local = fds[0];   // for server-side use
	custom_fd_remote = fds[1];  // to be sent into parasite

#if ENABLE_SERVER
	for( i = 0; i < NUM_THREADS; i++ ){
		if (dsm_setup_dual_connections(&conn[i]) < 0) {
				fprintf(stderr, "Failed to set up DSM connections\n");
				exit(EXIT_FAILURE);
		}
		param.fd_handler[i] = conn[i].fd_handler; //give the thread's fault handler the connection to all clients

		PRINT("Checking connection as RECEIVER on COMMAND\n");
		perform_struct_handshake(conn[i].fd_command, conn[i].fd_command, false);
		PRINT("Checking connection as SENDEE on COMMAND\n");
		perform_struct_handshake(conn[i].fd_command, conn[i].fd_command, true);
	}
	
	
#endif 

	read_pid(&restored_pid);
	
#if VMA_REC	
	read_proc_maps(restored_pid);

    reconstruct_vm_area_list(restored_pid, &vmas);
    //print_vm_area_list(&vmas);
#endif
	//Start infection
	uffd = 0;
	uffd = stealUFFD(restored_pid);
	
#if DEMO
	//replaceGlobalWithAnonPage(restored_pid, (void *) aligned);
	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n");
		exit(EXIT_FAILURE);
	}
	else PRINT("Success initialize userfaultfd API\n");
	base_address = get_base_address(restored_pid);
	printf("Calling scan_and_prepare_coalesced_globals with base address:%lx\n", base_address);
	scan_and_prepare_coalesced_globals(base_address, restored_pid, uffd, MODIFIED);

	//register_page( uffd, (void *) aligned );
	//enable_wp( uffd, (void *) aligned );
#else
	register_and_write_protect_coalesced(restored_pid, uffd, MODIFIED);
	//replaceGlobalWithAnonPage(restored_pid, (void *) aligned);
	//register_page( uffd, (void *) aligned );
#endif

	//Creating pipes 
	if (pipe(server_pipe) == -1 || pipe(uffd_pipe) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	//Start UFFD thread
	param.uffd = uffd;               // from stealUFFD()
	param.server_pipe = server_pipe[0];    // read end for handler
	param.uffd_pipe = uffd_pipe[1];  // write end for handler
	//Spawn handler thread
	pthread_create(&uffd_thread, NULL, handler, &param);
	


#if COMMAND_THREAD
	PRINT("[DSM Server] Connections established. Creating thread for command loop\n");

	args = malloc(sizeof(struct command_thread_args));
	if (!args) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	args->restored_pid = restored_pid;
	args->uffd = uffd;
	args->conn = conn[0];  // shallow copy is OK here


	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&command_thread, &attr, command_thread_func_server, args) != 0) {
		perror("pthread_create (command loop)");
		free(args);
		exit(EXIT_FAILURE);
	}

	pthread_attr_destroy(&attr);

	PRINT("[DSM Server] After creating thread. Entering main loop...\n");
	#if ENABLE_SERVER
    dsm_command_main_loop(conn[0].fd_command);
	#endif
#elif COMMAND_LOOP
	PRINT("[DSM Server] Connections established. Entering command loop\n");
	command_loop(restored_pid, uffd, &conn[0]);
#elif ENABLE_SERVER
	PRINT("[DSM Server] Connections established. Entering main loop...\n");
    dsm_command_main_loop(conn[0].fd_command);
	if(!DBG) send_sigcont(restored_pid);
#endif


	

	if( client_fd )	close(client_fd);
	if( server_fd ) close(server_fd);
	
	//Freeing vmas
	free_mappings(&vmas); 
}
