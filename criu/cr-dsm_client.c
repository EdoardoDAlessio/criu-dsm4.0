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
int restored_pid, uffd;

#define SIGMAX 64

/***************** INFECTION HEADERS ************************/
#include "pie/parasite-blob.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "util.h" //xfree
#include <compel/infect.h> //for compel_parasite_args
#include <compel/ptrace.h>
#include "compel/plugins/std/fds.h"
#include "compel/include/uapi/infect-util.h"
struct vm_area_list* my_vm_area_list;
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
// Setup global variable address 
extern unsigned long global_addr;
extern unsigned long aligned;
/***************** END USERFAULTFD HEADERS ************************/

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
	//dsm_msg.msg_type = MSG_WAKE_THREAD;
	//send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0);
	//printf("[CLIENT] Sent MSG_WAKE_THREAD to server.\n");
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
			if (send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0) != sizeof(dsm_msg)) {
				perror("[CLIENT] Failed to send MSG_SEND_INVALIDATE");
				return NULL;
			}
			PRINT("[CLIENT] Sent MSG_SEND_INVALIDATE to server. With address:0x%lx\n", addr);

			n = recv(p->fd_handler[0], &ack, 1, MSG_WAITALL);
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
			PRINT("[handler] MISSING fault on global page\n");

			dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
			dsm_msg.page_addr = addr;
			dsm_msg.page_size = PAGE_SIZE;
			dsm_msg.msg_id = 1001;

			if (send_get_page(dsm_msg, p->fd_handler[0], page_data) == 0) {
				print_global_value_from_page(page_data, sizeof(page_data));
			}else if (send_get_page(dsm_msg, p->fd_handler[0], page_data) < 0) {
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



#if COMMAND_THREAD
struct command_thread_args {
    int restored_pid;
    int uffd;
    struct dsm_connection conn;
};

void* command_thread_func(void* arg) {
    struct command_thread_args* args = arg;
    command_loop(args->restored_pid, args->uffd, &args->conn);
    return NULL;
}

#endif

void dsm_client_main_loop(int fd_command) {
    struct msg_info msg;
    ssize_t n;
	unsigned char ack;
    while (1) {
        PRINT("[DSM Client] (fd=%d) Waiting for command message...\n", fd_command);

        n = recv(fd_command, &msg, sizeof(msg), 0);
        if (n <= 0) {
            perror("[DSM Client] recv failed or connection closed");
            break;
        } else if (n != sizeof(msg)) {
            fprintf(stderr, "[DSM Client] Incomplete message received (got %zd bytes)\n", n);
            continue;
        }

        PRINT("[DSM Client] Received message: type=%d, addr=0x%lx, id=%ld\n",
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

				if (runMADVISE(restored_pid, (void *)msg.page_addr)) {
					perror("runMADVISE command loop");
				} else {
					PRINT("Successfully ran madvise on page at %p\n", (void *)msg.page_addr);

					ack = MSG_INVALIDATE_ACK;
					if (send(fd_command, &ack, 1, 0) != 1) {
						perror("send MSG_INVALIDATE_ACK");
					} else {
						PRINT("[Client] Sent MSG_INVALIDATE_ACK to client.\n");
					}
				}
				break;

            case MSG_HANDSHAKE:
                PRINT("[DSM Client] Test handshake message received, ignoring.\n");
                continue;

            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the Client on protocol error
                break;
        }
    }
}



/********************************* MAIN ***************************************/
void start_dsm_client(const char *server_ip)
{
	struct vm_area_list vmas = { .nr = 0};
	struct dsm_connection conn;
	pthread_t uffd_thread;
	struct thread_param param;
	int client_pipe[2], uffd_pipe[2]; 


	#if COMMAND_THREAD
		pthread_attr_t attr;
		pthread_t command_thread;
		struct command_thread_args* args;
	#endif

	
	vm_area_list_init(&vmas); // CRIU macro

	if (dsm_client_dual_connect(&conn, server_ip) < 0) {
		fprintf(stderr, "DSM client connection failed\n");
		exit(EXIT_FAILURE);
	}

	PRINT("Checking connection as SENDER on HANDLER\n");
	perform_struct_handshake(conn.fd_handler, conn.fd_handler, true);
	PRINT("Checking connection as RECEIVER on HANDLER\n");
	perform_struct_handshake(conn.fd_handler, conn.fd_handler, false);

	read_pid(&restored_pid);
	read_proc_maps(restored_pid);

    reconstruct_vm_area_list(restored_pid, &vmas);
	PRINT("Aligned %p\n", (void*) aligned);

	uffd = stealUFFD(restored_pid);

#if DEMO

	replaceGlobalWithAnonPage(restored_pid, (void *) aligned);
	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n");
		exit(EXIT_FAILURE);
	}
	else PRINT("Success initialize userfaultfd API\n");
	register_page( uffd, (void *) aligned );
	runMADVISE(restored_pid, (void *) aligned);
	//enable_wp( uffd, (void *) aligned );
#else
	register_and_write_protect_coalesced(uffd, INVALID);
#endif
	
	//Creating pipes 
	if (pipe(client_pipe) == -1 || pipe(uffd_pipe) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}
	//Start UFFD thread
	param.uffd = uffd;               // from stealUFFD()
	//param.server_pipe = server_pipe[0];    // read end for handler
	//param.uffd_pipe = uffd_pipe[1];  // write end for handler
	param.fd_handler[0] = conn.fd_handler;
	//Spawn handler thread
	pthread_create(&uffd_thread, NULL, handler, &param);

#if COMMAND_THREAD
	PRINT("[DSM Client] Connections established. Creating thread for command loop\n");

	args = malloc(sizeof(struct command_thread_args));
	if (!args) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	args->restored_pid = restored_pid;
	args->uffd = uffd;
	args->conn = conn;  // shallow copy is OK here


	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&command_thread, &attr, command_thread_func, args) != 0) {
		perror("pthread_create (command loop)");
		free(args);
		exit(EXIT_FAILURE);
	}

	pthread_attr_destroy(&attr);

	PRINT("[DSM Client] After creating thread. Entering main loop...\n");
    dsm_client_main_loop(conn.fd_command);

#elif COMMAND_LOOP
	PRINT("[DSM Client] Connections established. Entering command loop\n");
	command_loop(restored_pid, uffd, &conn);
#elif ENABLE_SERVER
	PRINT("[DSM Client] Connections established. Entering main loop...\n");
    dsm_client_main_loop(conn.fd_command);
	if(!DBG) send_sigcont(restored_pid);
#endif


	kill_and_exit(restored_pid);

}
