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

// Setup global variable address 
extern unsigned long global_addr;
extern unsigned long aligned;
unsigned long start_address, end_address;
extern int total_pages;
int restored_pid;
int uffd;
int total_threads = 2; //total threads (local + remote)
int local_threads;
//Special PTHREAD traps DSM 

#include "dsm.h"
#include "dsm_log.h"


#include <pthread.h>
#include <stdbool.h>
#include <time.h>


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
	int index;
	struct uffdio_range r;
	size_t n;
	(void) n;
    DSM_EVENT_HANDLER("[handler] started, uffd = %d\n", p->uffd);

	//sleep(5);
	//dsm_msg.msg_type = MSG_WAKE_THREAD;
	//send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0);
	//printf("[CLIENT] Sent MSG_WAKE_THREAD to server.\n");
#if !DBG 
send_sigcont(restored_pid);
#endif
    while (1) {
        int pollres = poll(pollfd, 1, -1);
        if (pollres == -1) {
            perror("poll/userfaultfd");
            continue;
        }

        if (!(pollfd[0].revents & POLLIN)) continue;

        if (all_read(p->uffd, &msg, sizeof(msg)) != 0) {
            perror("read/userfaultfd");
            continue;
        }

         if (!(msg.event & UFFD_EVENT_PAGEFAULT)) continue;

        addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
        DSM_DEBUG_HANDLER("[handler] page fault at 0x%llx, (flags: %llx), thread:%d\n", msg.arg.pagefault.address, msg.arg.pagefault.flags, msg.arg.pagefault.feat.ptid);

		if( msg.arg.pagefault.address >= barrier_start_address && msg.arg.pagefault.address < barrier_end_address){
			
			pthread_mutex_lock(&barrier.lock);

			DSM_EVENT_HANDLER("[barrier] Local barrier hit: tid=%d page=%p", msg.arg.pagefault.feat.ptid, (void*)msg.arg.pagefault.address);
			local_barrier_addr = msg.arg.pagefault.address;
			//all local threads arrived, send the message to remote 
			// Send BARRIER HIT
			dsm_msg.msg_type = MSG_BARRIER_HIT;
			dsm_msg.msg_id = 1001;
			dsm_msg.page_addr = msg.arg.pagefault.address;
			if (send_all(p->fd_handler[0 ], &dsm_msg, sizeof(dsm_msg)) != 0) {
				perror("[CLIENT] Failed to send MSG_BARRIER_HIT");
				kill_and_exit(restored_pid);
			}else DSM_DEBUG_HANDLER("[CLIENT] Sent MSG_BARRIER_HIT to server\n");
			
			//and let's see if remote threads have already arrived
			if (remote_threads_barrier_arrived == 0) {
				pthread_cond_wait(&barrier.cond, &barrier.lock);
			}

			/*Cheking if fault address match*/
			if( remote_barrier_addr != local_barrier_addr ){
				printf("Error!\n");
				//kill_and_exit(restored_pid);
			}

			DSM_DEBUG_HANDLER("[CLIENT] remote threads barrier arrived\n");
			//remote threads arrived, resolve fault and exit
			remote_threads_barrier_arrived = 0; //reset for next barrier
			pthread_cond_broadcast(&barrier.cond);
#if 0
			disable_wp(uffd, (void*) msg.arg.pagefault.address);
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE*2;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr );
#else
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
			disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
			
#endif
			pthread_mutex_unlock(&barrier.lock);
			continue;
		}

		//pthread_mutex_lock(&pagefaults_mutex);

		//Getting index in page list data
		index = -1;
		for (int i=0; i < total_pages; i++) {
			unsigned long start = page_list_data[i].saddr;
			if (addr == start ) {
				index = i;
				break;
			}
		}
		if(index == -1 ) {
			PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n", addr);
			continue;
		}

        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
            DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n");
			//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
			// to make SERVER issue the drop page to all 
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = addr; 
			dsm_msg.page_size = 4096;

			dsm_msg.msg_id = get_list_page_index(addr);
			if( dsm_msg.msg_id < 0 ){
				fprintf(stderr, "[handler] ERROR: page not found in list for address %lx\n", addr);
				exit(-1);
				//pthread_mutex_unlock(&pagefaults_mutex);
				continue;
			}
			

			// Send invalidate request
			if (send_all(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg)) != 0) {
				perror("[CLIENT] Failed to send MSG_SEND_INVALIDATE");
				return NULL;
			}
			DSM_EVENT_HANDLER("[CLIENT] Sent MSG_SEND_INVALIDATE to server. With address:0x%lx\n", addr);

			switch ( all_read(p->fd_handler[0], &ack, 1) ) {
				case -2:
					fprintf(stderr, "[SERVER] Connection closed before ACK\n");
					kill_and_exit(restored_pid);
					break;
				case -1:
					perror("[SERVER] all_read(ACK) failed");
					kill_and_exit(restored_pid);
					break;
				case 0: 
					DSM_EVENT_HANDLER("[SERVER] Received MSG_INVALIDATE_ACK on INVALIDATION\n");
					break;
				default:
					perror("Unknown value for handler all_read(ACK)\n");
					kill_and_exit(restored_pid);
					break;
			}

			// Now you can safely disable WP
    		disable_wp(uffd, (void *)addr);
			//update_page_info(addr, 0, MODIFIED, -2);
			PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n", addr, page_list_data[index].state, MODIFIED, index);
			page_list_data[index].state = MODIFIED;	
     	} else {
			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p\n", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
				copy.mode = 0; 
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n", addr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;
			} else {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p\n", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA;
				copy.mode = UFFDIO_COPY_MODE_WP;
				//update_page_info(addr, -1, SHARED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n", addr, page_list_data[index].state, SHARED, index);
				page_list_data[index].state = SHARED;
			}

#if ENABLE_SERVER
			//if( ENABLE_SERVER ){
				dsm_msg.page_addr = addr;
				dsm_msg.page_size = PAGE_SIZE;
				dsm_msg.msg_id = index;
				if( dsm_msg.msg_id < 0 ){
					fprintf(stderr, "[handler] ERROR: page not found in list for address %lx\n", addr);
					kill_and_exit(restored_pid);
					//pthread_mutex_unlock(&pagefaults_mutex);
					continue;
				}

				if (send_get_page(dsm_msg, p->fd_handler[0 ], page_data) != 0) {
					fprintf(stderr, "[handler] Failed to fetch page from remote\n");
					kill_and_exit(restored_pid);
					continue;
				}
				copy.src  = (unsigned long)page_data;
#else
			//}else{ //meaning we are in debug mode without the client
				// Create a zero page for missing fault
				//memset(page_data, 0, PAGE_SIZE);
				copy.src  = (unsigned long)zero_page;
				DSM_EVENT_HANDLER("[handler] Creating zero page for MISSING PAGE FAULT on READ on an ALREADY SHARED PAGE (debug mode)\n");
			//}
#endif
			// dst & len already set:
			copy.dst = addr;
			copy.len = PAGE_SIZE;        // or your chunk size
			// copy.mode = UFFDIO_COPY_MODE_WP;   // if you want WP after copy

			if (ioctl(p->uffd, UFFDIO_COPY, &copy) == -1) {
				// Kernel-level failure (not the EEXIST race, that shows up in copy.copy)
				int e = errno;
				if (e == EEXIST) {
					// Some kernels may surface EEXIST via errno (rare). Wake and continue.
					r.start = addr;
                    r.len = PAGE_SIZE;
					(void)ioctl(p->uffd, UFFDIO_WAKE, &r);
					DSM_DEBUG_HANDLER("[handler] UFFDIO_COPY errno==EEXIST on %p → woke waiters", (void*)addr);
					continue;
				}
				perror("[handler] UFFDIO_COPY ioctl failed");
				kill_and_exit(restored_pid);
			}

			/*
			* On success, copy.copy is either:
			*   + PAGE_SIZE             → full copy, normal case
			*   + -EEXIST               → another thread already resolved; just wake & continue
			*   + < 0 (other -errno)    → semantic error; decide policy
			*   + otherwise             → short copy (unexpected)
			*/
			if (copy.copy == PAGE_SIZE) {
				// normal — optional wake to release any co-waiters
				r.start = addr;
                r.len = PAGE_SIZE;
				if (ioctl(p->uffd, UFFDIO_WAKE, &r) == -1) {
					perror("[handler] UFFDIO_WAKE failed after copy");
					kill_and_exit(restored_pid);
				}
				DSM_EVENT_HANDLER("[handler] Page copied back to missing region\n");
			} else if (copy.copy == -EEXIST) {
				// Raced with another handler that already copied this page
				r.start = addr;
            	r.len = PAGE_SIZE;
				(void)ioctl(p->uffd, UFFDIO_WAKE, &r);  // harmless if none waiting
				DSM_DEBUG_HANDLER("[handler] EEXIST on %p → woke waiters and skipped duplicate copy", (void*)addr);
				continue;
			} else if (copy.copy < 0) {
				int e = -(int)copy.copy;
				// You can decide to log & continue, or treat as fatal
				fprintf(stderr, "[handler] UFFDIO_COPY semantic error %s (%d) on %lx\n",
						strerror(e), e, addr);
				// Optional: wake anyone waiting so they don’t hang
				r.start = addr;
                r.len = PAGE_SIZE;
				(void)ioctl(p->uffd, UFFDIO_WAKE, &r);
				kill_and_exit(restored_pid);
			} else {
				// Short copy – shouldn’t happen for anonymous pages
				fprintf(stderr, "[handler] UFFDIO_COPY short copy (%lld bytes) on %lx\n",
						(long long)copy.copy, addr);
				kill_and_exit(restored_pid);
			}
		}
		DSM_EVENT_HANDLER("[handler] done handling fault at 0x%lx\n", addr);

		//pthread_mutex_unlock(&pagefaults_mutex);
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
size_t page_size = 0;
int num_pages = 0;

void dsm_client_main_loop(int fd_command) {
    struct msg_info msg;
    ssize_t n;
	unsigned char ack;

    while (1) {
        DSM_EVENT_CLIENT("[DSM Client] (fd=%d) Waiting for command message...\n", fd_command);

        n = recv(fd_command, &msg, sizeof(msg), 0);
        if (n <= 0) {
            perror("[DSM Client] recv failed or connection closed");
            break;
        } else if (n != sizeof(msg)) {
            fprintf(stderr, "[DSM Client] Incomplete message received (got %zd bytes)\n", n);
            continue;
        }

        DSM_DEBUG_CLIENT("[DSM Client] Received message: type=%d, addr=0x%lx, id=%ld\n",
               msg.msg_type, msg.page_addr, msg.msg_id);

        switch (msg.msg_type) {
			case MSG_BARRIER_HIT:
                DSM_DEBUG_CLIENT("[DSM Client] Remote barrier hit.\n");
				#if 1
				pthread_mutex_lock(&barrier.lock);
				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_CLIENT("[DSM Client] Remote hit barrier, releasing...\n");
				pthread_mutex_unlock(&barrier.lock);
				#endif
				break;
			case MSG_BARRIER_RELEASE:
				DSM_DEBUG_CLIENT("[DSM Client] Remote barrier released.\n");
				pthread_mutex_lock(&barrier.lock);
				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				if( remote_threads_barrier_arrived ){
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_CLIENT("[DSM Client] Remote hit barrier, releasing...\n");
				pthread_mutex_unlock(&barrier.lock);
				break;
			case MSG_WAKE_THREAD:
				send_sigcont(restored_pid);
				break;
			case MSG_STOP_THREAD:
				send_sigstop(restored_pid);
				break;
			case MSG_GET_PAGE_DATA:
				//pthread_mutex_lock(&pagefaults_mutex);
				DSM_EVENT_CLIENT("→ Handling GET_PAGE_DATA\n");
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
				//pthread_mutex_unlock(&pagefaults_mutex);
                break;
            case MSG_GET_PAGE_DATA_INVALID:
				//pthread_mutex_lock(&pagefaults_mutex);
                DSM_EVENT_CLIENT("→ Handling GET_PAGE_DATA_INVALID\n");
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
				//pthread_mutex_unlock(&pagefaults_mutex);
                break;
            case MSG_SEND_INVALIDATE:
				//pthread_mutex_lock(&pagefaults_mutex);
				DSM_EVENT_CLIENT("→ Handling remote invalidation request. Madvise(MADV_DONTNEED) on page at %p\n", (void *)msg.page_addr);

				if (runMADVISE(restored_pid, (void *)msg.page_addr, 4096)) {
					perror("runMADVISE command loop");
					kill_and_exit(restored_pid);
				} else {
					DSM_EVENT_CLIENT("Successfully ran madvise on page at %p\n", (void *)msg.page_addr);

					ack = MSG_INVALIDATE_ACK;
					if (send_all(fd_command, &ack, 1) != 0) {
						perror("send MSG_INVALIDATE_ACK");
						kill_and_exit(restored_pid);
					} else {
						DSM_EVENT_CLIENT("[SERVER] Sent MSG_INVALIDATE_ACK to client.\n");
					}
					update_page_info(msg.page_addr, 1, INVALID, -1);
				}
				//pthread_mutex_unlock(&pagefaults_mutex);
				break;

            case MSG_HANDSHAKE:
                DSM_EVENT_CLIENT("[DSM Client] Test handshake message received, ignoring.\n");
                continue;
			
            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
		PRINT("\n");
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
	FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "r");
	#if DEMO
	unsigned long base_address;
	#endif

	#if COMMAND_THREAD
		pthread_attr_t attr;
		pthread_t command_thread;
		struct command_thread_args* args;
	#endif
	
	FILE *f2 = fopen("/tmp/ranges.txt", "r");
	char line[256]; 
	
	(void) line;
	(void) base_address;

#if 1
	remote_threads_barrier_arrived = 0;
	read_pid(&restored_pid);
	dsm_log_verbosity_check();
	init_zero_page();
	barrier_init();
	//pthread_create(&barrier_tid, NULL, barrier_resolver_thread, NULL);
#endif 

	vm_area_list_init(&vmas); // CRIU macro

	if (dsm_client_dual_connect(&conn, server_ip) < 0) {
		fprintf(stderr, "DSM client connection failed\n");
		kill_and_exit(restored_pid);
	}


	/*PRINT("Checking connection as SENDER on HANDLER\n");
	perform_struct_handshake(conn.fd_handler, conn.fd_handler, true);
	PRINT("Checking connection as RECEIVER on HANDLER\n");
	perform_struct_handshake(conn.fd_handler, conn.fd_handler, false);*/


	

	//Start infection
	uffd = stealUFFD(restored_pid);

	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n");
		kill_and_exit(restored_pid);
	}
	else PRINT("Success initialize userfaultfd API\n");


	read_proc_maps(restored_pid);
#if 0 //!EP
	base_address = get_base_address(restored_pid);
	register_all(uffd, restored_pid, base_address, &vmas, INVALID);

#endif

	if( f2 ){

		while (fgets(line, sizeof(line), f2)) {
			if (sscanf(line, "base=%lx page_size=%zu num_pages=%d", &start_address, &page_size, &num_pages) != 3) {
				fprintf(stderr, "[dsm] failed to parse line: %s", line);
				continue; // skip malformed line
			}

			for( int i=0; i< num_pages; i++ ){
				unsigned long aux = start_address + i*page_size;
				PRINT("Registering page %d at address %lx\n", i, aux);
				page_list_data[total_pages].saddr = aux;
				page_list_data[total_pages].owner = -1;
				page_list_data[total_pages].state = SHARED;
				//register_page(uffd, (void*)aux);
				//enable_wp(uffd, (void*)aux);
				total_pages++;
			}

			end_address = start_address + page_size * num_pages;
			PRINT("/tmp/ranges.txt: start addr:%lx, end:%lx\n", start_address, end_address);

			register_region_with_uffd(uffd, (void*)start_address, page_size * num_pages);
			enable_region_wp(uffd, (void*)start_address, page_size * num_pages);
		}

		fclose(f2);
	}else{
		fprintf(stderr, "[dsm] /tmp/ranges.txt not found \n");	
	}

	if( f ){
		if (fscanf(f, "base=%lx page_size=%zu num_pages=%d", &barrier_start_address, &page_size, &num_pages) != 3) {
			fprintf(stderr, "[dsm] failed to parse barrier info file\n");
		}
		fclose(f);

		
		barrier_end_address = barrier_start_address + page_size * num_pages;
		PRINT("/tmp/dsm_barrier_pages.txt: start addr:%lx, end:%lx\n", barrier_start_address, barrier_end_address);

		register_region_with_uffd(uffd, (void*) barrier_start_address, page_size * num_pages);
		enable_region_wp(uffd, (void*) barrier_start_address, page_size * num_pages);
	}else{
		fprintf(stderr, "[dsm] /tmp/dsm_barrier_pages.txt not found, no pthread barrier support\n");	
	}

	
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
#elif ENABLE_CLIENT
	PRINT("[DSM Client] Connections established. Entering main loop...\n");
    dsm_client_main_loop(conn.fd_command);
	if(!DBG) send_sigcont(restored_pid);
#endif

	PRINT("Killing and exiting\n");
	kill_and_exit(restored_pid);

}
