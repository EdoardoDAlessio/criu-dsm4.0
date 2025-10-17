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
unsigned long start_address, end_address;
extern int total_pages;
int restored_pid;
int uffd;
int local_threads;

#include "dsm.h"
#include "dsm_log.h"


struct params {
    int uffd;
    long page_size;
    int client_send_socket;
};
int total_pages;


#include <dirent.h>
int get_local_thread_count(int restored_pid) {
    char path[256];
    int count = 0;
    struct dirent *entry;
    DIR *dir; 
	PRINT("Opening /proc/%d/task", restored_pid);
	snprintf(path, sizeof(path), "/proc/%d/task", restored_pid);
	dir = opendir(path);
    if (!dir) return -1;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            // skip "." and ".."
            if (entry->d_name[0] != '.')
                count++;
        }
    }
    closedir(dir);
    return count - 1;
}

#if 0
int get_total_threads(void) {
    char *env = getenv("TOTAL_THREADS");
    if (!env) {
        fprintf(stderr, "Error: TOTAL_THREADS not set\n");
        return -1; // or some default value
    }

    char *endptr;
    long val = strtol(env, &endptr, 10);
    if (*endptr != '\0' || val <= 0) {
        fprintf(stderr, "Error: TOTAL_THREADS has invalid value '%s'\n", env);
        return -1;
    }

    return (int)val;
}
#endif


#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#if 0

typedef struct barrier_state {
    int total_threads;       // total participants (local + remote)
    int arrived;             // number of threads that have hit the barrier
    void **pending_addrs;    // array of faulting pages to resolve later
    int pending_count;
    pthread_mutex_t lock;
    pthread_cond_t cond;     // signal resolver when all arrived
} barrier_state_t;

barrier_state_t barrier = {0};

void barrier_init(void) {
    barrier.total_threads = total_threads;
    barrier.arrived = 0;
    barrier.pending_addrs = malloc(total_threads * sizeof(void *));
    barrier.pending_count = 0;
    pthread_mutex_init(&barrier.lock, NULL);
    pthread_cond_init(&barrier.cond, NULL);
}


void *barrier_resolver_thread(void *arg) {
		
	//struct timespec ts;
	//ts.tv_sec = 0;
	//ts.tv_nsec = 500000000;  // 0.5 seconds
    while (true) {
        pthread_mutex_lock(&barrier.lock);

        while (barrier.arrived < barrier.total_threads) {
            pthread_cond_wait(&barrier.cond, &barrier.lock);
        }

        // ✅ At this point, all threads are waiting at the barrier
        PRINT("[resolver] All threads arrived. Resolving %d faults.\n",
              barrier.pending_count);

			  
        for (int i = 0; i < barrier.pending_count; i++) {
			disable_wp(uffd, barrier.pending_addrs[i]);
			PRINT("[resolver] Resolved fault at %p\n", barrier.pending_addrs[i]);
        }
		//nanosleep(&ts, NULL);//sleep 0.5s to let threads continue and hit the barrier again
		for (int i = 0; i < barrier.pending_count; i++) {
			enable_wp(uffd, barrier.pending_addrs[i]);
			PRINT("[resolver] Resolved fault at %p\n", barrier.pending_addrs[i]);
        }
		
        // Reset for next barrier round
        barrier.arrived = 0;
        barrier.pending_count = 0;

        pthread_mutex_unlock(&barrier.lock);
    }
    return NULL;
}
#endif



#if 1
static void *handler(void *arg) {
    struct thread_param *p = arg;
    struct uffd_msg msg;
	struct msg_info dsm_msg = {0};
    struct pollfd pollfd[1] = {
        { .fd = p->uffd, .events = POLLIN }
    };
	unsigned long addr;
	unsigned char ack = 0;
	int state = -1; //assume NOT SHARED
	unsigned char page_data[PAGE_SIZE] = {0}; 
	
	struct uffdio_copy copy;
	struct uffdio_range r;
	size_t n;

	(void) n;
	(void) ack;
	(void) dsm_msg;

    DSM_EVENT_HANDLER("[handler] started, uffd = %d\n", p->uffd);

	//sleep(5);
#if !DBG 
send_sigcont(restored_pid);
#endif

    while (1) {
		int index;
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
#if ENABLE_SERVER

			//all local threads arrived, send the message to remote 
			// Send BARRIER HIT
			dsm_msg.msg_type = MSG_BARRIER_HIT;
			dsm_msg.msg_id = 1001;
			dsm_msg.page_addr = msg.arg.pagefault.address;
			if (send_all(p->fd_handler[0 ], &dsm_msg, sizeof(dsm_msg)) != 0) {
				perror("[SERVER] Failed to send MSG_BARRIER_HIT");
				kill_and_exit(restored_pid);
			}else DSM_DEBUG_HANDLER("[SERVER] Sent MSG_BARRIER_HIT to client\n");
			
			//and let's see if remote threads have already arrived
			if (remote_threads_barrier_arrived == 0) {
				pthread_cond_wait(&barrier.cond, &barrier.lock);
			}

			/*Cheking if fault address match*/
			if( remote_barrier_addr != local_barrier_addr ){
				printf("Error!\n");
				//kill_and_exit(restored_pid);
			}

			DSM_DEBUG_HANDLER("[SERVER] remote threads barrier arrived\n");
			//remote threads arrived, resolve fault and exit
			remote_threads_barrier_arrived = 0; //reset for next barrier
			pthread_cond_broadcast(&barrier.cond); //notify the other thread if it was waiting 

#endif


#if 0
			disable_wp(uffd, (void*) msg.arg.pagefault.address);
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE*2;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr );

			pthread_mutex_unlock(&barrier.lock);
			continue;

#else

			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
			disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
			

			pthread_mutex_unlock(&barrier.lock);
			continue;
#endif
		}
		//pthread_mutex_lock(&pagefaults_mutex);

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
		//mark_fault_start(addr, "LOCAL_HANDLER", msg.arg.pagefault.feat.ptid);

		if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
			
            DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n");

			//check if page is tracked and who's the owner

			#if ENABLE_SERVER
			//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
			// to make SERVER issue the drop page to all 
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = addr;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = index;

			if( dsm_msg.msg_id < 0 ){
				fprintf(stderr, "[handler] ERROR: page not found in list for address %lx\n", addr);
				kill_and_exit(restored_pid);
				//pthread_mutex_unlock(&pagefaults_mutex);
				continue;
			}

			// Send invalidate request
			if (send_all(p->fd_handler[0 ], &dsm_msg, sizeof(dsm_msg)) != 0) {
				perror("[SERVER] Failed to send MSG_SEND_INVALIDATE");
				kill_and_exit(restored_pid);
				return NULL;
			}
			DSM_EVENT_HANDLER("[SERVER] Sent MSG_SEND_INVALIDATE to server. With address:0x%lx\n", addr);

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
			#endif

			// Now you can safely disable WP
    		disable_wp(uffd, (void *)addr);
			//update_page_info(addr, 0, MODIFIED, -2);
			PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n", page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
			page_list_data[index].state = MODIFIED;	
			
        } else {
			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p\n", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
				copy.mode = 0; 
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n",
                   			page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;	
			} else {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p\n", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA;
				copy.mode = UFFDIO_COPY_MODE_WP;
				//update_page_info(addr, -1, SHARED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n",
                   			page_list_data[index].saddr, page_list_data[index].state, SHARED, index);
				page_list_data[index].state = SHARED;		
			}

			
			if( 1 || state ){
			//if( ENABLE_SERVER && state != SHARED ){
				state = -1; //reset
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
			}else{ //meaning we are in debug mode without the client
				// Create a zero page for missing fault
				//memset(page_data, 0, PAGE_SIZE);
				copy.src  = (unsigned long)zero_page;
				DSM_EVENT_HANDLER("[handler] Creating zero page for MISSING PAGE FAULT on READ on an ALREADY SHARED PAGE (debug mode)\n");
			}

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
					kill_and_exit(restored_pid);
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
				kill_and_exit(restored_pid);
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
		//mark_fault_end(addr, "LOCAL_HANDLER", msg.arg.pagefault.feat.ptid);
		//pthread_mutex_unlock(&pagefaults_mutex);
    }

    return NULL;
}
#endif


#if ENABLE_SERVER
void dsm_command_main_loop(int fd_command) {
    struct msg_info msg;
    ssize_t n;
	unsigned char ack;
	printf("Page0x:%lx Page1:0x%lx\n", page_thread0, page_thread1);
    while (1) {
        DSM_EVENT_SERVER("[DSM Server] (fd=%d) Waiting for command message...\n", fd_command);

        n = recv(fd_command, &msg, sizeof(msg), 0);
        if (n <= 0) {
            perror("[DSM Server] recv failed or connection closed");
            break;
        } else if (n != sizeof(msg)) {
            fprintf(stderr, "[DSM Server] Incomplete message received (got %zd bytes)\n", n);
            continue;
        }

        DSM_DEBUG_SERVER("[DSM Server] Received message: type=%d, addr=0x%lx, id=%ld\n",
               msg.msg_type, msg.page_addr, msg.msg_id);
		
		//mark_fault_start(msg.page_addr, "REMOTE_FAULT", msg.msg_id);
        switch (msg.msg_type) {
			case MSG_BARRIER_HIT:
                DSM_DEBUG_SERVER("[DSM Server] Remote barrier hit.\n");
				#if 1
				pthread_mutex_lock(&barrier.lock);

				if( remote_threads_barrier_arrived == 1 ){
					//means that the handler thread has not process the barrier yet, let's wait until it does
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_SERVER("[DSM Server] Remote hit barrier, releasing...\n");
				pthread_mutex_unlock(&barrier.lock);
				#endif
				break;
			case MSG_WAKE_THREAD:
				send_sigcont(restored_pid);
				break;
			case MSG_STOP_THREAD:
				send_sigstop(restored_pid);
				break;
			case MSG_GET_PAGE_DATA:
				//pthread_mutex_lock(&pagefaults_mutex);
				DSM_EVENT_SERVER("→ Handling GET_PAGE_DATA\n");
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
				//pthread_mutex_unlock(&pagefaults_mutex);
                break;
            case MSG_GET_PAGE_DATA_INVALID:
				//pthread_mutex_lock(&pagefaults_mutex);
                DSM_EVENT_SERVER("→ Handling GET_PAGE_DATA_INVALID\n");
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
				//pthread_mutex_unlock(&pagefaults_mutex);
                break;
            case MSG_SEND_INVALIDATE:
				DSM_EVENT_SERVER("→ Handling remote invalidation request. Madvise(MADV_DONTNEED) on page at %p\n", (void *)msg.page_addr);
				//pthread_mutex_lock(&pagefaults_mutex);
				if (runMADVISE(restored_pid, (void *)msg.page_addr, 4096)) {
					perror("runMADVISE command loop");
					kill_and_exit(restored_pid);
				} else {
					DSM_EVENT_SERVER("Successfully ran madvise on page at %p\n", (void *)msg.page_addr);

					ack = MSG_INVALIDATE_ACK;
					if (send_all(fd_command, &ack, 1) != 0) {
						perror("send MSG_INVALIDATE_ACK");
						kill_and_exit(restored_pid);
					} else {
						DSM_EVENT_SERVER("[SERVER] Sent MSG_INVALIDATE_ACK to client.\n");
					}
					//update_page_info(msg.page_addr, 1, INVALID, -1);
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n",
                   			msg.page_addr, page_list_data[msg.msg_id].state, INVALID, msg.msg_id);
					page_list_data[msg.msg_id].state = INVALID;		
				}
				//pthread_mutex_unlock(&pagefaults_mutex);
				break;

            case MSG_HANDSHAKE:
                DSM_EVENT_SERVER("[DSM Server] Test handshake message received, ignoring.\n");
                continue;
			
            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
		PRINT("\n");
		//mark_fault_end(msg.page_addr, "REMOTE_FAULT", msg.msg_id);
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
	int bin, i, num_pages;
	struct dsm_connection conn[NUM_THREADS];
	pthread_t uffd_thread; //, barrier_tid;
	struct thread_param param;
	unsigned long base_address;
	size_t page_size;
	
    
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

	FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "r");
    FILE *f2 = fopen("/tmp/ranges.txt", "r");
	char line[256]; 

	(void) line;
	(void) base_address;
	(void) page;
	(void) custom_fd_remote; //avoiding unused variable warning WERROR
	(void) custom_fd_local; //avoiding unused variable warning WERROR
	(void) bin; //avoiding unused variable warning WERROR
	(void) i;

#if 1
	remote_threads_barrier_arrived = 0;
	read_pid(&restored_pid);
	dsm_log_verbosity_check();
	init_zero_page();
	barrier_init();
	//pthread_create(&barrier_tid, NULL, barrier_resolver_thread, NULL);
#endif 

	vm_area_list_init(&vmas); // CRIU macro
	
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		perror("socketpair");
		kill_and_exit(restored_pid);
	}

	custom_fd_local = fds[0];   // for server-side use
	custom_fd_remote = fds[1];  // to be sent into parasite

#if ENABLE_SERVER
	for( i = 0; i < NUM_THREADS; i++ ){
		if (dsm_setup_dual_connections(&conn[i]) < 0) {
				fprintf(stderr, "Failed to set up DSM connections\n");
				kill_and_exit(restored_pid);
		}
		param.fd_handler[i] = conn[i].fd_handler; //give the thread's fault handler the connection to all clients

		//PRINT("Checking connection as RECEIVER on COMMAND\n");
		//perform_struct_handshake(conn[i].fd_handler, conn[i].fd_command, false);
		//PRINT("Checking connection as SENDEE on COMMAND\n");
		//perform_struct_handshake(conn[i].fd_command, conn[i].fd_command, true);
	}
#endif 

	local_threads = get_local_thread_count(restored_pid);
	PRINT("local threads:%d\n", local_threads );

	//Start infection
	uffd = 0;
	uffd = stealUFFD(restored_pid);

	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n");
		exit(EXIT_FAILURE);
	}
	else PRINT("Success initialize userfaultfd API\n");


#if VMA_REC	
	read_proc_maps(restored_pid);
#endif	


#if 0 //!EP
	base_address = get_base_address(restored_pid);
	register_all(uffd, restored_pid, base_address, &vmas, SHARED);

#endif

/*
	printf("Registering manually the pages\n");
	register_page(uffd, (void *)0x7f957fa7b000);
	enable_wp(uffd, (void *)0x7f957fa7b000);
	register_page(uffd, (void *)0x7f957fa7c000);
	enable_wp(uffd, (void *)0x7f957fa7c000);
	register_page(uffd, (void *)0x7f957f70d000);
	enable_wp(uffd, (void *)0x7f957f70d000);
	register_page(uffd, (void *)0x7f957f70e000);
	enable_wp(uffd, (void *)0x7f957f70e000);*/
	
	//Registering DSM pages
	//barrier_start_address = register_special_pages(); old way to barrier threads

	
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
		fprintf(stderr, "[dsm] barrier info file not found, no pthread barrier support\n");	
	}
   

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
	//pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

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
	printf("PAge0x:%lx Page1:0x%lx\n", page_thread0, page_thread1);
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
