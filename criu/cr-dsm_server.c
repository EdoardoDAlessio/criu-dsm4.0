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

#include <infiniband/verbs.h>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

#define err_and_ret(msg) do { PRINT( msg);  return -1; } while (0)
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
//#include "user.h"

//#include "parsemap.h"

//INFECTION
#include "pie/parasite-blob.h"
#include "parasite-syscall.h"
#include "parasite.h"

//#define PAGE_SIZE 4096
#include "page.h" //this takes the page size

int check_halt_file(void){
    //while(!= 0) spin wait for haltcode file
    return access("/tmp/haltcode", F_OK) ;
}

// Setup global variable address 
extern unsigned long global_addr;
extern unsigned long aligned;

#include "dsm.h"
#include "dsm_log.h"

typedef struct  {
    int restored_pid;
	int client_id;
    int uffd;
    struct dsm_connection *conn;
}command_thread_args;

int num_clients = 0;
unsigned long *active_addr;
pthread_cond_t *fault_cond;
pthread_mutex_t *handler_locks;

void print_owner_mask(uint64_t mask)
{
    PRINT("owner_mask = 0b");
    for (int i = num_clients; i >= 0; i--) {
        PRINT("%d", (int)((mask >> i) & 1));
    }
    PRINT("\n");
}


int check_barrier( unsigned long addr ){
	pthread_mutex_lock(&fault_lock);
	
	for (int i = 0; i <= num_clients; i++) {
		if (active_addr[i] != addr) {
			return i;
		}
	}
	return -1;

}

void fault_start(unsigned long addr, const char *who, int tid)
{
	int conflict;
    pthread_mutex_lock(&fault_lock);
	fault_counter++;

    // Wait if another thread is already handling the same page
    conflict = 1;
    while (conflict) {
        conflict = 0;
        for (int i = 0; i <= num_clients; i++) {
            if (i == tid) continue;
            if (active_addr[i] == addr) {
                PRINT(
                    "⚠️  [%s:t%d] waiting, page %lx handled by t%d\n",
                    who, tid, addr, i);
                pthread_cond_wait(&fault_cond[i], &fault_lock);
                conflict = 1;  // check again after wakeup
                break;
            }
        }
    }

    // No conflict: mark myself as active
    active_addr[tid] = addr;
    PRINT( "🟢 [%s:t%d] started page %lx\n", who, tid, addr);

    pthread_mutex_unlock(&fault_lock);
}

void fault_end(unsigned long addr, const char *who, int tid)
{
    pthread_mutex_lock(&fault_lock);

    if (active_addr[tid] == addr) {
        active_addr[tid] = 0;
        PRINT( "✅ [%s:t%d] finished page %lx\n", who, tid, addr);

        // Wake up everyone who might be waiting on me
        pthread_cond_broadcast(&fault_cond[tid]);
    }

    pthread_mutex_unlock(&fault_lock);
}

void dump_fault_status(void) {
    pthread_mutex_lock(&fault_lock);
    for (int i = 0; i <= num_clients; i++) {
        if (active_addr[i])
            PRINT( "[STATUS] t%d → page %lx\n", i, active_addr[i]);
    }
    pthread_mutex_unlock(&fault_lock);
}


// shared barrier state per node

//static int arrived_count = 0; 


struct params {
    int uffd;
    long page_size;
    int client_send_socket;
};

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
        PRINT("[resolver] All threads arrived. Resolving %d faults.\n\r",
              barrier.pending_count);

			  
        for (int i = 0; i < barrier.pending_count; i++) {
			disable_wp(uffd, barrier.pending_addrs[i]);
			PRINT("[resolver] Resolved fault at %p\n\r", barrier.pending_addrs[i]);
        }
		//nanosleep(&ts, NULL);//sleep 0.5s to let threads continue and hit the barrier again
		for (int i = 0; i < barrier.pending_count; i++) {
			enable_wp(uffd, barrier.pending_addrs[i]);
			PRINT("[resolver] Resolved fault at %p\n\r", barrier.pending_addrs[i]);
        }
		
        // Reset for next barrier round
        barrier.arrived = 0;
        barrier.pending_count = 0;

        pthread_mutex_unlock(&barrier.lock);
    }
    return NULL;
}
#endif

//pthread_barrier_t local_barrier;
pthread_mutex_t local_barrier = PTHREAD_MUTEX_INITIALIZER;
int local_barrier_count = 0;

#if RDMA_ENABLE

static void *handler_RDMA(void *arg) {
	struct thread_param *p = arg;
	struct uffd_msg msg;
	struct msg_info dsm_msg = {0};
	struct pollfd pollfd[1] = {
		{ .fd = p->uffd, .events = POLLIN }
	};
	unsigned long addr;
	unsigned char ack = 0;
	//unsigned char page_data[PAGE_SIZE] = {0}; 
	
	struct uffdio_copy copy;
	struct uffdio_range r;
	size_t n;
	struct ibv_wc wc;
	rdma_cmd_msg cmd; /* temporary on stack, but we will copy it into MR */
	uint64_t my_handler_addr;
	int owner_id;

	(void) n;
	(void) ack;
	(void) dsm_msg;

	DSM_EVENT_HANDLER("[handler] started, uffd = %d\n\r", p->uffd);

	
#if !DBG 
	//sleep(5);
	DSM_EVENT_HANDLER("[handler] Sending SIGCONT to restored process %d\n\r", restored_pid);
	send_sigcont(restored_pid);

	
	//dsm_msg.msg_type = MSG_WAKE_THREAD;
	//send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0);
	//DSM_EVENT_HANDLER("[SERVER] Sent MSG_WAKE_THREAD to server.\n\r");
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
		DSM_DEBUG_HANDLER("[handler] page fault at 0x%llx, (flags: %llx), thread:%d\n\r", msg.arg.pagefault.address, msg.arg.pagefault.flags, msg.arg.pagefault.feat.ptid);

		if( msg.arg.pagefault.address >= barrier_start_address && msg.arg.pagefault.address < barrier_end_address){
			
			pthread_mutex_lock(&barrier.lock);

			DSM_EVENT_HANDLER("[barrier] Local barrier hit: tid=%d page=%p", msg.arg.pagefault.feat.ptid, (void*)msg.arg.pagefault.address);
			local_barrier_addr = msg.arg.pagefault.address;
			if ( num_clients ) {
				//all local threads arrived, send the message to remotes
				//RDMA BARRIER HIT
				cmd.faulting_addr  = htobe64((uint64_t)addr);
				cmd.id           = htonl(MSG_BARRIER_HIT);
				//and let's see if remote threads have already arrived
				if (remote_threads_barrier_arrived < num_clients ) {
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				DSM_DEBUG_HANDLER("[SERVER] all threads barrier arrived\n\r");
				// Send BARRIER HIT
				dsm_msg.msg_type = MSG_BARRIER_HIT;
				for( int i=0; i<num_clients; i++ ){
					pthread_mutex_lock(&handler_locks[i]);
					PRINT("handler locked fd_handler of client:%d\n", i);
					/* 3) Copy CMD into TX buffer (handler_data MR) */
					memcpy(endpoints[i].handler_data.base_addr, &cmd, sizeof(cmd));

					//Prepare for response 
					post_one_recv(&endpoints[i].handler);

					/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
					DSM_EVENT_HANDLER("[SERVER] Sending RELEASE BARRIER to client.receiver %d (imm=0xCAFE)\n\r", i);
					rdma_write_core(&endpoints[i].handler_data,
									be64toh(endpoints[i].remote_all.receiver.vaddr),
									ntohl(endpoints[i].remote_all.receiver.rkey),
									endpoints[i].handler_data.base_addr, sizeof(cmd), 0xCAFE);

					/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
					for (;;) {
						if (ibv_poll_cq(endpoints[i].handler.cq, 1, &wc) > 0) {
							if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
								if (wc.wc_flags & IBV_WC_WITH_IMM)
									DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
								break;
							}
						}
					}

					pthread_mutex_unlock(&handler_locks[i]);
					PRINT("handler unlocked fd_handler of client:%d\n", i);
				}

				//remote threads arrived, resolve fault and exit
				remote_threads_barrier_arrived = 0; //reset for next barrier
				pthread_cond_broadcast(&barrier.cond); //notify the other thread if it was waiting 
			}
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
			disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
			pthread_mutex_unlock(&barrier.lock);
			continue;
		}
		

		index = -1;
		for (int i=0; i < total_pages; i++) {
			unsigned long start = page_list_data[i].saddr;
			if (addr == start ) {
				index = i;
				break;
			}
		}
		if(index == -1 ) {
			PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n\r", addr);
			kill_and_exit(restored_pid);
			// continue;
		}
		fault_start(addr, "LOCAL_HANDLER", num_clients );
		print_owner_mask(page_list_data[index].owner_mask);
			
		if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
			DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n\r");
			//check if page is tracked and who's the owner
			if( num_clients ){
				//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
				// to make SERVER issue the drop page to all 
				dsm_msg.msg_id = index;

				/* 2) Build command asking server to write into OUR handler */
				my_handler_addr   = (uint64_t)(uintptr_t)endpoints[0].handler.base_addr;
				cmd.target_addr   = htobe64(my_handler_addr);
				cmd.faulting_addr  = htobe64((uint64_t)addr);
				cmd.id           = htonl(MSG_SEND_INVALIDATE);
				cmd.index = htonl(index);
				

				owner_id = -1;
				for (int i = 1; i <= num_clients; i++) {
					if (page_list_data[index].owner_mask & (1ULL << i)) {
						owner_id = i - 1;
						pthread_mutex_lock(&handler_locks[owner_id]);
						PRINT("handler locked fd_handler of client:%d\n", owner_id);
						dsm_outgoing[MSG_SEND_INVALIDATE]++;
						// Send invalidate request
						DSM_EVENT_HANDLER("[SERVER] Sending rdma MSG_SEND_INVALIDATE : target_addr=%#llx faulting_addr=%#llx id=%u index:%d client:%d\n\r",
							(unsigned long long)be64toh(cmd.target_addr),
							(unsigned long long)be64toh(cmd.faulting_addr),
							(unsigned)ntohl(cmd.id),
							(unsigned)ntohl(cmd.index), 
							owner_id);

						/* 3) Copy CMD into TX buffer (handler_data MR) */
						memcpy(endpoints[owner_id].handler_data.base_addr, &cmd, sizeof(cmd));

						//Prepare for response 
						post_one_recv(&endpoints[owner_id].handler);

						/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
						DSM_EVENT_HANDLER("[SERVER] Sending MSG_SEND_INVALIDATE to client.receiver (imm=0xCAFE)\n\r");
						rdma_write_core(&endpoints[owner_id].handler_data,
										be64toh(endpoints[owner_id].remote_all.receiver.vaddr),
										ntohl(endpoints[owner_id].remote_all.receiver.rkey),
										endpoints[owner_id].handler_data.base_addr, sizeof(cmd), 0xCAFE);

						/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
						for (;;) {
							if (ibv_poll_cq(endpoints[owner_id].handler.cq, 1, &wc) > 0) {
								if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
									if (wc.wc_flags & IBV_WC_WITH_IMM)
										DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
									break;
								}
							}
						}

						pthread_mutex_unlock(&handler_locks[owner_id]);	
						PRINT("handler unlocked fd_handler of client:%d\n", owner_id);
					}
				}
			}
			// Now you can safely disable WP
			disable_wp(uffd, (void *)addr);
			//update_page_info(addr, 0, MODIFIED, -2);
			PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
			page_list_data[index].state = MODIFIED;	
			page_list_data[index].owner_mask = (1ULL << 0); //server exclusive owner
			
		} else if ( !(page_list_data[index].owner_mask & (1ULL << 0)) ){ //if server owns it, it means that some one requested it 

			//find owner
			// 2. find which client currently owns it
			owner_id = -1;
			for (int i = 1; i <= num_clients; i++) {
				if (page_list_data[index].owner_mask & (1ULL << i)) {
					owner_id = i - 1; // convert bit to client index
					break;
				}
			}


			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p, owner_id:%d\n\r", (void*)msg.arg.pagefault.address, owner_id);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
				copy.mode = 0; 
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
							page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;	
				page_list_data[index].owner_mask = (1ULL << 0); //server exclusive owner
			} else {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p, owner_id:%d\n\r", (void*)msg.arg.pagefault.address, owner_id);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA;
				copy.mode = UFFDIO_COPY_MODE_WP;
				//update_page_info(addr, -1, SHARED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
							page_list_data[index].saddr, page_list_data[index].state, SHARED, index);
				page_list_data[index].state = SHARED;		
				page_list_data[index].owner_mask |= (1ULL << 0); //add server to current owners
			}

						
			if( num_clients ){
				// 3. If a client owns it, request the page from them
				if (owner_id >= 0) {
					
					//let's take fd_handler mutex
					pthread_mutex_lock(&handler_locks[owner_id]);						
					PRINT("handler locked RDMA of client:%d\n", owner_id);

					/* 2 Build command asking server to write into OUR handler */
					my_handler_addr   = (uint64_t)(uintptr_t)endpoints[owner_id].handler.base_addr;
					cmd.target_addr   = htobe64(my_handler_addr);
					cmd.faulting_addr  = htobe64((uint64_t)addr);
					cmd.id           = htonl(dsm_msg.msg_type);
					cmd.index = htonl(index);

					DSM_EVENT_HANDLER("[SERVER] Sending rdma : target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
						(unsigned long long)be64toh(cmd.target_addr),
						(unsigned long long)be64toh(cmd.faulting_addr),
						(unsigned)ntohl(cmd.id),
						(unsigned)ntohl(cmd.index));

					/* 3) Copy CMD into TX buffer (handler_data MR) */
					memcpy(endpoints[owner_id].handler_data.base_addr, &cmd, sizeof(cmd));

					//Prepare for response 
					post_one_recv(&endpoints[owner_id].handler);

					/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
					DSM_EVENT_HANDLER("[SERVER] Sending CMD to client.receiver (imm=0xCAFE)\n\r");
					rdma_write_core(&endpoints[owner_id].handler_data,
									be64toh(endpoints[owner_id].remote_all.receiver.vaddr),
									ntohl(endpoints[owner_id].remote_all.receiver.rkey),
									endpoints[owner_id].handler_data.base_addr, sizeof(cmd), 0xCAFE);

					/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
					for (;;) {
						if (ibv_poll_cq(endpoints[owner_id].handler.cq, 1, &wc) > 0) {
							if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
								if (wc.wc_flags & IBV_WC_WITH_IMM )
									DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
								else{
									PRINT( "[SERVER] endpoints[owner_id].handler != MSG_GET_PAGE/GET_PAGE_INVALIDATE:%d\n\r", MSG_INVALIDATE_ACK);
									kill_and_exit(restored_pid);
								}
								break;
							}
						}
					}


					
					pthread_mutex_unlock(&handler_locks[owner_id]);
					PRINT("handler unlocked RDMA of client:%d\n", owner_id);

				}else{
					DSM_EVENT_HANDLER("[handler] Page %d has no valid owner, bug\n\r", addr);
					kill_and_exit(restored_pid);
				}
				copy.src  = (unsigned long)endpoints[owner_id].handler.base_addr;
			}
			else{
				copy.src  = (unsigned long)zero_page;
				DSM_EVENT_HANDLER("[handler] Creating zero page for MISSING PAGE FAULT on READ on an ALREADY SHARED PAGE (debug mode)\n\r");
			}
			// dst & len already set:
			copy.dst = addr;
			copy.len = PAGE_SIZE;      

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
				DSM_EVENT_HANDLER("[handler] Page copied back to missing region\n\r");
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
				PRINT( "[handler] UFFDIO_COPY semantic error %s (%d) on %lx\n\r",
						strerror(e), e, addr);
				// Optional: wake anyone waiting so they don’t hang
				r.start = addr;
				r.len = PAGE_SIZE;
				(void)ioctl(p->uffd, UFFDIO_WAKE, &r);
				kill_and_exit(restored_pid);
			} else {
				// Short copy – shouldn’t happen for anonymous pages
				PRINT( "[handler] UFFDIO_COPY short copy (%lld bytes) on %lx\n\r",
						(long long)copy.copy, addr);
				kill_and_exit(restored_pid);
			}
		}
		DSM_EVENT_HANDLER("[handler] done handling fault at 0x%lx\n\r", addr);
		fault_end(addr, "LOCAL_HANDLER", num_clients);
		print_owner_mask(page_list_data[dsm_msg.msg_id].owner_mask);
	}

	return NULL;
}
#endif
static void *handler(void *arg) {
	struct thread_param *p = arg;
	struct uffd_msg msg;
	struct msg_info dsm_msg = {0};
	struct pollfd pollfd[1] = {
		{ .fd = p->uffd, .events = POLLIN }
	};
	unsigned long addr;
	unsigned char ack = 0;
	unsigned char page_data[PAGE_SIZE] = {0}; 
	
	struct uffdio_copy copy;
	struct uffdio_range r;
	int owner_id;
	size_t n;
	//int e;
	//uintptr_t next;
	(void) n;
	(void) ack;
	(void) dsm_msg;

	DSM_EVENT_HANDLER("[handler] started, uffd = %d, DBG:%d\n\r", p->uffd, DBG);

#if !DBG //&& 0
	//sleep(8);
	DSM_EVENT_HANDLER("[handler] Sending SIGCONT to restored process %d\n\r", restored_pid);
	start_time = time_now_us();
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
		DSM_DEBUG_HANDLER("[handler] page fault at 0x%llx, (flags: %llx), thread:%d\n\r", msg.arg.pagefault.address, msg.arg.pagefault.flags, msg.arg.pagefault.feat.ptid);

		if( msg.arg.pagefault.address >= barrier_start_address && msg.arg.pagefault.address < barrier_end_address){
			
			pthread_mutex_lock(&barrier.lock);

			DSM_EVENT_HANDLER("[barrier] Local barrier hit: tid=%d page=%p", msg.arg.pagefault.feat.ptid, (void*)msg.arg.pagefault.address);
			local_barrier_addr = msg.arg.pagefault.address;
			if( num_clients ){
				//all local threads arrived, send the message to remote 			
				//and let's see if remote threads have already arrived
				if (remote_threads_barrier_arrived < num_clients ) {
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				DSM_DEBUG_HANDLER("[SERVER] all threads barrier arrived\n\r");
				// Send BARRIER HIT
				dsm_msg.msg_type = MSG_BARRIER_HIT;
				for( int i=0; i<num_clients; i++ ){
					pthread_mutex_lock(&handler_locks[i]);
					PRINT("handler locked fd_handler of client:%d\n", i);
					if (send_all(p->fd_handler[i], &dsm_msg, sizeof(dsm_msg)) != 0) {
						perror("[SERVER] Failed to send MSG_BARRIER_HIT");
						kill_and_exit(restored_pid);
					}else DSM_DEBUG_HANDLER("[SERVER] Sent MSG_BARRIER_HIT to client:%d\n\r", i);
					pthread_mutex_unlock(&handler_locks[i]);
					PRINT("handler unlocked fd_handler of client:%d\n", i);
				}


				//remote threads arrived, resolve fault and exit
				remote_threads_barrier_arrived = 0; //reset for next barrier
				pthread_cond_broadcast(&barrier.cond); //notify the other threads are waiting 
			}
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
			disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
			pthread_mutex_unlock(&barrier.lock);
			continue;
		}

		/* Local LOCK via page fault */
		else if (msg.arg.pagefault.address >= mutex_lock_start_address && msg.arg.pagefault.address < mutex_lock_end_address) {
			unsigned long my_ticket;
			pthread_mutex_lock(&mutex_l);

			my_ticket = ticket_next++;
			DSM_EVENT_HANDLER("[mutex] local LOCK fault from ptid=%d, ticket=%lu (serving=%lu)\n", msg.arg.pagefault.feat.ptid, (unsigned long)my_ticket, (unsigned long)ticket_serving);

			/* Wait until our ticket is being served */
			while (my_ticket != ticket_serving) {
				pthread_cond_wait(&mutex_cond, &mutex_l);
			}
			/* At this point, this thread owns the lock. Resolve the fault. */
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if (dsm_msg.page_addr >= mutex_lock_end_address) {
				dsm_msg.page_addr = mutex_lock_start_address;
			}
			enable_wp(uffd, (void *)dsm_msg.page_addr);              /* enable next lock page */
			disable_wp(uffd, (void *)msg.arg.pagefault.address);     /* unlock current page */
			pthread_mutex_unlock(&mutex_l);
			continue;
		}

		/* Local UNLOCK via page fault */
		if (msg.arg.pagefault.address >= mutex_unlock_start_address && msg.arg.pagefault.address <  mutex_unlock_end_address) {
			pthread_mutex_lock(&mutex_l);
			/* Release the lock: advance the ticket and wake up waiters */
			ticket_serving++;
			DSM_EVENT_HANDLER("[mutex] local UNLOCK fault from ptid=%d, now serving=%lu\n",	msg.arg.pagefault.feat.ptid, (unsigned long)ticket_serving);
			pthread_cond_broadcast(&mutex_cond);

			/* Move write-protect to next unlock page (if you’re rotating them) */
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if (dsm_msg.page_addr >= mutex_unlock_end_address) {
				dsm_msg.page_addr = mutex_unlock_start_address;
			}
			enable_wp(uffd, (void *)dsm_msg.page_addr);
			disable_wp(uffd, (void *)msg.arg.pagefault.address);

			pthread_mutex_unlock(&mutex_l);
			continue;
		}
		
		index = -1;
		for (int i=0; i < total_pages; i++) {
			unsigned long start = page_list_data[i].saddr;
			if (addr == start ) {
				index = i;
				break;
			}
		}
		if(index == -1 ) {
			PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n\r", addr);
			continue;
		}
		fault_start(addr, "LOCAL_HANDLER", num_clients );
		print_owner_mask(page_list_data[index].owner_mask);
		
		
	
		if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
			
			DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n\r");
			//if it's write protected means it was shared, just invalidate all owners
			//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
			// to make SERVER issue the drop page to all 
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = addr;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = index;

			owner_id = -1;
			for (int i = 1; i <= num_clients; i++) {
				if (page_list_data[index].owner_mask & (1ULL << i)) {
					owner_id = i - 1;
					pthread_mutex_lock(&handler_locks[owner_id]);
					PRINT("handler locked fd_handler of client:%d\n", owner_id);
					// Send invalidate request
					if (send_all(p->fd_handler[owner_id], &dsm_msg, sizeof(dsm_msg)) != 0) {
						perror("[SERVER] Failed to send MSG_SEND_INVALIDATE");
						kill_and_exit(restored_pid);
						return NULL;
					}
					DSM_EVENT_HANDLER("[Handler] Sent MSG_SEND_INVALIDATE to client:%d. With address:0x%lx\n\r", owner_id, addr);
					switch ( all_read(p->fd_handler[owner_id], &ack, 1)) {
						case -2:
							PRINT( "[SERVER] Connection closed before ACK\n\r");
							kill_and_exit(restored_pid);
						case -1:
							fprintf( stderr, "[SERVER] all_read(ACK) failed");
							kill_and_exit(restored_pid);
						case 0: 
							DSM_EVENT_HANDLER("[SERVER] Received MSG_INVALIDATE_ACK on INVALIDATION from client:%d\n\r", owner_id);
							break;
						default:
							fprintf( stderr, "Unknown value for handler all__read(ACK)\n\r");
							kill_and_exit(restored_pid);
					}

					pthread_mutex_unlock(&handler_locks[owner_id]);	
					PRINT("handler unlocked fd_handler of client:%d\n", owner_id);
				}
			}
			// Now you can safely disable WP
			disable_wp(uffd, (void *)addr);
			//update_page_info(addr, 0, MODIFIED, -2);
			PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
			page_list_data[index].state = MODIFIED;	
			page_list_data[index].owner_mask = (1ULL << 0); //server exclusive owner
			
		} else if ( !(page_list_data[index].owner_mask & (1ULL << 0)) ){ //if server owns it, it means that some one requested it 
			//find owner
			// 2. find which client currently owns it
			owner_id = -1;
			for (int i = 1; i <= num_clients; i++) {
				if (page_list_data[index].owner_mask & (1ULL << i)) {
					owner_id = i - 1; // convert bit to client index
					break;
				}
			}

			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p, owner_id:%d\n\r", (void*)msg.arg.pagefault.address, owner_id);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
				copy.mode = 0; 
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
							page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;	
				page_list_data[index].owner_mask = (1ULL << 0); //server exclusive owner
			} else {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p, owner_id:%d\n\r", (void*)msg.arg.pagefault.address, owner_id);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA;
				copy.mode = UFFDIO_COPY_MODE_WP;
				//update_page_info(addr, -1, SHARED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
							page_list_data[index].saddr, page_list_data[index].state, SHARED, index);
				page_list_data[index].state = SHARED;		
				page_list_data[index].owner_mask |= (1ULL << 0); //add server to current owners
			}

			if( 1 ){
				dsm_msg.page_addr = addr;
				dsm_msg.page_size = PAGE_SIZE;
				dsm_msg.msg_id = index;
				// 3. If a client owns it, request the page from them
				if (owner_id >= 0) {
					//let's take fd_handler mutex
					pthread_mutex_lock(&handler_locks[owner_id]);						
					PRINT("handler locked fd_handler of client:%d\n", owner_id);

					if (send_get_page(dsm_msg, p->fd_handler[owner_id], page_data) != 0) {
						PRINT( "[handler] Failed to fetch page from remote\n\r");
						kill_and_exit(restored_pid);
					}
					pthread_mutex_unlock(&handler_locks[owner_id]);
					PRINT("handler unlocked fd_handler of client:%d\n", owner_id);

				}else{
					DSM_EVENT_HANDLER("[handler] Page %d has no valid owner, bug\n\r", addr);
					kill_and_exit(restored_pid);
				}			
				copy.src  = (unsigned long)page_data;

			}else{ //meaning we are in debug mode without the client
				// Create a zero page for missing fault
				//memset(page_data, 0, PAGE_SIZE);
				copy.src  = (unsigned long)zero_page;
				DSM_EVENT_HANDLER("[handler] Creating zero page for MISSING PAGE FAULT on READ on an ALREADY SHARED PAGE (debug mode)\n\r");
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
				DSM_EVENT_HANDLER("[handler] Page copied back to missing region\n\r");
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
				PRINT( "[handler] UFFDIO_COPY semantic error %s (%d) on %lx\n\r",
						strerror(e), e, addr);
				// Optional: wake anyone waiting so they don’t hang
				r.start = addr;
				r.len = PAGE_SIZE;
				(void)ioctl(p->uffd, UFFDIO_WAKE, &r);
				kill_and_exit(restored_pid);
			} else {
				// Short copy – shouldn’t happen for anonymous pages
				PRINT( "[handler] UFFDIO_COPY short copy (%lld bytes) on %lx\n\r",
						(long long)copy.copy, addr);
				kill_and_exit(restored_pid);
			}
		}
		DSM_EVENT_HANDLER("[handler] done handling fault at 0x%lx\n\r", addr);
		fault_end(addr, "LOCAL_HANDLER", num_clients);
		print_owner_mask(page_list_data[dsm_msg.msg_id].owner_mask);
		//pthread_mutex_unlock(&pagefaults_mutex);
	}

	return NULL;
}



#if RDMA_ENABLE
void dsm_command_main_loop_RDMA(command_thread_args *a){
    struct msg_info msg;
	//RDMA
	struct ibv_wc wc;
	rdma_cmd_msg cmd;
	int client_id  = a->client_id;
	int owner_id = -1;
	struct uffdio_copy copy;
    struct iovec local_iov, remote_iov;
    ssize_t nread;

	/* 1) Wait for client's CMD on client.receiver */
	post_one_recv(&endpoints[client_id].receiver);

    while (1) {
        DSM_EVENT_SERVER("[SERVER] Waiting for RDMA message on endpoints[client_id].receiver...\n\r");
		/* 1. Wait for WRITE_WITH_IMM from client */
		poll_one_cqe(&endpoints[client_id].receiver, &wc);
		if (!(wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM)) {
			DSM_EVENT_SERVER("[SERVER] Unexpected CQE opcode=%d\n\r", wc.opcode);
		}
		memcpy(&cmd, endpoints[client_id].receiver.base_addr, sizeof(cmd));
		DSM_EVENT_SERVER("[SERVER] Command CMD: target_addr=%#llx fault addr=%#llx id=%u, index:%u\n\r",
			(unsigned long long)be64toh(cmd.target_addr),
			(unsigned long long)be64toh(cmd.faulting_addr),
			(unsigned)ntohl(cmd.id),
			(unsigned)ntohl(cmd.index));

		msg.msg_type = ntohl(cmd.id); //abusing msg_type to store the command type
		msg.page_addr = be64toh(cmd.faulting_addr);
		msg.msg_id = ntohl(cmd.index);
		post_one_recv(&endpoints[client_id].receiver);
        DSM_DEBUG_SERVER("[DSM Server] Received message: type=%d, addr=0x%lx, id=%ld\n\r",
               msg.msg_type, msg.page_addr, msg.msg_id);
		
		if( msg.msg_type != MSG_BARRIER_HIT ) {
			fault_start(msg.page_addr, "SERVER", client_id);
			print_owner_mask( page_list_data[msg.msg_id].owner_mask );
		}	
        switch (msg.msg_type) {
			case MSG_BARRIER_HIT:
				if( num_clients ){
					pthread_mutex_lock(&barrier.lock);
					DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler (imm=0xBB)\n\r");
					rdma_write_core(&endpoints[client_id].receiver_data,
									be64toh(endpoints[client_id].remote_all.handler.vaddr),
									ntohl(endpoints[client_id].remote_all.handler.rkey),
									endpoints[client_id].receiver_data.base_addr, 0, 0xBB);

					if( remote_threads_barrier_arrived == num_clients){
						//means that the handler thread has not process the barrier yet, let's wait until it does
						pthread_cond_wait(&barrier.cond, &barrier.lock);
					}

					// mark that remote threads have arrived, this is useful if we come before the local threads have, 
					//so that we don't care if the signal was lost since we can check the variable
					remote_threads_barrier_arrived++; 
					remote_barrier_addr = msg.page_addr;
					DSM_DEBUG_SERVER("[DSM Server] Remote barrier hit. %d/%d\n\r",remote_threads_barrier_arrived, num_clients);
					if( remote_threads_barrier_arrived == num_clients ){
						DSM_EVENT_SERVER("[DSM Server] All remote threads have arrived! \n\r");
						pthread_cond_broadcast(&barrier.cond); 
						//releasing local handler if it was waiting, if not it will not wait due to remote_threads_barrier_arrived being already N_Clients
					}
					pthread_mutex_unlock(&barrier.lock);
					continue;
				}
				break;
			case MSG_WAKE_THREAD:
				DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler (imm=0xB1)\n\r");
				rdma_write_core(&endpoints[client_id].receiver_data,
								be64toh(endpoints[client_id].remote_all.handler.vaddr),
								ntohl(endpoints[client_id].remote_all.handler.rkey),
								endpoints[client_id].receiver_data.base_addr, 0, 0xB1);
				send_sigcont(restored_pid);
				break;
			case MSG_STOP_THREAD:
				send_sigstop(restored_pid);
				break;
			case MSG_GET_PAGE_DATA:
				DSM_EVENT_SERVER("→ Handling RDMA GET_PAGE_DATA\n\r");
				//We already have fault start, therefore we have permission to handle this address 
				//Now we have to check the owner and request the page from him
				owner_id = -2; //-2 means no owner, -1 means server owns it
				for (int i = 0; i <= num_clients; i++) {
					if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
						owner_id = i - 1; // convert bit to client index
						break;
					}
				}
				if( owner_id == -1){
					//server owns the page, we can serve it directly
					PRINT("[DSM] Using process_vm_readv() to fetch remote page (pid=%d, addr=%p)\n\r",
					restored_pid, (void*)msg.page_addr);
					// --- Prepare iovecs ---
					local_iov.iov_base = endpoints[client_id].receiver_data.base_addr; //RDMA 
					local_iov.iov_len  = PAGE_SIZE;
					remote_iov.iov_base = (void*)msg.page_addr;
					remote_iov.iov_len  = PAGE_SIZE;	
					// --- Read the page directly from target process ---
					nread = process_vm_readv(restored_pid,
											&local_iov, 1,
											&remote_iov, 1,
											0);	
					if (nread != PAGE_SIZE) {
						if (nread < 0)
							PRINT("❌ process_vm_readv failed: %s\n\r", strerror(errno));
						else
							PRINT("⚠️ process_vm_readv read partial data: %ld bytes\n\r", nread);
						kill_and_exit(restored_pid);	
					}	
					PRINT("✅ Read %ld bytes from target process memory\n\r", nread);
				}
				else if( owner_id == -2 ){
					DSM_EVENT_SERVER("[SERVER] Page %d has no valid owner, bug\n\r", msg.msg_id);
					kill_and_exit(restored_pid);
				}else{
					//we first need to request it from the owner client
					//let's take fd_handler mutex
					pthread_mutex_lock(&handler_locks[owner_id]);
					PRINT("receiver:%d locked RDMA handler of client:%d\n", client_id, owner_id);
					//now we can send to the client receiver our request
					//1. copy message GET PAGE_DATA to the owner receiver buffer
					memcpy(endpoints[owner_id].handler_data.base_addr, endpoints[client_id].receiver.base_addr, sizeof(cmd));
					//Prepare for response 
					post_one_recv(&endpoints[owner_id].handler);
					/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
					DSM_EVENT_HANDLER("[SERVER] Sending CMD to client.receiver (imm=0xCAFE)\n\r");
					rdma_write_core(&endpoints[owner_id].handler_data,
									be64toh(endpoints[owner_id].remote_all.receiver.vaddr),
									ntohl(endpoints[owner_id].remote_all.receiver.rkey),
									endpoints[owner_id].handler_data.base_addr, sizeof(cmd), 0xCAFE);

					/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
					for (;;) {
						if (ibv_poll_cq(endpoints[owner_id].handler.cq, 1, &wc) > 0) {
							if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
								if (wc.wc_flags & IBV_WC_WITH_IMM )
									DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
								else{
									PRINT( "[SERVER] endpoints[owner_id].handler != MSG_GET_PAGE/GET_PAGE_INVALIDATE:%d\n\r", MSG_INVALIDATE_ACK);
									kill_and_exit(restored_pid);
								}
								break;
							}
						}
					}
					
					pthread_mutex_unlock(&handler_locks[owner_id]);
					PRINT("handler unlocked RDMA of client:%d\n", owner_id);

					//Now we locally update the page and then send it to the client requesting it
					copy.src  = (unsigned long)endpoints[owner_id].handler.base_addr;
					copy.mode = UFFDIO_COPY_MODE_WP;
					copy.dst = msg.page_addr;
					copy.len = PAGE_SIZE;  
					if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) {
						// Kernel-level failure (not the EEXIST race, that shows up in copy.copy)
						DSM_EVENT_SERVER("[receiver:%d] ", client_id);
						perror("UFFDIO_COPY ioctl failed\n");
						kill_and_exit(restored_pid);
					}
					if( copy.copy  ){
						DSM_EVENT_SERVER("[Receiver:%d] Page copied back to missing region\n\r", client_id);
					}
					//changing ownership
					page_list_data[msg.msg_id].owner_mask |= (1ULL << 0);  //adding server as owner
					page_list_data[msg.msg_id].state = SHARED;

					//now we have the page in the correct RDMA buffer, we can send it to the client
					memcpy(endpoints[client_id].receiver_data.base_addr, endpoints[owner_id].handler.base_addr, PAGE_SIZE);

				}
				//now we have the page in the RDMA buffer, we can send it to the client
				// --- Send page data to client ---
				rdma_write_core(&endpoints[client_id].receiver_data,
								be64toh(endpoints[client_id].remote_all.handler.vaddr),
								ntohl(endpoints[client_id].remote_all.handler.rkey),
								endpoints[client_id].receiver_data.base_addr, 4096, 0xB1);
				PRINT("✅ Page_transfer_complete to client (addr=%p)\n\r", (void*)msg.page_addr);
				
				page_list_data[msg.msg_id].owner_mask |= (1ULL << (client_id + 1)); //adding requesting client as owner
				if( page_list_data[msg.msg_id].state != SHARED ){
					enable_wp(uffd, (void*)msg.page_addr);
					page_list_data[msg.msg_id].state = SHARED;	
				}

				break;
			case MSG_GET_PAGE_DATA_INVALID:
				DSM_EVENT_SERVER("→ Handling RDMA GET_PAGE_DATA_INVALID\n\r");
				//We already have fault start, therefore we have permission to handle this address 
				//Now we have to check the owner and request the page from him
				owner_id = -2; //-2 means no owner, -1 means server owns it
				for (int i = 0; i <= num_clients; i++) {
					if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
						owner_id = i - 1; // convert bit to client index
						break;
					}
				}
				if( owner_id == -1){
					//server owns the page, we can serve it directly
					PRINT("[DSM] Using process_vm_readv() to fetch remote page (pid=%d, addr=%p)\n\r",
					restored_pid, (void*)msg.page_addr);
				
					// --- Prepare iovecs ---
					local_iov.iov_base = endpoints[client_id].receiver_data.base_addr; //RDMA 
					local_iov.iov_len  = PAGE_SIZE;
					remote_iov.iov_base = (void*)msg.page_addr;
					remote_iov.iov_len  = PAGE_SIZE;	
					// --- Read the page directly from target process ---
					nread = process_vm_readv(restored_pid,
											&local_iov, 1,
											&remote_iov, 1,
											0);	
					if (nread != PAGE_SIZE) {
						if (nread < 0)
							PRINT("❌ process_vm_readv failed: %s\n\r", strerror(errno));
						else
							PRINT("⚠️ process_vm_readv read partial data: %ld bytes\n\r", nread);
						kill_and_exit(restored_pid);	
					}	
					PRINT("✅ Read %ld bytes from target process memory\n\r", nread);

					//AND invalidate the page
					page_list_data[msg.msg_id].owner_mask &= ~(1ULL << 0);  //removing server as owner
					PRINT("Message is GET_PAGE_INVALIDATE → SERVER Drops the page to INVALIDATE\n\r");
					if (run_proc_MADVISE(pidfd, restored_pid, (void*)msg.page_addr, PAGE_SIZE) == 0)
						PRINT("process_madvise to invalidate page %p\n\r", (void*)msg.page_addr);
					else{
						PRINT("❌ MADV_DONTNEED failed: %s\n\r", strerror(errno));
						kill_and_exit(restored_pid);
					}
				}
				else if( owner_id == -2 ){
					DSM_EVENT_SERVER("[SERVER] Page %d has no valid owner, bug\n\r", msg.msg_id);
					kill_and_exit(restored_pid);
				}else{
					//we first need to request it from the owner client
					//let's take fd_handler mutex
					pthread_mutex_lock(&handler_locks[owner_id]);
					PRINT("receiver:%d locked RDMA handler of client:%d\n", client_id, owner_id);
					//now we can send to the client receiver our request
					//1. copy message GET PAGE_DATA to the owner receiver buffer
					memcpy(endpoints[owner_id].handler_data.base_addr, endpoints[client_id].receiver.base_addr, sizeof(cmd));
					//Prepare for response 
					post_one_recv(&endpoints[owner_id].handler);
					/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
					DSM_EVENT_HANDLER("[SERVER] Sending CMD to client.receiver (imm=0xCAFE)\n\r");
					rdma_write_core(&endpoints[owner_id].handler_data,
									be64toh(endpoints[owner_id].remote_all.receiver.vaddr),
									ntohl(endpoints[owner_id].remote_all.receiver.rkey),
									endpoints[owner_id].handler_data.base_addr, sizeof(cmd), 0xCAFE);

					/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
					for (;;) {
						if (ibv_poll_cq(endpoints[owner_id].handler.cq, 1, &wc) > 0) {
							if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
								if (wc.wc_flags & IBV_WC_WITH_IMM )
									DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
								else{
									PRINT( "[SERVER] endpoints[owner_id].handler != MSG_GET_PAGE/GET_PAGE_INVALIDATE:%d\n\r", MSG_INVALIDATE_ACK);
									kill_and_exit(restored_pid);
								}
								break;
							}
						}
					}
					
					pthread_mutex_unlock(&handler_locks[owner_id]);
					PRINT("handler unlocked RDMA of client:%d\n", owner_id);

					//this client (owner_id) has the page, we need to copy it to the client requesting it (client_id)
					
					//also it already did the invalidation, remove the owner from the owner mask
					page_list_data[msg.msg_id].owner_mask &= ~(1ULL << (owner_id + 1));

					//now we have the page in the correct RDMA buffer, we can send it to the client
					memcpy(endpoints[client_id].receiver_data.base_addr, endpoints[owner_id].handler.base_addr, PAGE_SIZE);

				}
				//now we have the page in the RDMA buffer, we can send it to the client
				// --- Send page data to client ---
				rdma_write_core(&endpoints[client_id].receiver_data,
								be64toh(endpoints[client_id].remote_all.handler.vaddr),
								ntohl(endpoints[client_id].remote_all.handler.rkey),
								endpoints[client_id].receiver_data.base_addr, 4096, 0xB1);
				PRINT("✅ Page_transfer_complete to client (addr=%p)\n\r", (void*)msg.page_addr);
				
				
				//check if we may have to invalidate other shares
				if( page_list_data[msg.msg_id].state == SHARED ){ //its shared, we may have some clients to invalidate
					//prepare the invalidate message
					cmd.id = htonl(MSG_SEND_INVALIDATE);
					
					
					for (int i = 1; i <= num_clients; i++) {
						if( i - 1 == client_id ) continue; //skip to not invalidate requesting client
						if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
							owner_id = i - 1;
							//let's take fd_handler mutex
							pthread_mutex_lock(&handler_locks[owner_id]);						
							PRINT("handler locked RDMA of client:%d\n", owner_id);
							
							/* 3) Copy CMD into TX buffer (handler_data MR) */
							memcpy(endpoints[owner_id].handler_data.base_addr, &cmd, sizeof(cmd));
							
							//Prepare for response 
							post_one_recv(&endpoints[owner_id].handler);

							/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
							DSM_EVENT_HANDLER("[SERVER] Sending INVALIDATE to client.receiver (imm=0xCAFE)\n\r");
							rdma_write_core(&endpoints[owner_id].handler_data,
											be64toh(endpoints[owner_id].remote_all.receiver.vaddr),
											ntohl(endpoints[owner_id].remote_all.receiver.rkey),
											endpoints[owner_id].handler_data.base_addr, sizeof(cmd), 0xCAFE);

							/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
							for (;;) {
								if (ibv_poll_cq(endpoints[owner_id].handler.cq, 1, &wc) > 0) {
									if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
										if (wc.wc_flags & IBV_WC_WITH_IMM )
											DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
										else{
											PRINT( "[SERVER] endpoints[owner_id].handler != MSG_GET_PAGE/GET_PAGE_INVALIDATE:%d\n\r", MSG_INVALIDATE_ACK);
											kill_and_exit(restored_pid);
										}
										break;
									}
								}
							}
							pthread_mutex_unlock(&handler_locks[owner_id]);
							PRINT("handler unlocked RDMA of client:%d\n", owner_id);
						}
					}
				}
				page_list_data[msg.msg_id].owner_mask = (1ULL << (client_id + 1)); //adding requesting client as owner
				page_list_data[msg.msg_id].state = INVALID; 
				break;
            case MSG_SEND_INVALIDATE:
				//Just send this message to all owners 
				DSM_EVENT_SERVER("→ Handling remote RDMA invalidation request. Madvise(MADV_DONTNEED) on page at %p\n\r", (void *)msg.page_addr);
				for (int i = 1; i <= num_clients; i++) {
					if( i - 1 == client_id ) continue; //skip to not invalidate requesting client
					if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
						owner_id = i - 1;
						//let's take fd_handler mutex
						pthread_mutex_lock(&handler_locks[owner_id]);						
						PRINT("handler locked RDMA of client:%d\n", owner_id);
						
						/* 3) Copy CMD into TX buffer (handler_data MR) */
						memcpy(endpoints[owner_id].handler_data.base_addr, &cmd, sizeof(cmd));
						
						//Prepare for response 
						post_one_recv(&endpoints[owner_id].handler);

						/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
						DSM_EVENT_HANDLER("[SERVER] Sending INVALIDATE to client.receiver (imm=0xCAFE)\n\r");
						rdma_write_core(&endpoints[owner_id].handler_data,
										be64toh(endpoints[owner_id].remote_all.receiver.vaddr),
										ntohl(endpoints[owner_id].remote_all.receiver.rkey),
										endpoints[owner_id].handler_data.base_addr, sizeof(cmd), 0xCAFE);

						/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
						for (;;) {
							if (ibv_poll_cq(endpoints[owner_id].handler.cq, 1, &wc) > 0) {
								if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
									if (wc.wc_flags & IBV_WC_WITH_IMM )
										DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
									else{
										PRINT( "[SERVER] endpoints[owner_id].handler != MSG_GET_PAGE/GET_PAGE_INVALIDATE:%d\n\r", MSG_INVALIDATE_ACK);
										kill_and_exit(restored_pid);
									}
									break;
								}
							}
						}
						pthread_mutex_unlock(&handler_locks[owner_id]);
						PRINT("handler unlocked RDMA of client:%d\n", owner_id);
					}
				}
				
				// then invalidate server if owner
				if (page_list_data[msg.msg_id].owner_mask & (1ULL << 0)) {
					if (run_proc_MADVISE(pidfd, restored_pid, (void *)msg.page_addr, 4096) == 0){
						DSM_EVENT_SERVER("Successfully ran madvise on page at %p\n\r", (void *)msg.page_addr);
						
						DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler on INVALIDATE (imm=0xB1)\n\r");
						rdma_write_core(&endpoints[client_id].receiver_data,
										be64toh(endpoints[client_id].remote_all.handler.vaddr),
										ntohl(endpoints[client_id].remote_all.handler.rkey),
										endpoints[client_id].receiver_data.base_addr, 0, 0xB1);

						PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n\r",	msg.page_addr, page_list_data[msg.msg_id].state, INVALID, msg.msg_id);
						page_list_data[msg.msg_id].state = INVALID;		
					}else {
						perror("run_proc_MADVISE RDMA command loop");
						kill_and_exit(restored_pid);
					} 
				}
				

				PRINT("Changing state and owner\n");
				page_list_data[msg.msg_id].state = INVALID;		
				page_list_data[msg.msg_id].owner_mask = (1ULL << (client_id + 1)); 
				//pthread_mutex_unlock(&pagefaults_mutex);
				break;

            case MSG_HANDSHAKE:
                DSM_EVENT_SERVER("[DSM Server] Test handshake message received, ignoring.\n\r");
                continue;
			
            default:
                PRINT( "⚠️ Unknown message type: %d\n\r", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
		fault_end(msg.page_addr, "SERVER", client_id);
		PRINT("\n\r");
    }
}
#endif
	void dsm_command_main_loop(command_thread_args *a){
	//void dsm_command_main_loop(int fd_command, int client_id) {
		struct msg_info msg;
		ssize_t n;
		unsigned char ack;
		int client_id  = a->client_id;
		int fd_command  = a->conn[client_id].fd_command;
		//int n_cli  = a->n_clients;
		int owner_id = -1;
		unsigned char page_data[PAGE_SIZE] = {0}; 
		struct uffdio_copy copy;

		while (1) {
			DSM_EVENT_SERVER("[DSM Server for client:%d] (fd=%d) Waiting for command message...\n\r", client_id, fd_command);

			n = recv(fd_command, &msg, sizeof(msg), 0);
			if (n <= 0) {
				perror("[DSM Server] recv failed or connection closed");
				break;
			} else if (n != sizeof(msg)) {
				PRINT( "[DSM Server] Incomplete message received (got %zd bytes)\n\r", n);
				continue;
			}

			DSM_DEBUG_SERVER("[DSM Server Client:%d] Received message: type=%d, addr=0x%lx, id=%ld\n\r", client_id, msg.msg_type, msg.page_addr, msg.msg_id);
			
			if( msg.msg_type != MSG_BARRIER_HIT &&  msg.msg_type != MSG_LOCK_REQUEST && msg.msg_type != MSG_UNLOCK && msg.msg_type != MSG_JOIN_THREAD ) {
				fault_start(msg.page_addr, "SERVER", client_id);
				print_owner_mask( page_list_data[msg.msg_id].owner_mask );
			}
		
			switch (msg.msg_type) {

				case MSG_LOCK_REQUEST: 
					unsigned long my_ticket;

					pthread_mutex_lock(&mutex_l);

					my_ticket = ticket_next++;
					DSM_EVENT_SERVER("[mutex] remote LOCK from client=%d, ticket=%lu (serving=%lu)\n",
									client_id,
									(unsigned long)my_ticket,
									(unsigned long)ticket_serving);

					while (my_ticket != ticket_serving) {
						pthread_cond_wait(&mutex_cond, &mutex_l);
					}

					/* Now this client is granted the lock */
					pthread_mutex_unlock(&mutex_l);
					ack = MSG_GRANT_LOCK;
					if (send_all(fd_command, &ack, 1) != 0) {
						perror("send MSG_GRANT_LOCK");
						kill_and_exit(restored_pid);
					} else {
						DSM_EVENT_SERVER("[SERVER] Sent MSG_GRANT_LOCK to client.\n\r");
					}
					continue;
					break;

				case MSG_UNLOCK: 
					pthread_mutex_lock(&mutex_l);

					ticket_serving++;
					DSM_EVENT_SERVER("[mutex] remote UNLOCK from client=%d, now serving=%lu\n",
									client_id,
									(unsigned long)ticket_serving);

					pthread_cond_broadcast(&mutex_cond);

					pthread_mutex_unlock(&mutex_l);
					continue;
					break;
				case MSG_JOIN_THREAD:
					DSM_EVENT_SERVER("Server received JOIN_THREAD from client:%d, tid:%d\n\r", client_id, msg.msg_id);
					{
						char path[256];
						int fd ;
						snprintf(path, sizeof(path), "/tmp/thread_%ld_dead", msg.msg_id);

						fd = open(path, O_CREAT | O_WRONLY, 0666);
						if (fd < 0) {
							perror("open dead thread file");
						} else {
							close(fd);
						}

					}

					continue;
					break;


				case MSG_BARRIER_HIT:
					pthread_mutex_lock(&barrier.lock);

					if( remote_threads_barrier_arrived == num_clients){
						//means that the handler thread has not process the barrier yet, let's wait until it does
						pthread_cond_wait(&barrier.cond, &barrier.lock);
					}

					// mark that remote threads have arrived, this is useful if we come before the local threads have, 
					//so that we don't care if the signal was lost since we can check the variable
					remote_threads_barrier_arrived++; 
					remote_barrier_addr = msg.page_addr;
					DSM_DEBUG_SERVER("[DSM Server] Remote barrier hit. %d/%d\n\r",remote_threads_barrier_arrived, num_clients);
					if( remote_threads_barrier_arrived == num_clients ){
						DSM_EVENT_SERVER("[DSM Server] All remote threads have arrived! \n\r");
						pthread_cond_broadcast(&barrier.cond); 
						//releasing local handler if it was waiting, if not it will not wait due to remote_threads_barrier_arrived being already N_Clients
					}
					pthread_mutex_unlock(&barrier.lock);
					continue;
					
					break;
				case MSG_WAKE_THREAD:
					send_sigcont(restored_pid);
					break;
				case MSG_STOP_THREAD:
					send_sigstop(restored_pid);
					break;
				case MSG_GET_PAGE_DATA:
					//We already have fault start, therefore we have permission to handle this address 
					//Now we have to check the owner and request the page from him
					owner_id = -1;
					// 1. Check if the server already has the page
					if (page_list_data[msg.msg_id].owner_mask & (1ULL << 0)) {
						// Server owns the page -> serve it directly
						DSM_EVENT_SERVER("→ Handling TCP GET_PAGE_DATA from node:%d on server\n\r", client_id);
						handle_page_data_request(restored_pid, uffd, fd_command, &msg);
						page_list_data[msg.msg_id].owner_mask |= (1ULL << (client_id + 1)); //adding requesting client as owner
						break;
					}
					// 2. Otherwise, find which client currently owns it
					for (int i = 1; i <= num_clients; i++) {
						if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
							owner_id = i - 1; // convert bit to client index
							break;
						}
					}
					// 3. If a client owns it, request the page from them
					if (owner_id >= 0) {
						DSM_EVENT_SERVER("[DSM] Handling TCP GET_PAGE_DATA for page %lx, from client %d, requesting to client:%d\n\r", msg.page_addr, client_id, owner_id);
						
						//let's take fd_handler mutex
						pthread_mutex_lock(&handler_locks[owner_id]);
						PRINT("receiver:%d locked fd_handler of client:%d\n", client_id, owner_id);
						//now we can send to the client receiver our request
						if (send_get_page(msg, a->conn[owner_id].fd_handler, page_data) != 0) {
							PRINT( "[handler] Failed to fetch page from remote\n\r");
							kill_and_exit(restored_pid);
						}
						//we have the page
						//now we need to send it back to the waiting client
						if (send_all(fd_command, page_data, PAGE_SIZE) < 0) {
							perror("send_all(page_data)");
							kill_and_exit(restored_pid);
						}

						copy.mode = UFFDIO_COPY_MODE_WP;
						copy.src  = (unsigned long)page_data;
						copy.dst = msg.page_addr;
						copy.len = PAGE_SIZE;  

						if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) {
							// Kernel-level failure (not the EEXIST race, that shows up in copy.copy)
							DSM_EVENT_SERVER("[receiver:%d] ", client_id);
							perror("UFFDIO_COPY ioctl failed\n");
							kill_and_exit(restored_pid);
						}
						if( copy.copy  ){
							DSM_EVENT_SERVER("[Receiver:%d] Page copied back to missing region\n\r", client_id);
						}

						//changing ownership
						page_list_data[msg.msg_id].owner_mask |= (1ULL << 0);  //adding server as owner
						page_list_data[msg.msg_id].owner_mask |= (1ULL << (client_id + 1)); //adding requesting client as owner
						page_list_data[msg.msg_id].state = SHARED;

						enable_wp(uffd, (void*) copy.dst);
						pthread_mutex_unlock(&handler_locks[owner_id]);
						PRINT("receiver:%d unlocked fd_handler of client:%d\n", client_id, owner_id);
						break;
					}
					
					DSM_EVENT_SERVER("[DSM] Page %d has no valid owner, bug\n\r", msg.page_addr);
					kill_and_exit(restored_pid);
					break;
				case MSG_GET_PAGE_DATA_INVALID:
					//We already have fault start, therefore we have permission to handle this address 
					//Now we have to check the owner and request the page from him
					// 1. Check if the server already has the page
					if (page_list_data[msg.msg_id].owner_mask & (1ULL << 0)) {
						// Server owns the page -> serve it directly
						DSM_EVENT_SERVER("→ Handling TCP GET_PAGE_DATA_INVALID from node:%d on server\n\r", client_id);
						
						//Now the server already sadisfy the GET_PAGE_INVALID, now we just have to 
						//send the invalidate to the other owners, if any 
						if( page_list_data[msg.msg_id].state != SHARED ) {
							//no possible other owners
							//page handled
							//change owner, change status
							handle_page_data_request(restored_pid, uffd, fd_command, &msg);
							page_list_data[msg.msg_id].owner_mask = (1ULL << (client_id + 1)); //owner set to the one requesting the page
							break;
						}

						handle_page_data_request(restored_pid, uffd, fd_command, &msg);
						msg.msg_type = MSG_SEND_INVALIDATE;
						
						owner_id = -1;
						for (int i = 1; i <= num_clients; i++) {
							if( i - 1 == client_id ) continue; //skip to not invalidate requesting client
							if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
								owner_id = i - 1;
								pthread_mutex_lock(&handler_locks[owner_id]);
								PRINT("receiver:%d locked fd_handler of client:%d\n", client_id, owner_id);
								// Send invalidate request
								
								if (send_all( a->conn[owner_id].fd_handler, &msg, sizeof(msg)) != 0) {
									fprintf( stderr, "[SERVER:%d] Failed to send MSG_SEND_INVALIDATE", client_id);
									kill_and_exit(restored_pid);
								}
								DSM_EVENT_SERVER("[SERVER:%d] Sent MSG_SEND_INVALIDATE to Client:%d. With address:0x%lx\n\r", client_id, owner_id, msg.page_addr);

								switch ( all_read(a->conn[owner_id].fd_handler, &ack, 1) ) {
									case -2:
										PRINT( "[SERVER] Connection closed before ACK\n\r");
										kill_and_exit(restored_pid);
									case -1:
										fprintf( stderr, "[SERVER] all_read(ACK) failed");
										kill_and_exit(restored_pid);
									case 0: 
										DSM_EVENT_SERVER("[SERVER] Received MSG_INVALIDATE_ACK on INVALIDATION\n\r");
										pthread_mutex_unlock(&handler_locks[owner_id]);	
										PRINT("receiver:%d unlocked fd_handler of client:%d\n", client_id, owner_id);
										continue;
									default:
										fprintf( stderr, "Unknown value for handler all_read(ACK)\n\r");
										kill_and_exit(restored_pid);
								}							
							}
						}
					}else {
						//It means there's only 1 owner, and it's not the server
						//get that owner id, starting from server
						owner_id = -1;
						for (int i = 1; i <= num_clients; i++) {
							if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
								owner_id = i - 1; // convert bit to client index
								break;
							}
						}
						// 3. If a client owns it, request the page from them
						if (owner_id >= 0) {
							DSM_EVENT_SERVER("[DSM] Handling TCP GET_PAGE_DATA_INVALID for page %d, from client %d, requesting to client:%d\n\r", msg.page_addr, client_id, owner_id);

							//let's take fd_handler mutex
							pthread_mutex_lock(&handler_locks[owner_id]);
							PRINT("receiver:%d locked fd_handler of client:%d\n", client_id, owner_id);
							//now we can send to the client receiver our request

							if (send_get_page(msg, a->conn[owner_id].fd_handler, page_data) != 0) {
								PRINT( "[handler] Failed to fetch page from remote\n\r");
								kill_and_exit(restored_pid);
							}
							DSM_EVENT_SERVER("[SERVER:%d] Sent GET_PAGE_DATA_INVALID to Client:%d. With address:0x%lx\n\r", client_id, owner_id, msg.page_addr);

							// --- Send page data to requesting client ---
							if (send_all(fd_command, page_data, PAGE_SIZE) < 0) {
								perror("send_all(page_data)");
							}
							DSM_EVENT_SERVER("[SERVER:%d] Sent page to requesting Client:%d. With address:0x%lx\n\r", client_id, client_id, msg.page_addr);

							//change owner and the status
							
							page_list_data[msg.msg_id].state = INVALID; 
							page_list_data[msg.msg_id].owner_mask = (1ULL << (client_id + 1)); //owner set to the one requesting the page


							pthread_mutex_unlock(&handler_locks[owner_id]);
							PRINT("receiver:%d unlocked fd_handler of client:%d\n", client_id, owner_id);

						}else{
							DSM_EVENT_SERVER("[DSM] Page %d has no valid owner, bug\n\r", msg.page_addr);
							kill_and_exit(restored_pid);
						}

					}
					break;
				case MSG_SEND_INVALIDATE:
					//Just send this message to all owners 
					//first invalidate remote
					owner_id = -1;
					for (int i = 1; i <= num_clients; i++) {
						if( i - 1 == client_id ) continue; //skip to not invalidate requesting client
						if (page_list_data[msg.msg_id].owner_mask & (1ULL << i)) {
							owner_id = i - 1;
							DSM_EVENT_SERVER("→ Receiver:%d, Handling TCP invalidation request on client:%d. Madvise(MADV_DONTNEED) on page at %p\n\r", client_id, owner_id,  (void *)msg.page_addr);
							pthread_mutex_lock(&handler_locks[owner_id]);
							PRINT("receiver:%d locked fd_handler of client:%d\n", client_id, owner_id);
							// Send invalidate request
						
							if (send_all( a->conn[owner_id].fd_handler, &msg, sizeof(msg)) != 0) {
								PRINT("[SERVER:%d] Failed to send MSG_SEND_INVALIDATE", client_id);
								kill_and_exit(restored_pid);
							}
							DSM_EVENT_SERVER("[SERVER:%d] Sent MSG_SEND_INVALIDATE to Client:%d. With address:0x%lx\n\r", client_id, owner_id, msg.page_addr);

							switch ( all_read(a->conn[owner_id].fd_handler, &ack, 1) ) {
								case -2:
									PRINT( "[SERVER] Connection closed before ACK\n\r");
									kill_and_exit(restored_pid);
								case -1:
									PRINT("[SERVER] all_read(ACK) failed");
									kill_and_exit(restored_pid);
								case 0: 
									DSM_EVENT_SERVER("[SERVER] Received MSG_INVALIDATE_ACK on INVALIDATION from client:%d\n\r", owner_id);
									pthread_mutex_unlock(&handler_locks[owner_id]);	
									PRINT("receiver:%d unlocked fd_handler of client:%d\n", client_id, owner_id);
									continue;
								default:
									PRINT("Unknown value for handler alll_read(ACK)\n\r");
									kill_and_exit(restored_pid);
							}
							pthread_mutex_unlock(&handler_locks[owner_id]);	
							PRINT("receiver:%d unlocked fd_handler of client:%d\n", client_id, owner_id);
						}
					}
					if( owner_id == -1 ) DSM_EVENT_SERVER("Receiver:%d, No other owner other than server\n", client_id);

					// then invalidate server if owner
					if (page_list_data[msg.msg_id].owner_mask & (1ULL << 0)) {
						DSM_EVENT_SERVER("→ Receiver:%d, Handling TCP invalidation request on server. Madvise(MADV_DONTNEED) on page at %p\n\r", client_id,  (void *)msg.page_addr);
						//pthread_mutex_lock(&pagefaults_mutex);
						if (run_proc_MADVISE(pidfd, restored_pid, (void *)msg.page_addr, 4096) == 0) {
							DSM_EVENT_SERVER("Successfully ran madvise on page at %p\n\r", (void *)msg.page_addr);

							ack = MSG_INVALIDATE_ACK;
							if (send_all(fd_command, &ack, 1) != 0) {
								perror("send MSG_INVALIDATE_ACK");
								kill_and_exit(restored_pid);
							} else {
								DSM_EVENT_SERVER("[SERVER] Sent MSG_INVALIDATE_ACK to client.\n\r");
							}
							//update_page_info(msg.page_addr, 1, INVALID, -1);
							PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n\r",
									msg.page_addr, page_list_data[msg.msg_id].state, INVALID, msg.msg_id);
						}else {
							perror("runMADVISE TCP command loop");
							kill_and_exit(restored_pid);
						}  
					}



					PRINT("Changing state and owner\n");
					page_list_data[msg.msg_id].state = INVALID;		
					page_list_data[msg.msg_id].owner_mask = (1ULL << (client_id + 1)); 	
					break;

				case MSG_HANDSHAKE:
					DSM_EVENT_SERVER("[DSM Server] Test handshake message received, ignoring.\n\r");
					continue;
				
				default:
					PRINT( "⚠️ Unknown message type: %d\n\r", msg.msg_type);
					kill_and_exit(restored_pid);  // shutdown the server on protocol error
					break;
			}
			PRINT("\n\r");
			fault_end(msg.page_addr, "SERVER", client_id);			
			print_owner_mask(page_list_data[msg.msg_id].owner_mask);
		}
	}



#if COMMAND_THREAD 

void* command_thread_func_server(void* arg) {
    struct command_thread_args* args = arg;


    command_loop(args->restored_pid, args->uffd, &args->conn);
    return NULL;
}



#endif
#if 0
// Thread wrapper — each runs one main loop
void *command_thread_main(void *arg) {
    struct command_thread_args *a = arg;
    PRINT("[DSM Server] Thread %d starting main loop (fd=%d)\n\r", a->client_id, a->conn.fd_command);

    dsm_command_main_loop(a->conn.fd_command, a->client_id);

    PRINT("[DSM Server] Thread %d exiting main loop\n\r", a->client_id);
    free(a);
    return NULL;
}
#else
void *command_thread_main(void *arg)
{
    command_thread_args *a = arg;

    PRINT("[DSM Server] Thread %d starting main loop (fd=%d)\n\r",
          a->client_id, a->conn[a->client_id].fd_command);

	if( rdma_on )  dsm_command_main_loop_RDMA(a);     
	else  dsm_command_main_loop(a);     

   

    PRINT("[DSM Server] Thread %d exiting main loop\n\r", a->client_id);
    free(a);
    return NULL;
}
#endif
void start_dsm_server(int n_clients, int rdma_enable)
{
	struct vm_area_list vmas = { .nr = 0};
	int server_fd=0, client_fd=0;
	int bin, i, num_pages;
	pthread_t uffd_thread; //, barrier_tid;
	struct thread_param *param = malloc(sizeof(*param));
	unsigned long base_address;
	size_t page_size;

	struct dsm_connection *conn = calloc(n_clients, sizeof(struct dsm_connection));
	pthread_attr_t attr;
	pthread_t *command_threads;
	command_thread_args* args;
	unsigned long page;
	int fds[2], custom_fd_local, custom_fd_remote; //server-parasite pipes
	int server_pipe[2], uffd_pipe[2]; 
	char line[256]; 

	FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "r");
	FILE *f_mutex = fopen("/tmp/dsm_mutex.txt", "r");
	rdma_on = rdma_enable;
	num_clients = n_clients;
	
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
	pidfd = init_pidfd(restored_pid);

	active_addr = calloc(n_clients + 1, sizeof(unsigned long));
	fault_cond  = calloc(n_clients + 1, sizeof(pthread_cond_t));
	handler_locks = calloc(n_clients, sizeof(pthread_mutex_t));
	param->fd_handler = calloc(n_clients, sizeof(int));

	if (!active_addr || !fault_cond || !handler_locks || !conn ) {
		perror("calloc");
		exit(1);
	}
	for (int i = 0; i < n_clients; i++) {
		pthread_mutex_init(&handler_locks[i], NULL);
		pthread_cond_init(&fault_cond[i], NULL);
	}
	pthread_cond_init(&fault_cond[n_clients], NULL);

 
	//pthread_create(&barrier_tid, NULL, barrier_resolver_thread, NULL);
#endif 

	if( rdma_on && !RDMA_ENABLE ) {
		PRINT("[DSM SERVER] Warning: RDMA support mismatch. Compiled with RDMA_ENABLE=%d, started with rdma_on=%d\n", RDMA_ENABLE, rdma_on);
		kill_and_exit(restored_pid);
	}

	vm_area_list_init(&vmas); // CRIU macro
	
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		perror("socketpair");
		kill_and_exit(restored_pid);
	}

	custom_fd_local = fds[0];   // for server-side use
	custom_fd_remote = fds[1];  // to be sent into parasite

	if( n_clients ) {
		for (i = 0; i < num_clients; i++) {
			if (dsm_setup_dual_connections(&conn[i]) < 0) {
				PRINT( "Failed to set up DSM connections\n\r");
				kill_and_exit(restored_pid);
			}

			param->fd_handler[i] = conn[i].fd_handler;
			
			PRINT("[DSM-CONN] [%s] handler_fd=%d command_fd=%d\n\r",
				"SERVER" , conn[i].fd_handler, conn[i].fd_command);


			PRINT("[DSM] Checking connectivity on handler connection...\n\r");
			if (dsm_connectivity_test(&conn[i], true) < 0) {
				PRINT( "[DSM] Connectivity test failed for thread %d\n\r", i);
				kill_and_exit(restored_pid);
			}
			PRINT("[DSM] Connectivity OK for node: %d ✅\n\r", i);
		}
	}


	if( rdma_on && n_clients ){ 
		#if RDMA_ENABLE 
		{
			union ibv_gid sgid;
			uint8_t sgid_idx = 0;
			/* We share the same HCA/port across all endpoints; we only need
				* to pick a non-zero GID once (for RoCE). */
			int first_gid_done = 0;
			memset(&sgid, 0, sizeof(sgid));

			endpoints = calloc(n_clients, sizeof(rdma_endpoint));
			if (!endpoints) {
				perror("calloc endpoints");
				exit(1);
			}
			

			for (int cid = 0; cid < num_clients; cid++) {
				rdma_endpoint *ep = &endpoints[cid];
				unsigned char rawbuf[sizeof(rdma_wire_all)];
				size_t k;

				/* --- init five zones (each one page) --- */
				if (rdma_context_init(&ep->handler)       ||
					rdma_context_init(&ep->receiver)      ||
					rdma_context_init(&ep->data)          ||
					rdma_context_init(&ep->handler_data)  ||
					rdma_context_init(&ep->receiver_data)) {
					PRINT( "[RDMA][SERVER] rdma_context_init failed for client %d\n\r", cid);
					kill_and_exit(restored_pid);
				}

				if (init_rdma_zone(&ep->handler,      NULL, 4096, 0) ||
					init_rdma_zone(&ep->receiver,     NULL, 4096, 0) ||
					init_rdma_zone(&ep->data,         NULL, 4096, 0) ||
					init_rdma_zone(&ep->handler_data, NULL, 4096, 0) ||
					init_rdma_zone(&ep->receiver_data,NULL, 4096, 0)) {
					PRINT( "[RDMA][SERVER] init_rdma_zone failed for client %d\n\r", cid);
					kill_and_exit(restored_pid);
				}

				/* --- GID setup (RoCE) --- */
				if (ep->data.port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
					if (!first_gid_done) {
						if (pick_valid_sgid_index(ep->data.ctx, 1, &sgid_idx, &sgid) != 0) {
							PRINT( "[RDMA] pick_valid_sgid_index failed\n\r");
							kill_and_exit(restored_pid);
						}
						first_gid_done = 1;
					}
					ep->handler.gid       = sgid;
					ep->receiver.gid      = sgid;
					ep->data.gid          = sgid;
					ep->receiver_data.gid = sgid;
					ep->handler_data.gid  = sgid;
				}

				/* --- fill per-client bundle --- */
				memset(&ep->local_all, 0, sizeof(ep->local_all));
				fill_conn_info_from_ctx(&ep->handler,
										ep->data.port_attr.lid,
										ep->handler.gid.raw,
										&ep->local_all.handler);
				fill_conn_info_from_ctx(&ep->receiver,
										ep->data.port_attr.lid,
										ep->receiver.gid.raw,
										&ep->local_all.receiver);
				fill_conn_info_from_ctx(&ep->data,
										ep->data.port_attr.lid,
										ep->data.gid.raw,
										&ep->local_all.data);
				fill_conn_info_from_ctx(&ep->receiver_data,
										ep->data.port_attr.lid,
										ep->receiver_data.gid.raw,
										&ep->local_all.receiver_data);
				fill_conn_info_from_ctx(&ep->handler_data,
										ep->data.port_attr.lid,
										ep->handler_data.gid.raw,
										&ep->local_all.handler_data);

				/* --- exchange: server SEND first on handler fd, RECV on command fd --- */
				if (writen_all_exact(conn[cid].fd_handler,
									&ep->local_all, sizeof(ep->local_all)) < 0) {
					perror("[RDMA][SERVER] send bundle");
					kill_and_exit(restored_pid);
				}
				if (readn_all_exact(conn[cid].fd_command,
									rawbuf, sizeof(rawbuf)) < 0) {
					perror("[RDMA][SERVER] recv bundle");
					kill_and_exit(restored_pid);
				}

				PRINT("[RDMA][DEBUG] SERVER[%d] read %u bytes bundle\n\r",
					cid, (unsigned)sizeof(rawbuf));
				PRINT("[RDMA][DEBUG] Raw[%d]: ", cid);
				for (k = 0; k < sizeof(rawbuf); k++)
					PRINT("%02x ", rawbuf[k]);
				PRINT("\n\r");

				memcpy(&ep->remote_all, rawbuf, sizeof(ep->remote_all));

				/* --- bring all 5 QPs to RTR/RTS --- */
				qp_to_rtr_rts(ep->handler.qp,
							&ep->handler.port_attr,
							&ep->remote_all.receiver_data,
							ep->handler.psn, sgid_idx, 1);

				qp_to_rtr_rts(ep->receiver.qp,
							&ep->receiver.port_attr,
							&ep->remote_all.handler_data,
							ep->receiver.psn, sgid_idx, 1);

				qp_to_rtr_rts(ep->handler_data.qp,
							&ep->handler_data.port_attr,
							&ep->remote_all.receiver,
							ep->handler_data.psn, sgid_idx, 1);

				qp_to_rtr_rts(ep->receiver_data.qp,
							&ep->receiver_data.port_attr,
							&ep->remote_all.handler,
							ep->receiver_data.psn, sgid_idx, 1);

				qp_to_rtr_rts(ep->data.qp,
							&ep->data.port_attr,
							&ep->remote_all.data,
							ep->data.psn, sgid_idx, 1);

				/* --- post one RECV on each zone (ready to receive from that client) --- */
				post_one_recv(&ep->handler);
				post_one_recv(&ep->receiver);
				post_one_recv(&ep->data);

				PRINT("[RDMA][SERVER] handshake complete for client %d: "
					"handler=%u receiver=%u data=%u\n\r",
					cid,
					ep->handler.qp->qp_num,
					ep->receiver.qp->qp_num,
					ep->data.qp->qp_num);
			}

			#if 0
				{
					struct ibv_wc wc;
					int got = 0;
					char *buf;

					PRINT("[SERVER] Waiting on client WRITEs…\n\r");

					// Post receives for incoming messages 
					post_one_recv(&z_handler);
					post_one_recv(&endpoints[client_id].receiver);
					post_one_recv(&z_data);

					// Wait for all 3 client WRITEs 
					while (got < 3) {
						if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
							PRINT("[SERVER] handler got: '%s'\n\r", (char*)z_handler.base_addr);
							got++;
						}
						if (ibv_poll_cq(endpoints[client_id].receiver.cq, 1, &wc) > 0) {
							PRINT("[SERVER] receiver got: '%s'\n\r", (char*)endpoints[client_id].receiver.base_addr);
							got++;
						}
						if (ibv_poll_cq(z_data.cq, 1, &wc) > 0) {
							PRINT("[SERVER] data got: '%s'\n\r", (char*)z_data.base_addr);
							got++;
						}
					}

					PRINT("[SERVER] ✅ Received all 3 client messages.\n\r");

					/* --- Now send responses back --- */
					

					/* ZONE 1: receiver_data -> client.handler */
					buf = (char*)endpoints[client_id].receiver_data.base_addr;
					strcpy(buf, "ACK_CMD");
					PRINT("[SERVER] Sending ACK_CMD to client.handler (imm=0xB1)\n\r");
					rdma_write_core(&endpoints[client_id].receiver_data,
									be64toh(endpoints[client_id].remote_all.handler.vaddr),
									ntohl(endpoints[client_id].remote_all.handler.rkey),
									buf, strlen(buf) + 1, 0xB1);
					PRINT("[SERVER] receiver_data WRITE done ✅\n\r");

					/* ZONE 2: handler_data -> client.receiver */
					buf = (char*)z_handler_data.base_addr;
					strcpy(buf, "ACK_HELLO");
					PRINT("[SERVER] Sending ACK_HELLO to client.receiver (imm=0xB2)\n\r");
					rdma_write_core(&z_handler_data,
									be64toh(endpoints[client_id].remote_all.receiver.vaddr),
									ntohl(endpoints[client_id].remote_all.receiver.rkey),
									buf, strlen(buf) + 1, 0xB2);
					PRINT("[SERVER] handler_data WRITE done ✅\n\r");

					/* Optional: respond via data channel too */
					buf = (char*)z_data.base_addr;
					strcpy(buf, "PONG");
					PRINT("[SERVER] Sending PONG to client.data (imm=0xB3)\n\r");
					rdma_write_core(&z_data,
									be64toh(endpoints[client_id].remote_all.data.vaddr),
									ntohl(endpoints[client_id].remote_all.data.rkey),
									buf, strlen(buf) + 1, 0xB3);
					PRINT("[SERVER] data WRITE done ✅\n\r");

					PRINT("[SERVER] ✅ All responses sent.\n\r");
				}				
				{
					struct ibv_wc wc;
					rdma_cmd_msg cmd;
					uint64_t tgt;

					PRINT("[SERVER] --- Waiting CMD on receiver; replying from receiver_data -> client.handler ---\n\r");

					/* 1) Wait for client's CMD on client.receiver */
					post_one_recv(&endpoints[client_id].receiver);
					poll_one_cqe(&endpoints[client_id].receiver, &wc);
					if (!(wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM))
						PRINT("[SERVER] Unexpected CQE opcode=%d\n\r", wc.opcode);

					/* 2) Parse CMD */
					memcpy(&cmd, endpoints[client_id].receiver.base_addr, sizeof(cmd));
					tgt = be64toh(cmd.target_addr);
					PRINT("[SERVER] CMD: target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
						(unsigned long long)tgt,
						(unsigned long long)be64toh(cmd.faulting_addr),
						(unsigned)ntohl(cmd.id),
						(unsigned)ntohl(cmd.index));

					
					/* 3) Prepare zero page in TX buffer (server.receiver_data MR) */
					memset(endpoints[client_id].receiver_data.base_addr, 0x00, 4096);

					/* 4) RDMA WRITE_WITH_IMM into client's handler */
					PRINT("[SERVER] Writing zero page into client.handler at %#llx\n\r",
						(unsigned long long)tgt);

					rdma_write_core(&endpoints[client_id].receiver_data,
									tgt,
									ntohl(endpoints[client_id].remote_all.handler.rkey),  /* client's handler rkey */
									endpoints[client_id].receiver_data.base_addr, 4096, 0xBEEF);

					PRINT("[SERVER] ✅ Wrote zero page into client.handler\n\r");
				}
			#endif


		}
		//kill_and_exit(restored_pid);
		#endif
	}


	local_threads = get_local_thread_count(restored_pid);
	PRINT("local threads:%d\n\r", local_threads );

	//Start infection
	uffd = 0;
	uffd = stealUFFD(restored_pid);

	if (init_userfaultfd_api(uffd) < 0) {
		PRINT( "Failed to initialize userfaultfd API\n\r");
		exit(EXIT_FAILURE);
	}
	else PRINT("Success initialize userfaultfd API\n\r");


#if VMA_REC	
	read_proc_maps(restored_pid);
	//num_remote_tids = read_all_tids(restored_pid, tids, MAX_THREADS);
#endif	


#if 0 //!EP
	base_address = get_base_address(restored_pid);
	register_all(uffd, restored_pid, base_address, &vmas, SHARED);

#endif
	
	/*RDMA INFECTION...*/
#if 0 && RDMA_ENABLE	
	register_ranges_from_file_parasite_ranged(uffd, restored_pid);
#else
	register_ranges_from_file(uffd);
#endif

	if( f ){
		if (fscanf(f, "base=%lx page_size=%zu num_pages=%d", &barrier_start_address, &page_size, &num_pages) != 3) {
			PRINT( "[dsm] failed to parse barrier info file\n\r");
		}
		fclose(f);

		
		barrier_end_address = barrier_start_address + page_size * num_pages;
		PRINT("/tmp/dsm_barrier_pages.txt: start addr:%lx, end:%lx\n\r", barrier_start_address, barrier_end_address);

		register_region_with_uffd(uffd, (void*) barrier_start_address, page_size * num_pages);
		enable_region_wp(uffd, (void*) barrier_start_address, page_size * num_pages);
	}else{
		PRINT( "[dsm] barrier info file not found, no pthread barrier support\n\r");	
	}


	if( f_mutex ){
		if (fscanf(f_mutex, "base=%lx page_size=%zu num_pages=%d\n", &mutex_lock_start_address, &page_size, &num_pages) != 3) {
			PRINT( "[dsm] failed to parse mutex info file\n\r");
		}		
		mutex_lock_end_address = mutex_lock_start_address + page_size * num_pages;
		PRINT("/tmp/dsm_mutex.txt: start addr:%lx, end:%lx\n\r", mutex_lock_start_address, mutex_lock_end_address);

		register_region_with_uffd(uffd, (void*) mutex_lock_start_address, page_size * num_pages);
		enable_region_wp(uffd, (void*) mutex_lock_start_address, page_size * num_pages);


		if (fscanf(f_mutex, "base=%lx page_size=%zu num_pages=%d", &mutex_unlock_start_address, &page_size, &num_pages) != 3) {
			PRINT( "[dsm] failed to parse mutex info file\n\r");
		}
		fclose(f_mutex);

		
		mutex_unlock_end_address = mutex_unlock_start_address + page_size * num_pages;
		PRINT("/tmp/dsm_mutex.txt: start addr:%lx, end:%lx\n\r", mutex_unlock_start_address, mutex_unlock_end_address);

		register_region_with_uffd(uffd, (void*) mutex_unlock_start_address, page_size * num_pages);
		enable_region_wp(uffd, (void*) mutex_unlock_start_address, page_size * num_pages);
	}else{
		PRINT( "[dsm] mutex info file not found, no pthread mutex support\n\r");	
	}
   

	//Creating pipes 
	if (pipe(server_pipe) == -1 || pipe(uffd_pipe) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	//Start UFFD thread
	param->uffd = uffd;               // from stealUFFD()
	param->server_pipe = server_pipe[0];    // read end for handler
	param->uffd_pipe = uffd_pipe[1];  // write end for handler
	//Spawn handler thread

#if RDMA_ENABLE
	if( rdma_on )
		pthread_create(&uffd_thread, NULL, handler_RDMA, param);
	else
#endif
		pthread_create(&uffd_thread, NULL, handler, param);
	


#if 1

	if( n_clients == 0 ){
		PRINT("[DSM Server] No clients connected. Running in single-node mode.\n\r");
		//send_sigcont(restored_pid);
	} else {
		PRINT("[DSM Server] %d clients connected. Running in multi-node mode.\n\r", n_clients);
		PRINT("[DSM Server] Connections established. Creating %d command loop threads\n\r", num_clients);
		for (int i = 0; i <= num_clients; i++) { //creating fault condition waiting for each remote node + local fault (num_clients + 1)
			active_addr[i] = 0;
			pthread_cond_init(&fault_cond[i], NULL);
		}


		command_threads = malloc(num_clients * sizeof(pthread_t));
		if (!command_threads) {
			perror("malloc (thread array)");
			exit(EXIT_FAILURE);
		}

		pthread_attr_init(&attr);
		// pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		for (int i = 0; i < num_clients; i++) {
			args = malloc(sizeof(*args));
			if (!args) {
				perror("malloc (thread args)");
				exit(EXIT_FAILURE);
			}

			args->restored_pid = restored_pid;
			args->uffd = uffd;
			args->conn = conn;   
			args->client_id = i;


			if (pthread_create(&command_threads[i], &attr, command_thread_main, args) != 0) {
				perror("pthread_create (command loop)");
				free(args);
				exit(EXIT_FAILURE);
			}

			PRINT("[DSM Server] Created command thread %d (tid=%lu)\n\r", i, command_threads[i]);
		}

		pthread_attr_destroy(&attr);



		free(command_threads);
		PRINT("[DSM Server] All command threads created and joined.\n\r");

	}

	
	
#elif COMMAND_LOOP
	PRINT("[DSM Server] Connections established. Entering command loop\n\r");
	PRINT("PAge0x:%lx Page1:0x%lx\n\r", page_thread0, page_thread1);
	command_loop(restored_pid, uffd, &conn[0]);
#elif ENABLE_SERVER
	PRINT("[DSM Server] Connections established. Entering main loop...\n\r");
    dsm_command_main_loop(conn[0].fd_command);
	//if(!DBG) send_sigcont(restored_pid);
#endif


	//Waiting for restored process to end
	{
		int ret;
		struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
		PRINT("[DSM] Waiting for restored process %d to exit...\n\r", restored_pid);

		ret = poll(&pfd, 1, -1);
		if (ret > 0 && (pfd.revents & POLLIN))
			PRINT("[DSM] Process %d exited.\n\r", restored_pid);
		end_time = time_now_us();
		PRINT("[DSM] N_clients:%d\n\r", n_clients);
		if( rdma_enable ){
			printf("RDMA MODE, NUM_CLIENTS:%d, NUM_FAULTS:%d, time:%ld us\n\r", n_clients, fault_counter, end_time - start_time);
		} else {
			printf("TCP MODE, NUM_CLIENTS:%d, NUM_FAULTS:%d, time:%ld us\n\r", n_clients, fault_counter, end_time - start_time);
		}
		close(pidfd);
	}

	if( client_fd )	close(client_fd);
	if( server_fd ) close(server_fd);
	
	//Freeing vmas
	free_mappings(&vmas); 
}
