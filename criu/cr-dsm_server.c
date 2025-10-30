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

static void *handler(void *arg) {
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


	(void) n;
	(void) ack;
	(void) dsm_msg;

	DSM_EVENT_HANDLER("[handler] started, uffd = %d\n\r", p->uffd);

	while(access("/tmp/haltcode", F_OK) != 0) {
        //spin wait for haltcode file
    }

#if !DBG && 0
	sleep(10);
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
		#if ENABLE_SERVER

			//all local threads arrived, send the message to remote 
			//RDMA BARRIER HIT
			/* 2) Build command asking server to write into OUR handler */
			my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
			cmd.target_addr   = htobe64(my_handler_addr);
			cmd.faulting_addr  = htobe64((uint64_t)addr);
			cmd.id           = htonl(MSG_BARRIER_HIT);

			DSM_EVENT_HANDLER("[SERVER] Sending rdma barrier hit: target_addr=%#llx faulting_addr=%#llx id=%u\n\r",
				(unsigned long long)be64toh(cmd.target_addr),
				(unsigned long long)be64toh(cmd.faulting_addr),
				(unsigned)ntohl(cmd.id),
				(unsigned)ntohl(cmd.index));

			/* 3) Copy CMD into TX buffer (handler_data MR) */
    		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

			//Prepare for response 
			post_one_recv(&z_handler);

			/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
			DSM_EVENT_HANDLER("[SERVER] Sending CMD to client.receiver (imm=0xCAFE)\n\r");
			rdma_write_core(&z_handler_data,
							be64toh(remote_all.receiver.vaddr),
							ntohl(remote_all.receiver.rkey),
							z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

			/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
			for (;;) {
				if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
					if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
						if (wc.wc_flags & IBV_WC_WITH_IMM)
							DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
						break;
					}
				}
			}

			//and let's see if remote threads have already arrived
			if (remote_threads_barrier_arrived == 0) {
				pthread_cond_wait(&barrier.cond, &barrier.lock);
			}

			/*Cheking if fault address match*/
			if( remote_barrier_addr != local_barrier_addr ){
				DSM_EVENT_HANDLER("Error!\n\r");
				kill_and_exit(restored_pid);
			}

			DSM_DEBUG_HANDLER("[SERVER] remote threads barrier arrived\n\r");
			//remote threads arrived, resolve fault and exit
			remote_threads_barrier_arrived = 0; //reset for next barrier
			pthread_cond_broadcast(&barrier.cond); //notify the other thread if it was waiting 

		#endif
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
			disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
			pthread_mutex_unlock(&barrier.lock);
			continue;
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
			PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n\r", addr);
			continue;
		}
		//mark_fault_start(addr, "LOCAL_HANDLER", msg.arg.pagefault.feat.ptid);

		if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
			
			DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n\r");

			//check if page is tracked and who's the owner

		#if ENABLE_SERVER
			//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
			// to make SERVER issue the drop page to all 
			dsm_msg.msg_id = index;

			/* 2) Build command asking server to write into OUR handler */
			my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
			cmd.target_addr   = htobe64(my_handler_addr);
			cmd.faulting_addr  = htobe64((uint64_t)addr);
			cmd.id           = htonl(MSG_SEND_INVALIDATE);
			cmd.index = htonl(index);

			DSM_EVENT_HANDLER("[SERVER] Sending rdma : target_addr=%#llx faulting_addr=%#llx id=%u\n\r",
				(unsigned long long)be64toh(cmd.target_addr),
				(unsigned long long)be64toh(cmd.faulting_addr),
				(unsigned)ntohl(cmd.id),
				(unsigned)ntohl(cmd.index));

			/* 3) Copy CMD into TX buffer (handler_data MR) */
    		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

			//Prepare for response 
			post_one_recv(&z_handler);

			/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
			DSM_EVENT_HANDLER("[SERVER] Sending CMD to client.receiver (imm=0xCAFE)\n\r");
			rdma_write_core(&z_handler_data,
							be64toh(remote_all.receiver.vaddr),
							ntohl(remote_all.receiver.rkey),
							z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

			/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
			for (;;) {
				if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
					if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
						if (wc.wc_flags & IBV_WC_WITH_IMM)
							DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
						break;
					}
				}
			}
			#endif
			// Now you can safely disable WP
			disable_wp(uffd, (void *)addr);
			//update_page_info(addr, 0, MODIFIED, -2);
			PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
			page_list_data[index].state = MODIFIED;	
			
		} else {
			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p\n\r", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
				copy.mode = 0; 
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
							page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;	
			} else {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p\n\r", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA;
				copy.mode = UFFDIO_COPY_MODE_WP;
				//update_page_info(addr, -1, SHARED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
							page_list_data[index].saddr, page_list_data[index].state, SHARED, index);
				page_list_data[index].state = SHARED;		
			}

			
		#if ENABLE_SERVER
			dsm_msg.msg_id = index;
			
			/* 2 Build command asking server to write into OUR handler */
			my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
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
    		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

			//Prepare for response 
			post_one_recv(&z_handler);

			/* 4) WRITE_WITH_IMM to client.receiver using that registered buffer */
			DSM_EVENT_HANDLER("[SERVER] Sending CMD to client.receiver (imm=0xCAFE)\n\r");
			rdma_write_core(&z_handler_data,
							be64toh(remote_all.receiver.vaddr),
							ntohl(remote_all.receiver.rkey),
							z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

			/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
			for (;;) {
				if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
					if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
						if (wc.wc_flags & IBV_WC_WITH_IMM )
							DSM_EVENT_HANDLER("[SERVER] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
						else{
							fprintf(stderr, "[SERVER] z_handler != MSG_GET_PAGE/GET_PAGE_INVALIDATE:%d\n\r", MSG_INVALIDATE_ACK);
							kill_and_exit(restored_pid);
						}
						break;
					}
				}
			}
			
			copy.src  = (unsigned long)z_handler.base_addr;
		#else
			copy.src  = (unsigned long)zero_page;
			DSM_EVENT_HANDLER("[handler] Creating zero page for MISSING PAGE FAULT on READ on an ALREADY SHARED PAGE (debug mode)\n\r");
		#endif
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
				fprintf(stderr, "[handler] UFFDIO_COPY semantic error %s (%d) on %lx\n\r",
						strerror(e), e, addr);
				// Optional: wake anyone waiting so they don’t hang
				r.start = addr;
				r.len = PAGE_SIZE;
				(void)ioctl(p->uffd, UFFDIO_WAKE, &r);
				kill_and_exit(restored_pid);
			} else {
				// Short copy – shouldn’t happen for anonymous pages
				fprintf(stderr, "[handler] UFFDIO_COPY short copy (%lld bytes) on %lx\n\r",
						(long long)copy.copy, addr);
				kill_and_exit(restored_pid);
			}
		}
		DSM_EVENT_HANDLER("[handler] done handling fault at 0x%lx\n\r", addr);
		//mark_fault_end(addr, "LOCAL_HANDLER", msg.arg.pagefault.feat.ptid);
		//pthread_mutex_unlock(&pagefaults_mutex);
	}

	return NULL;
}

#elif 1
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

		DSM_EVENT_HANDLER("[handler] started, uffd = %d\n\r", p->uffd);

		

	#if !DBG //&& 0
		sleep(8);
		DSM_EVENT_HANDLER("[handler] Sending SIGCONT to restored process %d\n\r", restored_pid);
		send_sigcont(restored_pid);

		/*
		dsm_msg.msg_type = MSG_WAKE_THREAD;
		send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0);
		DSM_EVENT_HANDLER("[SERVER] Sent MSG_WAKE_THREAD to server.\n\r");*/
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
	#if ENABLE_SERVER

				//all local threads arrived, send the message to remote 
				// Send BARRIER HIT
				dsm_msg.msg_type = MSG_BARRIER_HIT;
				dsm_msg.msg_id = 1001;
				dsm_msg.page_addr = msg.arg.pagefault.address;
				if (send_all(p->fd_handler[0 ], &dsm_msg, sizeof(dsm_msg)) != 0) {
					perror("[SERVER] Failed to send MSG_BARRIER_HIT");
					kill_and_exit(restored_pid);
				}else DSM_DEBUG_HANDLER("[SERVER] Sent MSG_BARRIER_HIT to client\n\r");
				//and let's see if remote threads have already arrived
				if (remote_threads_barrier_arrived == 0) {
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				/*Cheking if fault address match*/
				if( remote_barrier_addr != local_barrier_addr ){
					DSM_EVENT_HANDLER("Error!\n\r");
					//kill_and_exit(restored_pid);
				}

				DSM_DEBUG_HANDLER("[SERVER] remote threads barrier arrived\n\r");
				//remote threads arrived, resolve fault and exit
				remote_threads_barrier_arrived = 0; //reset for next barrier
				pthread_cond_broadcast(&barrier.cond); //notify the other thread if it was waiting 

	#endif
				dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
				if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
				enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
				disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
				pthread_mutex_unlock(&barrier.lock);
				continue;
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
				PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n\r", addr);
				continue;
			}
			//mark_fault_start(addr, "LOCAL_HANDLER", msg.arg.pagefault.feat.ptid);

			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
				
				DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n\r");

				//check if page is tracked and who's the owner

			#if ENABLE_SERVER
				//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
				// to make SERVER issue the drop page to all 
				dsm_msg.msg_type = MSG_SEND_INVALIDATE;
				dsm_msg.page_addr = addr;  // or any test address
				dsm_msg.page_size = 4096;
				dsm_msg.msg_id = index;

				if( dsm_msg.msg_id < 0 ){
					fprintf(stderr, "[handler] ERROR: page not found in list for address %lx\n\r", addr);
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
				DSM_EVENT_HANDLER("[SERVER] Sent MSG_SEND_INVALIDATE to server. With address:0x%lx\n\r", addr);

				switch ( all_read(p->fd_handler[0], &ack, 1) ) {
					case -2:
						fprintf(stderr, "[SERVER] Connection closed before ACK\n\r");
						kill_and_exit(restored_pid);
						break;
					case -1:
						perror("[SERVER] all_read(ACK) failed");
						kill_and_exit(restored_pid);
						break;
					case 0: 
						DSM_EVENT_HANDLER("[SERVER] Received MSG_INVALIDATE_ACK on INVALIDATION\n\r");
						break;
					default:
						perror("Unknown value for handler all_read(ACK)\n\r");
						kill_and_exit(restored_pid);
						break;
				}
			#endif

				// Now you can safely disable WP
				disable_wp(uffd, (void *)addr);
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;	
				
			} else {
				if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
					DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p\n\r", (void*)msg.arg.pagefault.address);
					dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
					copy.mode = 0; 
					//update_page_info(addr, 0, MODIFIED, -2);
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
								page_list_data[index].saddr, page_list_data[index].state, MODIFIED, index);
					page_list_data[index].state = MODIFIED;	
				} else {
					DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p\n\r", (void*)msg.arg.pagefault.address);
					dsm_msg.msg_type = MSG_GET_PAGE_DATA;
					copy.mode = UFFDIO_COPY_MODE_WP;
					//update_page_info(addr, -1, SHARED, -2);
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r",
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
						fprintf(stderr, "[handler] ERROR: page not found in list for address %lx\n\r", addr);
						kill_and_exit(restored_pid);
						//pthread_mutex_unlock(&pagefaults_mutex);
						continue;
					}

					if (send_get_page(dsm_msg, p->fd_handler[0 ], page_data) != 0) {
						fprintf(stderr, "[handler] Failed to fetch page from remote\n\r");
						kill_and_exit(restored_pid);
						continue;
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
					fprintf(stderr, "[handler] UFFDIO_COPY semantic error %s (%d) on %lx\n\r",
							strerror(e), e, addr);
					// Optional: wake anyone waiting so they don’t hang
					r.start = addr;
					r.len = PAGE_SIZE;
					(void)ioctl(p->uffd, UFFDIO_WAKE, &r);
					kill_and_exit(restored_pid);
				} else {
					// Short copy – shouldn’t happen for anonymous pages
					fprintf(stderr, "[handler] UFFDIO_COPY short copy (%lld bytes) on %lx\n\r",
							(long long)copy.copy, addr);
					kill_and_exit(restored_pid);
				}
			}
			DSM_EVENT_HANDLER("[handler] done handling fault at 0x%lx\n\r", addr);
			//mark_fault_end(addr, "LOCAL_HANDLER", msg.arg.pagefault.feat.ptid);
			//pthread_mutex_unlock(&pagefaults_mutex);
		}

		return NULL;
	}
#endif

#if RDMA_ENABLE
void dsm_command_main_loop(int fd_command) {
    struct msg_info msg;
    //ssize_t n;
	//unsigned char ack;
	
	//RDMA
	struct ibv_wc wc;
	rdma_cmd_msg cmd;
	//uint64_t tgt;
	//union ibv_gid sgid;
    //uint8_t sgid_idx;
    //unsigned char rawbuf[sizeof(rdma_wire_all)];
    //size_t i;
	//int got = 0;


	//unsigned char page_content[PAGE_SIZE];
    struct iovec local_iov, remote_iov;
    ssize_t nread;

	/* 1) Wait for client's CMD on client.receiver */
	post_one_recv(&z_receiver);

    while (1) {
        DSM_EVENT_SERVER("[SERVER] Waiting for RDMA message on z_receiver...\n\r");


		/* 1. Wait for WRITE_WITH_IMM from client */
		poll_one_cqe(&z_receiver, &wc);
		if (!(wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM)) {
			DSM_EVENT_SERVER("[SERVER] Unexpected CQE opcode=%d\n\r", wc.opcode);
		}
		memcpy(&cmd, z_receiver.base_addr, sizeof(cmd));
		DSM_EVENT_SERVER("[SERVER] Command CMD: target_addr=%#llx fault addr=%#llx id=%u, index:%u\n\r",
			(unsigned long long)be64toh(cmd.target_addr),
			(unsigned long long)be64toh(cmd.faulting_addr),
			(unsigned)ntohl(cmd.id),
			(unsigned)ntohl(cmd.index));

		msg.msg_type = ntohl(cmd.id); //abusing msg_type to store the command type
		msg.page_addr = be64toh(cmd.faulting_addr);
		msg.msg_id = ntohl(cmd.index);
		post_one_recv(&z_receiver);
        DSM_DEBUG_SERVER("[DSM Server] Received message: type=%d, addr=0x%lx, id=%ld\n\r",
               msg.msg_type, msg.page_addr, msg.msg_id);
		
		//mark_fault_start(msg.page_addr, "REMOTE_FAULT", msg.msg_id);
        switch (msg.msg_type) {
			case MSG_BARRIER_HIT:
                DSM_DEBUG_SERVER("[DSM Server] Remote barrier hit.\n\r");
				#if 1
				
				DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler (imm=0xB1)\n\r");
				rdma_write_core(&z_receiver_data,
								be64toh(remote_all.handler.vaddr),
								ntohl(remote_all.handler.rkey),
								z_receiver_data.base_addr, 0, 0xB1);
				pthread_mutex_lock(&barrier.lock);

				if( remote_threads_barrier_arrived == 1 ){
					//means that the handler thread has not process the barrier yet, let's wait until it does
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				
				// mark that remote threads have arrived, this is useful if we come before the threads 					
				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_SERVER("[DSM Server] Remote hit barrier, releasing...\n\r");
				pthread_mutex_unlock(&barrier.lock);
				#endif
				break;
			case MSG_WAKE_THREAD:
				DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler (imm=0xB1)\n\r");
				rdma_write_core(&z_receiver_data,
								be64toh(remote_all.handler.vaddr),
								ntohl(remote_all.handler.rkey),
								z_receiver_data.base_addr, 0, 0xB1);


				send_sigcont(restored_pid);
				break;
			case MSG_STOP_THREAD:
				send_sigstop(restored_pid);
				break;
			case MSG_GET_PAGE_DATA:
			case MSG_GET_PAGE_DATA_INVALID:
			
				DSM_EVENT_SERVER("→ Handling GET_PAGE_DATA/GET_PAGE_DATA_INVALID\n\r");
				PRINT("[DSM] Using process_vm_readv() to fetch remote page (pid=%d, addr=%p)\n\r",
					restored_pid, (void*)msg.page_addr);
				
				// --- Prepare iovecs ---
				local_iov.iov_base = z_receiver_data.base_addr; //RDMA 
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

				// --- Send page data to client ---
				rdma_write_core(&z_receiver_data,
								be64toh(remote_all.handler.vaddr),
								ntohl(remote_all.handler.rkey),
								z_receiver_data.base_addr, 4096, 0xB1);
					
   				PRINT("✅ Page_transfer_complete to client (addr=%p)\n\r", (void*)msg.page_addr);
				// --- Post-transfer page management ---
				if (msg.msg_type == MSG_GET_PAGE_DATA_INVALID) {
					PRINT("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n\r");
					if (run_proc_MADVISE(pidfd, restored_pid, (void*)msg.page_addr, PAGE_SIZE) == 0)
						PRINT("process_madvise to invalidate page %p\n\r", (void*)msg.page_addr);
					else{
						PRINT("❌ MADV_DONTNEED failed: %s\n\r", strerror(errno));
						kill_and_exit(restored_pid);
					}
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n\r",
						msg.page_addr, page_list_data[msg.msg_id].state, INVALID, msg.msg_id);
					page_list_data[msg.msg_id].state = INVALID;	
				} else {
					PRINT("Message is GET_PAGE_DATA → Enable WP to SHARED\n\r");
					if (enable_wp(uffd, (void*)msg.page_addr)){
						PRINT("⚠️ enable_wp failed\n\r");
						kill_and_exit(restored_pid);
					}
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n\r",
						msg.page_addr, page_list_data[msg.msg_id].state, SHARED, msg.msg_id);
					page_list_data[msg.msg_id].state = SHARED;	
				}

                break;
            case MSG_SEND_INVALIDATE:
				DSM_EVENT_SERVER("→ Handling remote RDMA invalidation request. Madvise(MADV_DONTNEED) on page at %p\n\r", (void *)msg.page_addr);
				//pthread_mutex_lock(&pagefaults_mutex);
				if (run_proc_MADVISE(pidfd, restored_pid, (void *)msg.page_addr, 4096) == 0){
					DSM_EVENT_SERVER("Successfully ran madvise on page at %p\n\r", (void *)msg.page_addr);
					
					DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler on INVALIDATE (imm=0xB1)\n\r");
					rdma_write_core(&z_receiver_data,
									be64toh(remote_all.handler.vaddr),
									ntohl(remote_all.handler.rkey),
									z_receiver_data.base_addr, 0, 0xB1);

					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n\r",	msg.page_addr, page_list_data[msg.msg_id].state, INVALID, msg.msg_id);
					page_list_data[msg.msg_id].state = INVALID;		
				}else {
					perror("run_proc_MADVISE RDMA command loop");
					kill_and_exit(restored_pid);
				} 
				//pthread_mutex_unlock(&pagefaults_mutex);
				break;

            case MSG_HANDSHAKE:
                DSM_EVENT_SERVER("[DSM Server] Test handshake message received, ignoring.\n\r");
                continue;
			
            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n\r", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
		PRINT("\n\r");
		//mark_fault_end(msg.page_addr, "REMOTE_FAULT", msg.msg_id);
    }
}
#else

	void dsm_command_main_loop(int fd_command) {
		struct msg_info msg;
		ssize_t n;
		unsigned char ack;
	

		while (1) {
			DSM_EVENT_SERVER("[DSM Server] (fd=%d) Waiting for command message...\n\r", fd_command);

			n = recv(fd_command, &msg, sizeof(msg), 0);
			if (n <= 0) {
				perror("[DSM Server] recv failed or connection closed");
				break;
			} else if (n != sizeof(msg)) {
				fprintf(stderr, "[DSM Server] Incomplete message received (got %zd bytes)\n\r", n);
				continue;
			}

			DSM_DEBUG_SERVER("[DSM Server] Received message: type=%d, addr=0x%lx, id=%ld\n\r",
				msg.msg_type, msg.page_addr, msg.msg_id);
			
			//mark_fault_start(msg.page_addr, "REMOTE_FAULT", msg.msg_id);
			switch (msg.msg_type) {
				case MSG_BARRIER_HIT:
					DSM_DEBUG_SERVER("[DSM Server] Remote barrier hit.\n\r");
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
					DSM_EVENT_SERVER("[DSM Server] Remote hit barrier, releasing...\n\r");
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
					DSM_EVENT_SERVER("→ Handling TCP GET_PAGE_DATA on status:%d\n\r", page_list_data[msg.msg_id].state);
					handle_page_data_request(restored_pid, uffd, fd_command, &msg);
					//pthread_mutex_unlock(&pagefaults_mutex);
					break;
				case MSG_GET_PAGE_DATA_INVALID:
					//pthread_mutex_lock(&pagefaults_mutex);
					DSM_EVENT_SERVER("→ Handling TCP GET_PAGE_DATA_INVALID\n\r", page_list_data[msg.msg_id].state);
					handle_page_data_request(restored_pid, uffd, fd_command, &msg);
					//pthread_mutex_unlock(&pagefaults_mutex);
					break;
				case MSG_SEND_INVALIDATE:
					DSM_EVENT_SERVER("→ Handling TCP invalidation request. Madvise(MADV_DONTNEED) on page at %p\n\r", (void *)msg.page_addr);
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
						page_list_data[msg.msg_id].state = INVALID;		
					}else {
						perror("runMADVISE TCP command loop");
						kill_and_exit(restored_pid);
					}  
					//pthread_mutex_unlock(&pagefaults_mutex);
					break;

				case MSG_HANDSHAKE:
					DSM_EVENT_SERVER("[DSM Server] Test handshake message received, ignoring.\n\r");
					continue;
				
				default:
					fprintf(stderr, "⚠️ Unknown message type: %d\n\r", msg.msg_type);
					kill_and_exit(restored_pid);  // shutdown the server on protocol error
					break;
			}
			PRINT("\n\r");
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
	pthread_t uffd_thread; //, barrier_tid;
	struct thread_param param;
	unsigned long base_address;
	size_t page_size;

#if ENABLE_SERVER
	struct dsm_connection conn[NUM_THREADS];
#endif

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
	char line[256]; 

	FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "r");
#if RDMA_ENABLE && 0
	struct ibv_port_attr port_attr = {};
	union ibv_gid gid;	
	ssize_t n;
#endif

	
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
	for (i = 0; i < NUM_THREADS; i++) {
		if (dsm_setup_dual_connections(&conn[i]) < 0) {
			fprintf(stderr, "Failed to set up DSM connections\n\r");
			kill_and_exit(restored_pid);
		}

		param.fd_handler[i] = conn[i].fd_handler;
		
		printf("[DSM-CONN] [%s] handler_fd=%d command_fd=%d\n\r",
      		 "SERVER" , conn[i].fd_handler, conn[i].fd_command);


		PRINT("[DSM] Checking connectivity on handler connection...\n\r");
		if (dsm_connectivity_test(&conn[i], true) < 0) {
			fprintf(stderr, "[DSM] Connectivity test failed for thread %d\n\r", i);
			kill_and_exit(restored_pid);
		}
		PRINT("[DSM] Connectivity OK for node: %d ✅\n\r", i);
	}
#endif


#if RDMA_ENABLE
{
    union ibv_gid sgid;
    uint8_t sgid_idx;
    unsigned char rawbuf[sizeof(rdma_wire_all)];
    size_t i;

    /* --- init three zones (each one page) --- */
    if (rdma_context_init(&z_handler)  ||
		rdma_context_init(&z_handler_data)  ||
		rdma_context_init(&z_receiver_data)  ||
        rdma_context_init(&z_receiver) ||
        rdma_context_init(&z_data)) {
        fprintf(stderr, "[RDMA][SERVER] rdma_context_init failed\n\r");
        kill_and_exit(restored_pid);
    }

    if (init_rdma_zone(&z_handler,  NULL, 4096, 0) ||
        init_rdma_zone(&z_receiver, NULL, 4096, 0) ||
		init_rdma_zone(&z_handler_data,  NULL, 4096, 0) ||
        init_rdma_zone(&z_receiver_data, NULL, 4096, 0) ||
        init_rdma_zone(&z_data,     NULL, 4096, 0)) {
        fprintf(stderr, "[RDMA][SERVER] init_rdma_zone failed\n\r");
        kill_and_exit(restored_pid);
    }

    sgid_idx = 0;
    memset(&sgid, 0, sizeof(sgid));
    if (z_data.port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
        if (pick_valid_sgid_index(z_data.ctx, 1, &sgid_idx, &sgid) != 0) {
            fprintf(stderr, "[RDMA] pick_valid_sgid_index failed\n\r");
            kill_and_exit(restored_pid);
        }
        z_handler.gid  = sgid;
        z_receiver.gid = sgid;
        z_data.gid     = sgid;
		z_receiver_data.gid = sgid;
		z_handler_data.gid  = sgid;
    }

    /* --- fill bundle --- */
    memset(&local_all, 0, sizeof(local_all));
    fill_conn_info_from_ctx(&z_handler,  		z_data.port_attr.lid, z_handler.gid.raw, 		&local_all.handler);
    fill_conn_info_from_ctx(&z_receiver, 		z_data.port_attr.lid, z_receiver.gid.raw,		&local_all.receiver);
    fill_conn_info_from_ctx(&z_data,     		z_data.port_attr.lid, z_data.gid.raw,     		&local_all.data);
	fill_conn_info_from_ctx(&z_receiver_data,	z_data.port_attr.lid, z_receiver_data.gid.raw,  &local_all.receiver_data);
	fill_conn_info_from_ctx(&z_handler_data,    z_data.port_attr.lid, z_handler_data.gid.raw,   &local_all.handler_data);
	
    /* --- exchange: server SEND first on handler fd, RECV on command fd --- */
    if (writen_all_exact(conn[0].fd_handler, &local_all, sizeof(local_all)) < 0) {
        perror("[RDMA][SERVER] send bundle"); kill_and_exit(restored_pid);
    }
    if (readn_all_exact(conn[0].fd_command, rawbuf, sizeof(rawbuf)) < 0) {
        perror("[RDMA][SERVER] recv bundle"); kill_and_exit(restored_pid);
    }
    printf("[RDMA][DEBUG] SERVER read %u bytes bundle\n\r", (unsigned)sizeof(rawbuf));
    printf("[RDMA][DEBUG] Raw: ");
    for (i=0;i<sizeof(rawbuf);i++) printf("%02x ", rawbuf[i]); 
	printf("\n\r");
    memcpy(&remote_all, rawbuf, sizeof(remote_all));

    /* --- bring all 5 QPs to RTR/RTS --- */
    qp_to_rtr_rts(z_handler.qp,       &z_handler.port_attr,       &remote_all.receiver_data,  z_handler.psn,       sgid_idx, 1);
	qp_to_rtr_rts(z_receiver.qp,      &z_receiver.port_attr,      &remote_all.handler_data,   z_receiver.psn,      sgid_idx, 1);
	qp_to_rtr_rts(z_handler_data.qp,  &z_handler_data.port_attr,  &remote_all.receiver,       z_handler_data.psn,  sgid_idx, 1);
	qp_to_rtr_rts(z_receiver_data.qp, &z_receiver_data.port_attr, &remote_all.handler,        z_receiver_data.psn, sgid_idx, 1);
	qp_to_rtr_rts(z_data.qp,          &z_data.port_attr,          &remote_all.data,           z_data.psn,          sgid_idx, 1);

    /* --- post one RECV on each zone (so we’re ready to receive on any) --- */
    post_one_recv(&z_handler);
    post_one_recv(&z_receiver);
    post_one_recv(&z_data);

    printf("[RDMA][SERVER] triple handshake complete: handler=%u receiver=%u data=%u\n\r",
        z_handler.qp->qp_num, z_receiver.qp->qp_num, z_data.qp->qp_num);


	{
		struct ibv_wc wc;
		int got = 0;
		char *buf;

		printf("[SERVER] Waiting on client WRITEs…\n\r");

		/* Post receives for incoming messages */
		post_one_recv(&z_handler);
		post_one_recv(&z_receiver);
		post_one_recv(&z_data);

		/* Wait for all 3 client WRITEs */
		while (got < 3) {
			if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
				printf("[SERVER] handler got: '%s'\n\r", (char*)z_handler.base_addr);
				got++;
			}
			if (ibv_poll_cq(z_receiver.cq, 1, &wc) > 0) {
				printf("[SERVER] receiver got: '%s'\n\r", (char*)z_receiver.base_addr);
				got++;
			}
			if (ibv_poll_cq(z_data.cq, 1, &wc) > 0) {
				printf("[SERVER] data got: '%s'\n\r", (char*)z_data.base_addr);
				got++;
			}
		}

		printf("[SERVER] ✅ Received all 3 client messages.\n\r");

		/* --- Now send responses back --- */
		

		/* ZONE 1: receiver_data -> client.handler */
		buf = (char*)z_receiver_data.base_addr;
		strcpy(buf, "ACK_CMD");
		printf("[SERVER] Sending ACK_CMD to client.handler (imm=0xB1)\n\r");
		rdma_write_core(&z_receiver_data,
						be64toh(remote_all.handler.vaddr),
						ntohl(remote_all.handler.rkey),
						buf, strlen(buf) + 1, 0xB1);
		printf("[SERVER] receiver_data WRITE done ✅\n\r");

		/* ZONE 2: handler_data -> client.receiver */
		buf = (char*)z_handler_data.base_addr;
		strcpy(buf, "ACK_HELLO");
		printf("[SERVER] Sending ACK_HELLO to client.receiver (imm=0xB2)\n\r");
		rdma_write_core(&z_handler_data,
						be64toh(remote_all.receiver.vaddr),
						ntohl(remote_all.receiver.rkey),
						buf, strlen(buf) + 1, 0xB2);
		printf("[SERVER] handler_data WRITE done ✅\n\r");

		/* Optional: respond via data channel too */
		buf = (char*)z_data.base_addr;
		strcpy(buf, "PONG");
		printf("[SERVER] Sending PONG to client.data (imm=0xB3)\n\r");
		rdma_write_core(&z_data,
						be64toh(remote_all.data.vaddr),
						ntohl(remote_all.data.rkey),
						buf, strlen(buf) + 1, 0xB3);
		printf("[SERVER] data WRITE done ✅\n\r");

		printf("[SERVER] ✅ All responses sent.\n\r");
	}


	
	{
		struct ibv_wc wc;
		rdma_cmd_msg cmd;
		uint64_t tgt;

		printf("[SERVER] --- Waiting CMD on receiver; replying from receiver_data -> client.handler ---\n\r");

		/* 1) Wait for client's CMD on client.receiver */
		post_one_recv(&z_receiver);
		poll_one_cqe(&z_receiver, &wc);
		if (!(wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM))
			printf("[SERVER] Unexpected CQE opcode=%d\n\r", wc.opcode);

		/* 2) Parse CMD */
		memcpy(&cmd, z_receiver.base_addr, sizeof(cmd));
		tgt = be64toh(cmd.target_addr);
		printf("[SERVER] CMD: target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
			(unsigned long long)tgt,
			(unsigned long long)be64toh(cmd.faulting_addr),
			(unsigned)ntohl(cmd.id),
			(unsigned)ntohl(cmd.index));

		
		/* 3) Prepare zero page in TX buffer (server.receiver_data MR) */
		memset(z_receiver_data.base_addr, 0x00, 4096);

		/* 4) RDMA WRITE_WITH_IMM into client's handler */
		printf("[SERVER] Writing zero page into client.handler at %#llx\n\r",
			(unsigned long long)tgt);

		rdma_write_core(&z_receiver_data,
						tgt,
						ntohl(remote_all.handler.rkey),  /* client's handler rkey */
						z_receiver_data.base_addr, 4096, 0xBEEF);

		printf("[SERVER] ✅ Wrote zero page into client.handler\n\r");
	}



}

//kill_and_exit(restored_pid);

#elif 0
{
    rdma_context ctx;
    rdma_wire_info local;
    rdma_wire_info remote;
    struct ibv_wc wc;
    uint8_t sgid_idx;
    union ibv_gid sgid;
    unsigned char rawbuf[sizeof(rdma_wire_info)];
    uint32_t peer_qp, peer_psn, peer_rkey;
    uint16_t peer_lid;
    uint64_t peer_addr;
    int gid_zero;
    size_t i;

    /* --- init context --- */
    if (rdma_context_init(&ctx) != 0) {
        fprintf(stderr, "[RDMA][SERVER] rdma_context_init failed\n\r");
        kill_and_exit(restored_pid);
    }
    printf("[DSM][RDMA][SERVER] qp=%u base=%p rkey=0x%x\n\r",
           ctx.qp->qp_num, ctx.base_addr, ctx.rkey);

    /* --- choose SGID (RoCE) --- */
    sgid_idx = 0;
    memset(&sgid, 0, sizeof(sgid));
    if (ctx.port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
        const char *e = getenv("ROCE_GID_INDEX");
        int tmp;
        if (e) {
            tmp = atoi(e);
            if (ibv_query_gid(ctx.ctx, 1, tmp, &sgid) == 0 &&
                !((((uint64_t*)sgid.raw)[0] == 0) && (((uint64_t*)sgid.raw)[1] == 0))) {
                sgid_idx = (uint8_t)tmp;
            } else {
                fprintf(stderr, "[RDMA] ROCE_GID_INDEX=%d invalid/zero — auto-pick\n\r", tmp);
                pick_valid_sgid_index(ctx.ctx, 1, &sgid_idx, &sgid);
            }
        } else {
            pick_valid_sgid_index(ctx.ctx, 1, &sgid_idx, &sgid);
        }
        memcpy(&ctx.gid, &sgid, sizeof(sgid));
    }

    /* --- fill + SEND our wire info (handler) --- */
    memset(&local, 0, sizeof(local));
    local.qp_num = htonl(ctx.qp->qp_num);
    local.lid    = htons(ctx.port_attr.lid);
    memcpy(local.gid, ctx.gid.raw, 16);
    local.psn    = htonl(ctx.psn);
    local.rkey   = htonl(ctx.rkey);
    local.vaddr  = htobe64((uint64_t)(uintptr_t)ctx.base_addr);

    printf("[RDMA] sizeof(rdma_wire_info)=%u\n\r", (unsigned)sizeof(rdma_wire_info));
    if (writen_all_exact(conn[0].fd_handler, &local, sizeof(local)) < 0) {
        perror("[RDMA][SERVER] send wire info");
        kill_and_exit(restored_pid);
    }

    /* --- RECV peer wire info (command) + dump --- */
    if (readn_all_exact(conn[0].fd_command, rawbuf, sizeof(rawbuf)) < 0) {
        perror("[RDMA][SERVER] recv wire info");
        kill_and_exit(restored_pid);
    }
    printf("[RDMA][DEBUG] SERVER TCP read %u bytes for remote wire info\n\r", (unsigned)sizeof(rawbuf));
    printf("[RDMA][DEBUG] Raw bytes: ");
    for (i = 0; i < sizeof(rawbuf); i++) printf("%02x ", rawbuf[i]); 
	printf("\n\r");
    memcpy(&remote, rawbuf, sizeof(remote));

    /* --- decode/validate peer --- */
    peer_qp   = ntohl(remote.qp_num);
    peer_lid  = ntohs(remote.lid);
    peer_psn  = ntohl(remote.psn);
    peer_rkey = ntohl(remote.rkey);
    peer_addr = be64toh(remote.vaddr);
    gid_zero  = 1;
    for (i = 0; i < 16; i++) if (remote.gid[i] != 0) { gid_zero = 0; break; }

    printf("[RDMA] link_layer=%s active_mtu=%u local_qp=%u\n\r",
           (ctx.port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND) ? "IB" : "ETH",
           (unsigned)ctx.port_attr.active_mtu, ctx.qp->qp_num);
    printf("[RDMA] LOCAL  lid=0x%04x gid[0..5]=%02x:%02x:%02x:%02x:%02x:%02x sgid_idx=%u\n\r",
           (unsigned)ctx.port_attr.lid,
           ctx.gid.raw[0], ctx.gid.raw[1], ctx.gid.raw[2],
           ctx.gid.raw[3], ctx.gid.raw[4], ctx.gid.raw[5],
           (unsigned)sgid_idx);
    printf("[RDMA] REMOTE qp=%u lid=0x%04x psn=0x%06x raddr=0x%llx rkey=0x%x gid[0..5]=%02x:%02x:%02x:%02x:%02x:%02x\n\r",
           (unsigned)peer_qp, (unsigned)peer_lid, (unsigned)peer_psn,
           (unsigned long long)peer_addr, (unsigned)peer_rkey,
           remote.gid[0], remote.gid[1], remote.gid[2],
           remote.gid[3], remote.gid[4], remote.gid[5]);

    if (ctx.port_attr.link_layer == IBV_LINK_LAYER_ETHERNET && gid_zero) {
        fprintf(stderr, "[RDMA][SERVER] BAD REMOTE: zero GID on RoCE\n\r");
        kill_and_exit(restored_pid);
    }

    /* --- move to RTR/RTS (PSN-correct) --- */
    qp_to_rtr_rts(ctx.qp, &ctx.port_attr, &remote, ctx.psn, sgid_idx, 1);

    /* --- wait HELLO (WRITE_WITH_IMM) --- */
    post_one_recv(&ctx);
    printf("[SERVER] Waiting for HELLO...\n\r");
    poll_one_cqe(&ctx, &wc);
    printf("[SERVER] CQE opcode=%d flags=0x%x\n\r", wc.opcode, wc.wc_flags);
    if (wc.wc_flags & IBV_WC_WITH_IMM) printf("[SERVER] RX imm=0x%x\n\r", ntohl(wc.imm_data));
    printf("[SERVER] Received data='%s'\n\r", (char*)ctx.base_addr);

    /* --- reply WORLD --- */
    strcpy((char*)ctx.base_addr, "WORLD");
    printf("[SERVER] Sending WORLD via WRITE_WITH_IMM (imm=0xBEEF)\n\r");
    rdma_write_core(&ctx, peer_addr, peer_rkey, ctx.base_addr, (size_t)(strlen("WORLD")+1), 0xBEEF);

    rdma_cleanup(&ctx);
}


#endif



	local_threads = get_local_thread_count(restored_pid);
	PRINT("local threads:%d\n\r", local_threads );

	//Start infection
	uffd = 0;
	uffd = stealUFFD(restored_pid);

	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n\r");
		exit(EXIT_FAILURE);
	}
	else PRINT("Success initialize userfaultfd API\n\r");


#if VMA_REC	
	read_proc_maps(restored_pid);
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
			fprintf(stderr, "[dsm] failed to parse barrier info file\n\r");
		}
		fclose(f);

		
		barrier_end_address = barrier_start_address + page_size * num_pages;
		PRINT("/tmp/dsm_barrier_pages.txt: start addr:%lx, end:%lx\n\r", barrier_start_address, barrier_end_address);

		register_region_with_uffd(uffd, (void*) barrier_start_address, page_size * num_pages);
		enable_region_wp(uffd, (void*) barrier_start_address, page_size * num_pages);
	}else{
		fprintf(stderr, "[dsm] barrier info file not found, no pthread barrier support\n\r");	
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
	PRINT("[DSM Server] Connections established. Creating thread for command loop\n\r");

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

	PRINT("[DSM Server] After creating thread. Entering main loop...\n\r");
	#if ENABLE_SERVER
    dsm_command_main_loop(conn[0].fd_command);
	#endif
#elif COMMAND_LOOP
	PRINT("[DSM Server] Connections established. Entering command loop\n\r");
	printf("PAge0x:%lx Page1:0x%lx\n\r", page_thread0, page_thread1);
	command_loop(restored_pid, uffd, &conn[0]);
#elif ENABLE_SERVER
	PRINT("[DSM Server] Connections established. Entering main loop...\n\r");
    dsm_command_main_loop(conn[0].fd_command);
	//if(!DBG) send_sigcont(restored_pid);
#endif




	{
		int ret;
		struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
		printf("[DSM] Waiting for restored process %d to exit...\n\r", restored_pid);

		ret = poll(&pfd, 1, -1);
		if (ret > 0 && (pfd.revents & POLLIN))
			printf("[DSM] Process %d exited.\n\r", restored_pid);

		close(pidfd);
	}

	if( client_fd )	close(client_fd);
	if( server_fd ) close(server_fd);
	
	//Freeing vmas
	free_mappings(&vmas); 
}
