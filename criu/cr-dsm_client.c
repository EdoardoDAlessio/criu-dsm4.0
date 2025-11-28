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
/***************** END INFECTION HEADERS ************************/

/***************** USERFAULTFD HEADERS ************************/
#include <sys/types.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>	

//#include "user.h"
#include "page.h" //this takes the page size
// Setup global variable address 
extern unsigned long global_addr;
extern unsigned long aligned;
/***************** END USERFAULTFD HEADERS ************************/

// Setup global variable address 
extern unsigned long global_addr;
extern unsigned long aligned;
int total_threads = 2; //total threads (local + remote)
//Special PTHREAD traps DSM 
struct dsm_connection conn;
#include "dsm.h"
#include "dsm_log.h"
#include <stdbool.h>
#include <time.h>


int tids[MAX_THREADS];
int num_remote_tids;
#include <dirent.h>
#include <ctype.h>

int read_all_tids(int pid, int *tids, int max_tids)
{
    char path[256];
	 int n = 0;
    struct dirent *entry;

	DIR *dir ;
    snprintf(path, sizeof(path), "/proc/%d/task", pid);

    dir = opendir(path);
    if (!dir) return -1;

   
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR) {
            if (isdigit(entry->d_name[0])) {
                if (n < max_tids)
                    tids[n++] = atoi(entry->d_name);
            }
        }
    }

    closedir(dir);
    return n;  // number of tids
}


#if !RDMA_ENABLE 
	static void *handler(void *arg) {
		struct thread_param *p = arg;
		struct uffd_msg msg;
		struct msg_info dsm_msg;
		struct pollfd pollfd[1] = {
			{ .fd = p->uffd, .events = POLLIN }
		};
		unsigned long addr;
		unsigned char ack = 0;
		#if ENABLE_SERVER
		unsigned char page_data[PAGE_SIZE] = {0}; 
		#endif
		struct uffdio_copy copy;
		int index;
		struct uffdio_range r;
		size_t n;
		//int e;
		//uintptr_t next;

		(void) n;
		DSM_EVENT_HANDLER("[handler] started, uffd = %d\n\r", p->uffd);

		
		//dsm_msg.msg_type = MSG_WAKE_THREAD;
		//send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0);
		//printf("[CLIENT] Sent MSG_WAKE_THREAD to server.\n\r");
	#if !DBG //&& 0
		sleep(10);
		DSM_EVENT_HANDLER("[handler] Sending SIGCONT to restored process %d\n\r", restored_pid);
		send_sigcont(restored_pid);		/*dsm_msg.msg_type = MSG_WAKE_THREAD;
		send(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg), 0);
		printf("[CLIENT] Sent MSG_WAKE_THREAD to server.\n\r");*/
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
			DSM_DEBUG_HANDLER("[handler] page fault at 0x%llx, (flags: %llx), thread:%d\n\r", msg.arg.pagefault.address, msg.arg.pagefault.flags, msg.arg.pagefault.feat.ptid);

			if( msg.arg.pagefault.address >= barrier_start_address && msg.arg.pagefault.address < barrier_end_address){
				
				pthread_mutex_lock(&barrier.lock);
				#if 1
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
				}else DSM_DEBUG_HANDLER("[CLIENT] Sent MSG_BARRIER_HIT to server\n\r");
				
				//and let's see if remote threads have already arrived
				if (remote_threads_barrier_arrived == 0) {
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}
				/*Cheking if fault address match*/
				if( remote_barrier_addr != local_barrier_addr ){
					printf("Error!\n\r");
					//kill_and_exit(restored_pid);
				}

				DSM_DEBUG_HANDLER("[CLIENT] remote threads barrier arrived\n\r");
				//remote threads arrived, resolve fault and exit
				remote_threads_barrier_arrived = 0; //reset for next barrier
				pthread_cond_broadcast(&barrier.cond);

				dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
				if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
				enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
				disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
				pthread_mutex_unlock(&barrier.lock);
				#else
				e = barrier.epoch;
				barrier.local_barrier_addr = addr;
				pthread_mutex_unlock(&barrier.lock);

				// Rep-only notify? If yes, gate this with is_rep()
				dsm_msg.msg_type = MSG_BARRIER_HIT;
				dsm_msg.msg_id   = 1001;
				dsm_msg.page_addr = addr;
				if (send_all(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg)) != 0) {
					perror("[CLIENT] send MSG_BARRIER_HIT");
					kill_and_exit(restored_pid);
				}

				// Now wait for release of *this* epoch
				pthread_mutex_lock(&barrier.lock);
				while (barrier.released_epoch != e) {
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				// advance epoch for next barrier locally (rep or all—pick one policy; usually rep)
				barrier.epoch++;
				// (released_epoch will be set by server receiver on next round)

				next = addr + PAGE_SIZE;
				if (next >= barrier_end_address) next = barrier_start_address;
				pthread_mutex_unlock(&barrier.lock);

				enable_wp(uffd, (void*)next);
				disable_wp(uffd, (void*)addr);
				#endif
				continue;
			}

			else if (msg.arg.pagefault.address >= mutex_lock_start_address && msg.arg.pagefault.address < mutex_lock_end_address) {

				dsm_msg.msg_type = MSG_LOCK_REQUEST;
								
				// Send invalidate request
				if (send_all(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg)) != 0) {
					perror("[CLIENT] Failed to send MSG_LOCK_REQUEST");
					return NULL;
				}
				DSM_EVENT_HANDLER("[CLIENT] Sent MSG_LOCK_REQUEST to server. With address:0x%lx\n\r", msg.arg.pagefault.address);

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
						DSM_EVENT_HANDLER("[CLIENT] Lock granted! \n\r");
						break;
					default:
						perror("Unknown value for handler all_read(ACK)\n\r");
						kill_and_exit(restored_pid);
						break;
				}

				/* At this point, this thread owns the lock. Resolve the fault. */

				dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
				if (dsm_msg.page_addr >= mutex_lock_end_address) {
					dsm_msg.page_addr = mutex_lock_start_address;
				}

				enable_wp(uffd, (void *)dsm_msg.page_addr);              /* enable next lock page */
				disable_wp(uffd, (void *)msg.arg.pagefault.address);     /* unlock current page */

				continue;
			}	

		/* Local UNLOCK via page fault */
		if (msg.arg.pagefault.address >= mutex_unlock_start_address && msg.arg.pagefault.address <  mutex_unlock_end_address) {

			dsm_msg.msg_type = MSG_UNLOCK;
							
			// Send invalidate request
			if (send_all(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg)) != 0) {
				perror("[CLIENT] Failed to send MSG_UNLOCK");
				return NULL;
			}
			DSM_EVENT_HANDLER("[CLIENT] Sent MSG_UNLOCK to server. With address:0x%lx\n\r", msg.arg.pagefault.address);


			/* Move write-protect to next unlock page (if you’re rotating them) */
			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if (dsm_msg.page_addr >= mutex_unlock_end_address) {
				dsm_msg.page_addr = mutex_unlock_start_address;
			}

			enable_wp(uffd, (void *)dsm_msg.page_addr);
			disable_wp(uffd, (void *)msg.arg.pagefault.address);

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
				PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n\r", addr);
				continue;
			}

			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
				DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n\r");
				//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
				// to make SERVER issue the drop page to all 
				dsm_msg.msg_type = MSG_SEND_INVALIDATE;
				dsm_msg.page_addr = addr; 
				dsm_msg.page_size = 4096;

				dsm_msg.msg_id = get_list_page_index(addr);
				if( dsm_msg.msg_id < 0 ){
					fprintf(stderr, "[handler] ERROR: page not found in list for address %lx\n\r", addr);
					exit(-1);
					//pthread_mutex_unlock(&pagefaults_mutex);
					continue;
				}
				
				// Send invalidate request
				if (send_all(p->fd_handler[0], &dsm_msg, sizeof(dsm_msg)) != 0) {
					perror("[CLIENT] Failed to send MSG_SEND_INVALIDATE");
					return NULL;
				}
				DSM_EVENT_HANDLER("[CLIENT] Sent MSG_SEND_INVALIDATE to server. With address:0x%lx\n\r", addr);

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

				// Now you can safely disable WP
				disable_wp(uffd, (void *)addr);
				//update_page_info(addr, 0, MODIFIED, -2);
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", addr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;	
			} else {
				if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
					DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p\n\r", (void*)msg.arg.pagefault.address);
					dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
					copy.mode = 0; 
					//update_page_info(addr, 0, MODIFIED, -2);
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", addr, page_list_data[index].state, MODIFIED, index);
					page_list_data[index].state = MODIFIED;
				} else {
					DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p\n\r", (void*)msg.arg.pagefault.address);
					dsm_msg.msg_type = MSG_GET_PAGE_DATA;
					copy.mode = UFFDIO_COPY_MODE_WP;
					//update_page_info(addr, -1, SHARED, -2);
					PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", addr, page_list_data[index].state, SHARED, index);
					page_list_data[index].state = SHARED;
				}

	#if ENABLE_SERVER

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
	#else
				copy.src  = (unsigned long)zero_page;
				DSM_EVENT_HANDLER("[handler] Creating zero page for MISSING PAGE FAULT on READ on an ALREADY SHARED PAGE (debug mode)\n\r");
	#endif
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

			//pthread_mutex_unlock(&pagefaults_mutex);
		}

		return NULL;
	}
#else 
static void *handler(void *arg) {
    struct thread_param *p = arg;
    struct uffd_msg msg;
	struct msg_info dsm_msg;
    struct pollfd pollfd[1] = {
        { .fd = p->uffd, .events = POLLIN }
    };
	unsigned long addr;
	//unsigned char ack = 0;
	#if ENABLE_SERVER && !RDMA_ENABLE
	unsigned char page_data[PAGE_SIZE] = {0}; 
	#endif
	struct uffdio_copy copy;
	int index;
	struct uffdio_range r;
	
	struct ibv_wc wc;
	rdma_cmd_msg cmd; /* temporary on stack, but we will copy it into MR */
	uint64_t my_handler_addr;
	
    //union ibv_gid sgid;
    //uint8_t sgid_idx;
    //unsigned char rawbuf[sizeof(rdma_wire_all)];
    //size_t i;
    //rdma_cmd_msg cmd; /* temporary on stack, but we will copy it into MR */
    //uint64_t my_data_addr;

    DSM_EVENT_HANDLER("[handler] started, uffd = %d\n\r", p->uffd);

	while(access("/tmp/haltcode", F_OK) != 0) {
        //spin wait for haltcode file
    }
	
	
#if !DBG 
	sleep(5);
	DSM_EVENT_HANDLER("[handler] Sending SIGCONT to restored process %d\n\r", restored_pid);
	send_sigcont(restored_pid);

	/* 2) Build command asking server to write into OUR handler */
	my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
	cmd.target_addr   = htobe64(my_handler_addr);
	cmd.faulting_addr  = htobe64((uint64_t)0xDEADBEEF);
	cmd.id           = htonl(MSG_WAKE_THREAD);

	DSM_EVENT_HANDLER("[CLIENT] Sending rdma barrier hit: target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
		(unsigned long long)be64toh(cmd.target_addr),
		(unsigned long long)be64toh(cmd.faulting_addr),
		(unsigned)ntohl(cmd.id),
		(unsigned)ntohl(cmd.index));

	/* 3) Copy CMD into TX buffer (handler_data MR) */
	memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

	//Prepare for response 
	post_one_recv(&z_handler);

	/* 4) WRITE_WITH_IMM to server.receiver using that registered buffer */
	DSM_EVENT_HANDLER("[CLIENT] Sending CMD to server.receiver (imm=0xCAFE)\n\r");
	rdma_write_core(&z_handler_data,
					be64toh(remote_all.receiver.vaddr),
					ntohl(remote_all.receiver.rkey),
					z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

	/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
	for (;;) {
		if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
			if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
				if (wc.wc_flags & IBV_WC_WITH_IMM)
					DSM_EVENT_HANDLER("[CLIENT] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
				break;
			}
		}
	}


	//dsm_msg.msg_type = MSG_WAKE_THREAD;
	DSM_EVENT_HANDLER("[CLIENT] Sent MSG_WAKE_THREAD to server.\n\r");
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
        DSM_DEBUG_HANDLER("[handler] page fault at 0x%llx, (flags: %llx), thread:%d\n\r", msg.arg.pagefault.address, msg.arg.pagefault.flags, msg.arg.pagefault.feat.ptid);

		if( msg.arg.pagefault.address >= barrier_start_address && msg.arg.pagefault.address < barrier_end_address){
			
			pthread_mutex_lock(&barrier.lock);

			DSM_EVENT_HANDLER("[barrier] Local barrier hit: tid=%d page=%p", msg.arg.pagefault.feat.ptid, (void*)msg.arg.pagefault.address);
			local_barrier_addr = msg.arg.pagefault.address;
			//all local threads arrived, send the message to remote 
			//RDMA BARRIER HIT
			/* 2) Build command asking server to write into OUR handler */
			my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
			cmd.target_addr   = htobe64(my_handler_addr);
			cmd.faulting_addr  = htobe64((uint64_t)addr);
			cmd.id           = htonl(MSG_BARRIER_HIT);

			DSM_EVENT_HANDLER("[CLIENT] Sending rdma barrier hit: target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
				(unsigned long long)be64toh(cmd.target_addr),
				(unsigned long long)be64toh(cmd.faulting_addr),
				(unsigned)ntohl(cmd.id),
				(unsigned)ntohl(cmd.index));

			/* 3) Copy CMD into TX buffer (handler_data MR) */
    		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

			//Prepare for response 
			post_one_recv(&z_handler);

			/* 4) WRITE_WITH_IMM to server.receiver using that registered buffer */
			DSM_EVENT_HANDLER("[CLIENT] Sending CMD to server.receiver (imm=0xCAFE)\n\r");
			rdma_write_core(&z_handler_data,
							be64toh(remote_all.receiver.vaddr),
							ntohl(remote_all.receiver.rkey),
							z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

			/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
			for (;;) {
				if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
					if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
						if (wc.wc_flags & IBV_WC_WITH_IMM)
							DSM_EVENT_HANDLER("[CLIENT] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
						break;
					}
				}
			}
			
			//And let's see if remote threads have already arrived
			if (remote_threads_barrier_arrived == 0) {
				pthread_cond_wait(&barrier.cond, &barrier.lock);
			}
			/*Cheking if fault address match*/
			if( remote_barrier_addr != local_barrier_addr ){
				DSM_EVENT_HANDLER(" remote_barrier_addr != local_barrier_addr !\n\r");
				kill_and_exit(restored_pid);
			}

			DSM_DEBUG_HANDLER("[CLIENT] remote threads barrier arrived\n\r");
			//remote threads arrived, resolve fault and exit
			remote_threads_barrier_arrived = 0; //reset for next barrier
			pthread_cond_broadcast(&barrier.cond);

			dsm_msg.page_addr = msg.arg.pagefault.address + PAGE_SIZE;
			if( dsm_msg.page_addr >= barrier_end_address ) dsm_msg.page_addr = barrier_start_address;// + dsm_msg.page_addr - barrier_end_address;
			enable_wp(uffd, (void*) dsm_msg.page_addr ); //enable next
			disable_wp(uffd, (void*) msg.arg.pagefault.address); //disable current
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
			PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n\r", addr);
			continue;
		}

        if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
            DSM_DEBUG_HANDLER("[handler] WRITE-PROTECT fault on page\n\r");
			//When I get WP fault it means we were in SHARED so MSG_SEND_INVALIDATE 
			// to make SERVER issue the drop page to all 
			dsm_msg.msg_id = index; 
			
			/* 2) Build command asking server to write into OUR handler */
			my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
			cmd.target_addr   = htobe64(my_handler_addr);
			cmd.faulting_addr  = htobe64((uint64_t)addr);
			cmd.id           = htonl(MSG_SEND_INVALIDATE);
			cmd.index           = htonl(index);

			DSM_EVENT_HANDLER("[CLIENT] Sending rdma : target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
				(unsigned long long)be64toh(cmd.target_addr),
				(unsigned long long)be64toh(cmd.faulting_addr),
				(unsigned)ntohl(cmd.id),
				(unsigned)ntohl(cmd.index));

			/* 3) Copy CMD into TX buffer (handler_data MR) */
    		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

			//Prepare for response 
			post_one_recv(&z_handler);

			/* 4) WRITE_WITH_IMM to server.receiver using that registered buffer */
			DSM_EVENT_HANDLER("[CLIENT] Sending CMD to server.receiver (imm=0xCAFE)\n\r");
			rdma_write_core(&z_handler_data,
							be64toh(remote_all.receiver.vaddr),
							ntohl(remote_all.receiver.rkey),
							z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

			/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
			for (;;) {
				if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
					if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
						if (wc.wc_flags & IBV_WC_WITH_IMM)
							DSM_EVENT_HANDLER("[CLIENT] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
						break;
					}
				}
			}
			// Now you can safely disable WP
    		disable_wp(uffd, (void *)addr);
			//update_page_info(addr, 0, MODIFIED, -2);
			PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", addr, page_list_data[index].state, MODIFIED, index);
			page_list_data[index].state = MODIFIED;	
     	} else {
			if (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for WRITE: %p\n\r", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
				copy.mode = 0; 
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", addr, page_list_data[index].state, MODIFIED, index);
				page_list_data[index].state = MODIFIED;
			} else {
				DSM_EVENT_HANDLER("[handler] MISSING fault on tracked page for READ: %p\n\r", (void*)msg.arg.pagefault.address);
				dsm_msg.msg_type = MSG_GET_PAGE_DATA;
				copy.mode = UFFDIO_COPY_MODE_WP;
				PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d \n\r", addr, page_list_data[index].state, SHARED, index);
				page_list_data[index].state = SHARED;
			}

		#if ENABLE_SERVER
			dsm_msg.msg_id = index;
			
			/* 2) Build command asking server to write into OUR handler */
			my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
			cmd.target_addr   = htobe64(my_handler_addr);
			cmd.faulting_addr  = htobe64((uint64_t)addr);
			cmd.id           = htonl(dsm_msg.msg_type);
			cmd.index           = htonl(index);

			DSM_EVENT_HANDLER("[CLIENT] Sending rdma : target_addr=%#llx faulting_addr=%#llx id=%u, index:%u\n\r",
				(unsigned long long)be64toh(cmd.target_addr),
				(unsigned long long)be64toh(cmd.faulting_addr),
				(unsigned)ntohl(cmd.id),
				(unsigned)ntohl(cmd.index));


			/* 3) Copy CMD into TX buffer (handler_data MR) */
    		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

			//Prepare for response 
			post_one_recv(&z_handler);

			/* 4) WRITE_WITH_IMM to server.receiver using that registered buffer */
			DSM_EVENT_HANDLER("[CLIENT] Sending CMD to server.receiver (imm=0xCAFE)\n\r");
			rdma_write_core(&z_handler_data,
							be64toh(remote_all.receiver.vaddr),
							ntohl(remote_all.receiver.rkey),
							z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

			/* Wait for server's WRITE_WITH_IMM CQE on our z_data CQ */
			for (;;) {
				if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
					if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
						if (wc.wc_flags & IBV_WC_WITH_IMM )
							DSM_EVENT_HANDLER("[CLIENT] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
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

#if RDMA_ENABLE 
void dsm_client_main_loop(int fd_command) {
    struct msg_info msg;
    //ssize_t n;
	//unsigned char ack;

	//RDMA
	struct ibv_wc wc;
	rdma_cmd_msg cmd;
	//union ibv_gid sgid;
    //uint8_t sgid_idx;
    //unsigned char rawbuf[sizeof(rdma_wire_all)];
    //size_t i;
	//int got = 0;


	//unsigned char page_content[PAGE_SIZE];
    struct iovec local_iov, remote_iov;
    ssize_t nread;
	
	post_one_recv(&z_receiver);
    while (1) {

        DSM_EVENT_CLIENT("[DSM Client] (fd=%d) Waiting for command message...\n\r", fd_command);

       /* 1. Wait for WRITE_WITH_IMM from client */
		poll_one_cqe(&z_receiver, &wc);
		if (!(wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM)) {
			DSM_EVENT_CLIENT("[SERVER] Unexpected CQE opcode=%d\n\r", wc.opcode);
		}
		memcpy(&cmd, z_receiver.base_addr, sizeof(cmd));
		DSM_EVENT_CLIENT("[SERVER] Command CMD: target_addr=%#llx fault addr=%#llx id=%u, index:%u\n\r",
			(unsigned long long)be64toh(cmd.target_addr),
			(unsigned long long)be64toh(cmd.faulting_addr),
			ntohl(cmd.id),
			ntohl(cmd.index));

		msg.msg_type = ntohl(cmd.id); //abusing msg_type to store the command type
		msg.page_addr = be64toh(cmd.faulting_addr);
		msg.msg_id = ntohl(cmd.index);
		post_one_recv(&z_receiver);

        DSM_DEBUG_CLIENT("[DSM Client] Received message: type=%d, addr=0x%lx, id=%ld\n\r",
               msg.msg_type, msg.page_addr, msg.msg_id);

        switch (msg.msg_type) {
			case MSG_BARRIER_HIT:
                DSM_DEBUG_CLIENT("[DSM Client] Remote barrier hit.\n\r");

			#if 1
				

				DSM_EVENT_CLIENT("[SERVER] Sending ACK_CMD to client.handler (imm=0xB1)\n\r");
				rdma_write_core(&z_receiver_data,
								be64toh(remote_all.handler.vaddr),
								ntohl(remote_all.handler.rkey),
								z_receiver_data.base_addr, 0, 0xB1);
				pthread_mutex_lock(&barrier.lock);
				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				if( remote_threads_barrier_arrived == 1 ){
					//means that the handler thread has not process the barrier yet, let's wait until it does
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}
				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_CLIENT("[DSM Client] Remote hit barrier, releasing...\n\r");
				pthread_mutex_unlock(&barrier.lock);
			#endif
				break;
			case MSG_BARRIER_RELEASE:
				DSM_DEBUG_CLIENT("[DSM Client] Remote barrier released.\n\r");
				pthread_mutex_lock(&barrier.lock);
				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				if( remote_threads_barrier_arrived ){
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_CLIENT("[DSM Client] Remote hit barrier, releasing...\n\r");
				pthread_mutex_unlock(&barrier.lock);
				break;
			case MSG_WAKE_THREAD:
				send_sigcont(restored_pid);
				break;
			case MSG_STOP_THREAD:
				send_sigstop(restored_pid);
				break;
			case MSG_GET_PAGE_DATA:
			case MSG_GET_PAGE_DATA_INVALID:
				//pthread_mutex_lock(&pagefaults_mutex);
				DSM_EVENT_CLIENT("→ Handling GET_PAGE_DATA/GET_PAGE_DATA_INVALID\n\r");
               
				DSM_EVENT_CLIENT("[DSM] Using process_vm_readv() to fetch remote page (pid=%d, addr=%p)\n",
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
						DSM_EVENT_CLIENT("❌ process_vm_readv failed: %s\n", strerror(errno));
					else
						DSM_EVENT_CLIENT("⚠️ process_vm_readv read partial data: %ld bytes\n", nread);
					kill_and_exit(restored_pid);	
				}	
				DSM_EVENT_CLIENT("✅ Read %ld bytes from target process memory\n", nread);

				// --- Send page data to client ---
				rdma_write_core(&z_receiver_data,
								be64toh(remote_all.handler.vaddr),
								ntohl(remote_all.handler.rkey),
								z_receiver_data.base_addr, 4096, 0xB1);
					
   				DSM_EVENT_CLIENT("✅ Page_transfer_complete to client (addr=%p)\n", (void*)msg.page_addr);
				// --- Post-transfer page management ---
				if (msg.msg_type == MSG_GET_PAGE_DATA_INVALID) {
					DSM_EVENT_CLIENT("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n");
					if (run_proc_MADVISE(pidfd, restored_pid, (void*)msg.page_addr, 4096) == 0)
						DSM_EVENT_CLIENT("process_madvise to invalidate page %p\n", (void*)msg.page_addr);
					else{
						DSM_EVENT_CLIENT("❌ MADV_DONTNEED failed: %s\n", strerror(errno));
						kill_and_exit(restored_pid);
					}
					DSM_EVENT_CLIENT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n",
						msg.page_addr, page_list_data[msg.msg_id].state, INVALID, msg.msg_id);
					page_list_data[msg.msg_id].state = INVALID;	
				} else {
					DSM_EVENT_CLIENT("Message is GET_PAGE_DATA → Enable WP to SHARED\n");
					if (enable_wp(uffd, (void*)msg.page_addr)){
						PRINT("⚠️ enable_wp failed\n");
						kill_and_exit(restored_pid);
					}
					DSM_EVENT_CLIENT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n",	msg.page_addr, page_list_data[msg.msg_id].state, SHARED, msg.msg_id);
					page_list_data[msg.msg_id].state = SHARED;	
				}

                break;
            case MSG_SEND_INVALIDATE:
				//pthread_mutex_lock(&pagefaults_mutex);
				DSM_EVENT_CLIENT("→ Handling RDMA invalidation request. Madvise(MADV_DONTNEED) on page at %p\n\r", (void *)msg.page_addr);

				if (run_proc_MADVISE(pidfd, restored_pid, (void *)msg.page_addr, 4096) == 0) {
					DSM_EVENT_SERVER("Successfully ran madvise on page at %p\n", (void *)msg.page_addr);
					DSM_EVENT_SERVER("[SERVER] Sending ACK_CMD to client.handler on INVALIDATE (imm=0xB1)\n\r");
					rdma_write_core(&z_receiver_data,
									be64toh(remote_all.handler.vaddr),
									ntohl(remote_all.handler.rkey),
									z_receiver_data.base_addr, 0, 0xB1);

					
				}else {
					perror("runMADVISE command loop");
					kill_and_exit(restored_pid);
				}  
				//pthread_mutex_unlock(&pagefaults_mutex);
				break;

            case MSG_HANDSHAKE:
                DSM_EVENT_CLIENT("[DSM Client] Test handshake message received, ignoring.\n\r");
                continue;
			
            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n\r", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
		PRINT("\n\r");
    }
}
#else
void dsm_client_main_loop(int fd_command) {
    struct msg_info msg;
    ssize_t n;
	unsigned char ack;

    while (1) {
        DSM_EVENT_CLIENT("[DSM Client] (fd=%d) Waiting for command message...\n\r", fd_command);

        n = recv(fd_command, &msg, sizeof(msg), 0);
        if (n <= 0) {
            perror("[DSM Client] recv failed or connection closed");
            break;
        } else if (n != sizeof(msg)) {
            fprintf(stderr, "[DSM Client] Incomplete message received (got %zd bytes)\n\r", n);
            continue;
        }

        DSM_DEBUG_CLIENT("[DSM Client] Received message: type=%d, addr=0x%lx, id=%ld\n\r",
               msg.msg_type, msg.page_addr, msg.msg_id);

        switch (msg.msg_type) {
			case MSG_BARRIER_HIT:
                DSM_DEBUG_CLIENT("[DSM Client] Remote barrier hit.\n\r");
				#if 1
				pthread_mutex_lock(&barrier.lock);
				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				if( remote_threads_barrier_arrived == 1 ){
					//means that the handler thread has not process the barrier yet, let's wait until it does
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_CLIENT("[DSM Client] Remote hit barrier, releasing...\n\r");
				pthread_mutex_unlock(&barrier.lock);
				#else
				pthread_mutex_lock(&barrier.lock);
				// Signal that barrier #2 for current epoch is released
				barrier.released_epoch = barrier.epoch;
				pthread_cond_broadcast(&barrier.cond);
				pthread_mutex_unlock(&barrier.lock);
				break;
				#endif
				break;
			case MSG_BARRIER_RELEASE:
				DSM_DEBUG_CLIENT("[DSM Client] Remote barrier released.\n\r");
				pthread_mutex_lock(&barrier.lock);
				// mark that remote threads have arrived, this is useful if we come before the local threads have, 
				//so that we don't care if the signal was lost since we can check the variable
				if( remote_threads_barrier_arrived ){
					pthread_cond_wait(&barrier.cond, &barrier.lock);
				}

				remote_threads_barrier_arrived = 1; 
				remote_barrier_addr = msg.page_addr;
				pthread_cond_broadcast(&barrier.cond);
				DSM_EVENT_CLIENT("[DSM Client] Remote hit barrier, releasing...\n\r");
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
				DSM_EVENT_CLIENT("→ Handling TCP GET_PAGE_DATA on status:%d\n\r", page_list_data[msg.msg_id].state);
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
				//pthread_mutex_unlock(&pagefaults_mutex);
                break;
            case MSG_GET_PAGE_DATA_INVALID:
				//pthread_mutex_lock(&pagefaults_mutex);
                DSM_EVENT_CLIENT("→ Handling TCP GET_PAGE_DATA_INVALID\n\r", page_list_data[msg.msg_id].state);
                handle_page_data_request(restored_pid, uffd, fd_command, &msg);
				//pthread_mutex_unlock(&pagefaults_mutex);
                break;
            case MSG_SEND_INVALIDATE:
				//pthread_mutex_lock(&pagefaults_mutex);
				DSM_EVENT_CLIENT("→ Handling TCP remote invalidation request. Madvise(MADV_DONTNEED) on page at %p\n\r", (void *)msg.page_addr);

				if (run_proc_MADVISE(pidfd, restored_pid, (void *)msg.page_addr, 4096) == 0) {
					DSM_EVENT_SERVER("Successfully ran process madvise on page at %p\n", (void *)msg.page_addr);

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
				}else {
					perror("runMADVISE command loop");
					kill_and_exit(restored_pid);
				}  
				//pthread_mutex_unlock(&pagefaults_mutex);
				break;

            case MSG_HANDSHAKE:
                DSM_EVENT_CLIENT("[DSM Client] Test handshake message received, ignoring.\n\r");
                continue;
			
            default:
                fprintf(stderr, "⚠️ Unknown message type: %d\n\r", msg.msg_type);
                kill_and_exit(restored_pid);  // shutdown the server on protocol error
                break;
        }
		PRINT("\n\r");
    }
}
#endif


static void *dsm_thread_start(void *arg)
{
    int fd_cmd = *(int*)arg;
    dsm_client_main_loop(fd_cmd);
    return NULL;
}



/********************************* MAIN ***************************************/
void start_dsm_client(const char *server_ip)
{	
    pthread_t receiver_thread;
	struct vm_area_list vmas = { .nr = 0};
	pthread_t uffd_thread;
	struct thread_param param;
	int client_pipe[2], uffd_pipe[2]; 
	FILE *f = fopen("/tmp/dsm_barrier_pages.txt", "r");
	FILE *f_mutex = fopen("/tmp/dsm_mutex.txt", "r");
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
	
#if RDMA_ENABLE && 0
	struct ibv_port_attr port_attr = {};
	union ibv_gid gid;	
	ssize_t n;
#endif


	(void) line;
	(void) base_address;

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

	if (dsm_client_dual_connect(&conn, server_ip) < 0) {
		fprintf(stderr, "DSM client connection failed\n\r");
		kill_and_exit(restored_pid);
	}

	PRINT("[DSM] Checking connectivity with server...\n\r");
	
	printf("[DSM-CONN] [%s] handler_fd=%d command_fd=%d\n\r",
         "CLIENT", conn.fd_handler, conn.fd_command);


	if (dsm_connectivity_test(&conn, false) < 0) {
		fprintf(stderr, "[DSM] Connectivity test failed\n\r");
		kill_and_exit(restored_pid);
	}
	PRINT("[DSM] First Connectivity OK ✅\n\r");




#if RDMA_ENABLE
{
	
    union ibv_gid sgid;
    uint8_t sgid_idx;
    unsigned char rawbuf[sizeof(rdma_wire_all)];
    size_t i;

    if (rdma_context_init(&z_handler)  ||
		rdma_context_init(&z_handler_data)  ||
		rdma_context_init(&z_receiver_data)  ||
        rdma_context_init(&z_receiver) ||
        rdma_context_init(&z_data)) {
        fprintf(stderr, "[RDMA][CLIENT] rdma_context_init failed\n\r");
        kill_and_exit(restored_pid);
    }

    if (init_rdma_zone(&z_handler,  NULL, 4096, 0) ||
        init_rdma_zone(&z_receiver, NULL, 4096, 0) ||
		init_rdma_zone(&z_handler_data,  NULL, 4096, 0) ||
        init_rdma_zone(&z_receiver_data, NULL, 4096, 0) ||
        init_rdma_zone(&z_data,     NULL, 4096, 0)) {
        fprintf(stderr, "[RDMA][CLIENT] init_rdma_zone failed\n\r");
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

    memset(&local_all, 0, sizeof(local_all));
    fill_conn_info_from_ctx(&z_handler,  		z_data.port_attr.lid, z_handler.gid.raw, 		&local_all.handler);
    fill_conn_info_from_ctx(&z_receiver, 		z_data.port_attr.lid, z_receiver.gid.raw,		&local_all.receiver);
    fill_conn_info_from_ctx(&z_data,     		z_data.port_attr.lid, z_data.gid.raw,     		&local_all.data);
	fill_conn_info_from_ctx(&z_receiver_data,	z_data.port_attr.lid, z_receiver_data.gid.raw,  &local_all.receiver_data);
	fill_conn_info_from_ctx(&z_handler_data,    z_data.port_attr.lid, z_handler_data.gid.raw,   &local_all.handler_data);
	
/* client: RECV first (command), then SEND (handler) */
    if (readn_all_exact(conn.fd_command, rawbuf, sizeof(rawbuf)) < 0) {
        perror("[RDMA][CLIENT] recv bundle"); kill_and_exit(restored_pid);
    }
    printf("[RDMA][DEBUG] CLIENT read %u bytes bundle\n\r", (unsigned)sizeof(rawbuf));
    printf("[RDMA][DEBUG] Raw: ");
    for (i=0;i<sizeof(rawbuf);i++) printf("%02x ", rawbuf[i]); 
	printf("\n\r");
    memcpy(&remote_all, rawbuf, sizeof(remote_all));

    if (writen_all_exact(conn.fd_handler, &local_all, sizeof(local_all)) < 0) {
        perror("[RDMA][CLIENT] send bundle"); kill_and_exit(restored_pid);
    }

    qp_to_rtr_rts(z_handler.qp,       &z_handler.port_attr,       &remote_all.receiver_data,  z_handler.psn,       sgid_idx, 1);
	qp_to_rtr_rts(z_receiver.qp,      &z_receiver.port_attr,      &remote_all.handler_data,   z_receiver.psn,      sgid_idx, 1);
	qp_to_rtr_rts(z_handler_data.qp,  &z_handler_data.port_attr,  &remote_all.receiver,       z_handler_data.psn,  sgid_idx, 1);
	qp_to_rtr_rts(z_receiver_data.qp, &z_receiver_data.port_attr, &remote_all.handler,        z_receiver_data.psn, sgid_idx, 1);
	qp_to_rtr_rts(z_data.qp,          &z_data.port_attr,          &remote_all.data,           z_data.psn,          sgid_idx, 1);


	//* post RECVs (all three ready to receive) */
    post_one_recv(&z_handler);
    post_one_recv(&z_receiver);
    post_one_recv(&z_data);

    printf("[RDMA][CLIENT] triple handshake complete: handler=%u receiver=%u data=%u\n\r",
           z_handler.qp->qp_num, z_receiver.qp->qp_num, z_data.qp->qp_num);
#if 0
	{
		char *buf;
		int got = 0;
		struct ibv_wc wc;

		printf("[CLIENT] Starting 5-zone RDMA full-duplex test\n\r");

		/* --- ZONE 1: handler_data -> server.receiver --- */
		buf = (char*)z_handler_data.base_addr;
		strcpy(buf, "CMD");
		printf("[CLIENT] Sending CMD to server.receiver (imm=0xA1)\n\r");
		rdma_write_core(&z_handler_data,
						be64toh(remote_all.receiver.vaddr),
						ntohl(remote_all.receiver.rkey),
						buf, strlen(buf) + 1, 0xA1);
		printf("[CLIENT] handler_data WRITE done ✅\n\r");

		/* --- ZONE 2: receiver_data -> server.handler --- */
		buf = (char*)z_receiver_data.base_addr;
		strcpy(buf, "HELLO");
		printf("[CLIENT] Sending HELLO to server.handler (imm=0xA2)\n\r");
		rdma_write_core(&z_receiver_data,
						be64toh(remote_all.handler.vaddr),
						ntohl(remote_all.handler.rkey),
						buf, strlen(buf) + 1, 0xA2);
		printf("[CLIENT] receiver_data WRITE done ✅\n\r");

		/* --- ZONE 3: data <-> server.data --- */
		buf = (char*)z_data.base_addr;
		strcpy(buf, "PING");
		printf("[CLIENT] Sending PING to server.data (imm=0xA3)\n\r");
		rdma_write_core(&z_data,
						be64toh(remote_all.data.vaddr),
						ntohl(remote_all.data.rkey),
						buf, strlen(buf) + 1, 0xA3);
		printf("[CLIENT] data WRITE done ✅\n\r");

		printf("[CLIENT] All 3 outbound WRITEs complete.\n\r");

		/* --- ZONE 4: handler <- server.receiver_data --- */
		post_one_recv(&z_handler);
		/* --- ZONE 5: receiver <- server.handler_data --- */
		post_one_recv(&z_receiver);

		printf("[CLIENT] Waiting for incoming messages from server...\n\r");
		
		while (got < 2) {
			if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
				printf("[CLIENT] handler got: '%s'\n\r", (char*)z_handler.base_addr);
				got++;
			}
			if (ibv_poll_cq(z_receiver.cq, 1, &wc) > 0) {
				printf("[CLIENT] receiver got: '%s'\n\r", (char*)z_receiver.base_addr);
				got++;
			}
		}

		printf("[CLIENT] ✅ Received both messages from server.\n\r");
	}



	{
		struct ibv_wc wc;
		rdma_cmd_msg cmd; /* copied into MR */
		uint64_t my_handler_addr;

		printf("[CLIENT] --- handler_data -> server.receiver ; server.receiver_data -> handler ---\n\r");

		/* 1) Dirty our handler page */
		memset(z_handler.base_addr, 0xAB, 4096);
		printf("[CLIENT] Handler zone at %p filled with 0xAB\n\r", z_handler.base_addr);

		/* 2) Build command asking server to write into OUR handler */
		my_handler_addr   = (uint64_t)(uintptr_t)z_handler.base_addr;
		cmd.target_addr   = htobe64(my_handler_addr);
		cmd.faulting_addr  = htobe64((uint64_t)0xDEADBEEF);
		cmd.id            = htonl(MSG_BARRIER_HIT);

		/* 3) Copy CMD into TX buffer (handler_data MR) */
		memcpy(z_handler_data.base_addr, &cmd, sizeof(cmd));

		/* 4) Post RECV on handler to catch server's WRITE_WITH_IMM */
		post_one_recv(&z_handler);

		/* 5) WRITE_WITH_IMM CMD to server.receiver */
		printf("[CLIENT] Sending CMD to server.receiver (imm=0xCAFE)\n\r");
		rdma_write_core(&z_handler_data,
						be64toh(remote_all.receiver.vaddr),
						ntohl(remote_all.receiver.rkey),
						z_handler_data.base_addr, sizeof(cmd), 0xCAFE);

		/* 6) Wait for server’s WRITE_WITH_IMM on our handler CQ */
		for (;;) {
			if (ibv_poll_cq(z_handler.cq, 1, &wc) > 0) {
				if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
					if (wc.wc_flags & IBV_WC_WITH_IMM)
						printf("[CLIENT] Got RDMA WRITE_WITH_IMM imm=0x%x\n\r", ntohl(wc.imm_data));
					break;
				}
			}
		}

		/* 7) Verify handler page is now zero */
		{
			volatile unsigned char *p = (unsigned char*)z_handler.base_addr;
			size_t i, dirty = 0;
			for (i = 0; i < 4096; i++) if (p[i] != 0x00) { dirty++; break; }
			if (dirty == 0) printf("[CLIENT] ✅ Handler page zeroed by server RDMA write\n\r");
			else            printf("[CLIENT] ❌ Handler still dirty (first=0x%02x)\n\r", p[0]);
		}
	}
#endif



}



//kill_and_exit(restored_pid); // TEMPORARY DISABLE DSM

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
        fprintf(stderr, "[RDMA][CLIENT] rdma_context_init failed\n\r");
        kill_and_exit(restored_pid);
    }
    printf("[DSM][RDMA][CLIENT] qp=%u base=%p rkey=0x%x\n\r",
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

    /* --- RECV server wire info (command) + dump --- */
    if (readn_all_exact(conn.fd_command, rawbuf, sizeof(rawbuf)) < 0) {
        perror("[RDMA][CLIENT] recv wire info");
        kill_and_exit(restored_pid);
    }
    printf("[RDMA][DEBUG] CLIENT TCP read %u bytes for remote wire info\n\r", (unsigned)sizeof(rawbuf));
    printf("[RDMA][DEBUG] Raw bytes: ");
    for (i = 0; i < sizeof(rawbuf); i++) printf("%02x ", rawbuf[i]); 
	printf("\n\r");
    memcpy(&remote, rawbuf, sizeof(remote));

    /* --- fill + SEND our wire info (handler) --- */
    memset(&local, 0, sizeof(local));
    local.qp_num = htonl(ctx.qp->qp_num);
    local.lid    = htons(ctx.port_attr.lid);
    memcpy(local.gid, ctx.gid.raw, 16);
    local.psn    = htonl(ctx.psn);
    local.rkey   = htonl(ctx.rkey);
    local.vaddr  = htobe64((uint64_t)(uintptr_t)ctx.base_addr);

    printf("[RDMA] sizeof(rdma_wire_info)=%u\n\r", (unsigned)sizeof(rdma_wire_info));
    if (writen_all_exact(conn.fd_handler, &local, sizeof(local)) < 0) {
        perror("[RDMA][CLIENT] send wire info");
        kill_and_exit(restored_pid);
    }

    /* --- decode/validate server BEFORE RTR --- */
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
        fprintf(stderr, "[RDMA][CLIENT] BAD REMOTE: zero GID on RoCE\n\r");
        kill_and_exit(restored_pid);
    }

    /* --- move to RTR/RTS (PSN-correct) --- */
    qp_to_rtr_rts(ctx.qp, &ctx.port_attr, &remote, ctx.psn, sgid_idx, 1);

    /* --- PRE-POST one RECV so server's WRITE_WITH_IMM can complete --- */
	post_one_recv(&ctx);
	printf("[CLIENT] Pre-posted RECV for server reply\n\r");

	/* --- Send HELLO via WRITE_WITH_IMM --- */
	strcpy((char*)ctx.base_addr, "HELLO");
	printf("[CLIENT] Sending HELLO via WRITE_WITH_IMM (imm=0xCAFE)\n\r");
	rdma_write_core(&ctx, peer_addr, peer_rkey,
					ctx.base_addr, (size_t)(strlen("HELLO") + 1), 0xCAFE);

	/* --- Poll until we have BOTH: SEND done and RECV done --- */
	{
		int got_send = 0;
		int got_recv = 0;

		printf("[CLIENT] Waiting for WORLD (and SEND completion)...\n\r");
		while (!got_recv) {
			struct ibv_wc wc;
			poll_one_cqe(&ctx, &wc);

			if (wc.opcode == IBV_WC_RDMA_WRITE) {
				if (!got_send) {
					got_send = 1;
					printf("[CLIENT] SEND complete (HELLO wrote), flags=0x%x\n\r", wc.wc_flags);
				}
				/* continue; still need the RECV */
				continue;
			}

			if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
				got_recv = 1;
				if (wc.wc_flags & IBV_WC_WITH_IMM)
					printf("[CLIENT] RX imm=0x%x\n\r", ntohl(wc.imm_data));
				printf("[CLIENT] Received data='%s'\n\r", (char*)ctx.base_addr);
				break;
			}

			/* Other CQEs (rare here) — just log and continue */
			printf("[CLIENT] skipping CQE opcode=%d flags=0x%x\n\r", wc.opcode, wc.wc_flags);
		}
	}


    /* Drain our own SEND completion */
    poll_one_cqe(&ctx, &wc);
    printf("[CLIENT] drained local CQE opcode=%d flags=0x%x\n\r", wc.opcode, wc.wc_flags);

    /* Wait for server's WRITE_WITH_IMM (RECV-type CQE) */
    printf("[CLIENT] Waiting for WORLD...\n\r");
    for (;;) {
        poll_one_cqe(&ctx, &wc);
        if (wc.opcode == IBV_WC_RECV || wc.opcode == IBV_WC_RECV_RDMA_WITH_IMM) break;
        printf("[CLIENT] skipping non-RECV CQE opcode=%d flags=0x%x\n\r", wc.opcode, wc.wc_flags);
    }

    if (wc.wc_flags & IBV_WC_WITH_IMM)
        printf("[CLIENT] RX imm=0x%x\n\r", ntohl(wc.imm_data));
    printf("[CLIENT] Received data='%s'\n\r", (char*)ctx.base_addr);

    rdma_cleanup(&ctx);
}
fprintf(stderr, "[DSM] Aborting due to previous error(s)\n\r");
kill_and_exit(restored_pid);
#endif
	//Start infection
	uffd = stealUFFD(restored_pid);

	if (init_userfaultfd_api(uffd) < 0) {
		fprintf(stderr, "Failed to initialize userfaultfd API\n\r");
		kill_and_exit(restored_pid);
	}
	else PRINT("Success initialize userfaultfd API\n\r");


	read_proc_maps(restored_pid);
	
	num_remote_tids = read_all_tids(restored_pid, tids, MAX_THREADS);
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
				PRINT("Registering page %d at address %lx\n\r", i, aux);
				page_list_data[total_pages].saddr = aux;
				page_list_data[total_pages].state = SHARED;
				//register_page(uffd, (void*)aux);
				//enable_wp(uffd, (void*)aux);
				total_pages++;
			}

			end_address = start_address + page_size * num_pages;
			PRINT("/tmp/ranges.txt: start addr:%lx, end:%lx\n\r", start_address, end_address);

			register_region_with_uffd(uffd, (void*)start_address, page_size * num_pages);
			enable_region_wp(uffd, (void*)start_address, page_size * num_pages);
		}

		fclose(f2);
	}else{
		fprintf(stderr, "[dsm] /tmp/ranges.txt not found \n\r");	
	}

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
		fprintf(stderr, "[dsm] /tmp/dsm_barrier_pages.txt not found, no pthread barrier support\n\r");	
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


	/*
	PRINT("[DSM] Checking connectivity with server...\n\r");
	if (dsm_connectivity_test(&conn, false) < 0) {
		fprintf(stderr, "[DSM] Connectivity test failed\n\r");
		kill_and_exit(restored_pid);
	}
	PRINT("[DSM] Connectivity OK ✅\n\r");*/


#if COMMAND_THREAD
	PRINT("[DSM Client] Connections established. Creating thread for command loop\n\r");

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

	PRINT("[DSM Client] After creating thread. Entering main loop...\n\r");
    dsm_client_main_loop(conn.fd_command);

#elif COMMAND_LOOP
	PRINT("[DSM Client] Connections established. Entering command loop\n\r");
	command_loop(restored_pid, uffd, &conn);
#elif 0
	PRINT("[DSM Client] Connection established. Entering main loop...\n\r");
    dsm_client_main_loop(conn.fd_command);
	//if(!DBG) send_sigcont(restored_pid);
#else
	pthread_create(&receiver_thread, NULL, dsm_thread_start , &conn.fd_command);
	pthread_detach(receiver_thread);
#endif

	{
		
		struct msg_info dsm_msg;
		int ret;
		struct pollfd pfd = { .fd = pidfd, .events = POLLIN };
		PRINT("[DSM] Waiting for restored process %d to exit...\n\r", restored_pid);

		ret = poll(&pfd, 1, -1);
		if (ret > 0 && (pfd.revents & POLLIN))
			PRINT("[DSM] Process %d exited.\n\r", restored_pid);

		dsm_msg.msg_type = MSG_JOIN_THREAD;
		
		for( int i= 0; i<num_remote_tids; i++ ){
			PRINT("send JOIN THREAD message for tid[%d]:%d\n\r", i, tids[i]);
			dsm_msg.msg_id = tids[i];
			if (send_all(conn.fd_handler, &dsm_msg, sizeof(dsm_msg)) != 0) {
				perror("[CLIENT] Failed to send JOIN THREAD message SERVER");
			}
		}

	#if RDMA_ENABLE
		printf("RDMA MODE, NUM_CLIENTS:%d, NUM_FAULTS:%d\n\r", N_CLIENTS, fault_counter);
	#else
		printf("TCP MODE, NUM_CLIENTS:%d, NUM_FAULTS:%d\n\r", N_CLIENTS, fault_counter);
	#endif
		close(pidfd);
	}


	PRINT("Killing and exiting\n\r");
	kill_and_exit(restored_pid);

}
