#ifndef DSM_H
#define DSM_H

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t, uint64_t
#include <sys/types.h> // for pid_t
#include "vma.h" 
#include <linux/types.h>

//#include <infiniband/verbs.h> //RDMA
/****************** Constants ******************/

#include "page.h" //this takes the page size #define PAGE_SIZE 4096
#define HANDSHAKE_MSG "READY"
#define PORT_COMMAND 7777
#define PORT_HANDLER 7778
#define N_CLIENTS 1
#define ACK_WRITE_PROTECT_EXPIRED 0x11
#define BACKLOG 1

#define KPROBE_MADVISE 0
#define RDMA_ENABLE 1
#define DBG 0
#define COMMAND_LOOP 0
#define ENABLE_SERVER 0
#define COMMAND_THREAD 0
#define EP 0

#define ENABLE_LOGGING 0
#define DEMO 1
#if ENABLE_LOGGING
#define PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#include "log.h"
#define PRINT(...) pr_info(__VA_ARGS__)
#endif
#define MAX_THREADS 512
#define MAX_PAGE_COUNT 100000 //general pages
#define MAX_PAGES 100 //malloc pages
#define MAX_RDMA_REGIONS 128
/****************** Global Variables (defined in dsm.c) ******************/

extern unsigned long global_addr;
extern unsigned long aligned;
extern int total_pages;
extern int uffd;
extern int restored_pid;
extern int local_threads;
extern int pidfd;
extern int fault_counter;
extern int rdma_on;
/****************** Enums ******************/

enum msg_type {
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
	MSG_BARRIER_HIT,
	MSG_BARRIER_RELEASE,
    MSG_LOCK_REQUEST,
    MSG_UNLOCK,
    MSG_JOIN_THREAD,
    MSG_GRANT_LOCK,
    MSG_TYPE_MAX,
};

extern unsigned long long dsm_incoming[MSG_TYPE_MAX];   // messages received
extern unsigned long long dsm_outgoing[MSG_TYPE_MAX];   // messages sent
extern unsigned long long dsm_forwarded[MSG_TYPE_MAX];  // messages forwarded (special case)


typedef enum {
    SHARED,
    MODIFIED,
    INVALID,
	DIVIDED,
} page_status;

/****************** Structs ******************/

struct msg_info {
	int msg_type;
	long page_addr;
	int page_size;
	long msg_id;
};

struct dsm_connection {
	int fd_handler;
	int fd_command;
};

struct thread_param {
    int uffd;
    int server_pipe;      // read end for handler
    int uffd_pipe;        // write end for handler
    int *fd_handler;
};

typedef struct {
    unsigned long saddr;
    uint64_t owner_mask;
    int state;
	int page_numbers; //if you have a continuous range, each page will tell how many pages are toghether
	int index_of_allocs; // != 0 if it's from malloc, the value gives the index of PageAlloc in allocs array
    void *rdma_addr;          // pointer inside RDMA mmap region
    int rdma_region_idx;      // index into rdma_context.regions[] if you keep those
} page_list ;

typedef struct {
    uintptr_t aligned_addr;
    uintptr_t addr;
    size_t npages;
    char symbol_name[32];
} PageAlloc;

#if !N_CLIENTS
typedef struct barrier_state {
    pthread_mutex_t lock;
    pthread_cond_t cond;     // signal resolver when all arrived
} barrier_state_t;

extern barrier_state_t barrier;
#else
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cond;

    int epoch;                // current barrier generation
    int released_epoch;       // epoch that has been globally released (barrier #2)
    uintptr_t local_barrier_addr;  // optional, per-epoch
    uintptr_t remote_barrier_addr; // optional, per-epoch
}barrier_state;



extern pthread_mutex_t mutex_l;
extern pthread_cond_t  mutex_cond;
extern unsigned long ticket_next;
extern unsigned long ticket_serving;


extern barrier_state barrier;
#endif
void barrier_init(void);
/****************** Extern Variables ******************/
extern void *zero_page;
extern int log_level;
extern pthread_mutex_t pagefaults_mutex;
extern page_list page_list_data[MAX_PAGE_COUNT];
extern int total_pages;
extern unsigned long barrier_addr;
extern unsigned long barrier_start_address;
extern unsigned long barrier_end_address;
extern unsigned long page_thread0;
extern unsigned long page_thread1;

extern unsigned long mutex_lock_start_address;
extern unsigned long mutex_lock_end_address;
extern unsigned long mutex_unlock_start_address;
extern unsigned long mutex_unlock_end_address;

extern unsigned long remote_barrier_addr;
extern unsigned long local_barrier_addr;
extern int remote_threads_barrier_arrived;
extern pthread_mutex_t fault_lock;
extern unsigned long active_fault_addr;
extern int active_fault_tid;
extern struct vm_area_list* my_vm_area_list;
extern unsigned long start_address, end_address;

extern long start_time; 
extern long end_time;

long time_now_us(void);
/****************** Function Declarations ******************/
void mark_fault_start(unsigned long addr, const char *who, pid_t tid);
void mark_fault_end(unsigned long addr, const char *who, pid_t tid);
void init_zero_page(void);
int get_list_page_index(unsigned long addr);
int update_page_info(unsigned long addr, int new_owner, int new_state, int new_index);
int interactive_page_inspect(struct msg_info *dsm_msg, int fd_handler, int mode);
//vma setup
unsigned long register_special_pages(void);
void register_all(int uffd, int restored_pid, unsigned long base_addr, struct vm_area_list *list, page_status status);
unsigned long get_base_address(int restored_pid);
void scan_and_prepare_coalesced_globals(unsigned long base_addr, pid_t restored_pid, int uffd, page_status status);
void register_and_write_protect_coalesced(int restored_pid, int uffd, page_status);
void reconstruct_vm_area_list(int uffd, int restored_pid, struct vm_area_list *list, page_status status);
struct vma_area *vma_area_alloc(void);
void print_vm_area_list(struct vm_area_list *list);
void read_proc_maps(int restored_pid);

//connection setup
int create_server_socket(int port);
int wait_for_connection(int listen_fd);
int dsm_setup_dual_connections(struct dsm_connection *conn);
int dsm_connectivity_test(struct dsm_connection *conn, bool is_server);
int connect_to_port(const char *server_ip, int port);
int dsm_client_dual_connect(struct dsm_connection *conn, const char *server_ip);
int perform_struct_handshake(int send_fd, int recv_fd, bool is_sender);

// userfaultfd setup
int init_userfaultfd_api(int uffd);
void register_page(int uffd, void *addr);
int register_region_with_uffd(int uffd, void *addr, size_t length);
void enable_region_wp( int uffd, void *addr, size_t length);
void disable_region_wp( int uffd, void *addr, size_t length);
int enable_wp(int uffd, void *addr);
void disable_wp(int uffd, void *addr);

// DSM helpers
void register_ranges_from_file(int uffd);
unsigned long leakGlobalPage(int restored_pid, unsigned long offset);
int replaceGlobalWithAnonPage(int restored_pid, void *addr);
int print_global_value_from_page(void *page_buf, size_t page_len) ;
int send_get_page(struct msg_info dsm_msg, int fd_handler, void *page_out);
void print_mutex(const unsigned char *page_data, size_t offset);
int change_mutex_content(int restored_pid, int uffd, struct msg_info *dsm_msg);
int test_mutex_content(int restored_pid, int uffd, struct msg_info *dsm_msg);
int runUnlockMutex(int restored_pid, void *mutex_addr);
int test_full_page_content(int restored_pid, int uffd, struct msg_info *dsm_msg, int print_int);
int test_page_content(int restored_pid, int uffd, struct msg_info *dsm_msg);
int runMADVISE(int restored_pid, void *addr, size_t len);
int init_pidfd(int restored_pid);
int run_proc_MADVISE(int pidfd, int restored_pid, void *addr, size_t len);
int read_invalidate(int restored_pid, void *addr);
int stealUFFD(int restored_pid);
int infection_test(int restored_pid);
int handle_page_data_request(int restored_pid, int uffd, int sk, struct msg_info *dsm_msg);
ssize_t all_read(int fd, void *buf, size_t len);
int send_all(int fd, const void *buf, size_t len);

//App helpers
void read_pid(int* restored_pid);
void send_sigcont(int pid);
void send_sigstop(int pid);
void kill_and_exit(int pid);

void command_loop(int restored_pid, int uffd, struct dsm_connection* conn);

//DSM Testing functions
int dsm_test_handle_page_fault(int restored_pid, int uffd, unsigned long fault_addr, int is_write);
int dsm_test_init(int restored_pid);
void dsm_test_finalize(void);
void dsm_test_generate_report(void);
int dsm_test_mode_controller(int restored_pid, int uffd);


#if RDMA_ENABLE

#include <infiniband/verbs.h>
#include <stdint.h>
#include <stdbool.h>
/* --------- Simple RDMA Context --------- */
typedef struct {
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr;
    void *base_addr;
    size_t length;
    uint32_t rkey;
    uint32_t lkey;
    uint32_t psn;
    uint32_t max_inline;
    struct ibv_port_attr port_attr;
    union ibv_gid gid;
} rdma_context;

/* --------- Wire Info exchanged over TCP --------- */


#pragma pack(push,1)
typedef struct {
    uint32_t qp_num;   /* network byte order on wire */
    uint16_t lid;      /* network byte order on wire (0 per RoCE) */
    uint8_t  gid[16];  /* raw */
    uint32_t psn;      /* network byte order */
    uint32_t rkey;     /* network byte order */
    uint64_t vaddr;    /* big-endian on wire */
} rdma_wire_info;
#pragma pack(pop)


typedef struct __attribute__((packed))  {
    uint64_t target_addr;   /* client's RDMA buffer addr */
    uint64_t faulting_addr;  /* e.g. 0xDEADBEEF */
    uint32_t id;            /* some tag, e.g. 10 */
    uint32_t index;         
} rdma_cmd_msg;

/* ---------------- Bundle of THREE zones ---------------- */
typedef struct {
    rdma_wire_info handler;
    rdma_wire_info receiver;
    rdma_wire_info data;
    rdma_wire_info handler_data;
    rdma_wire_info receiver_data;
} rdma_wire_all;

typedef struct {
    rdma_context handler;
    rdma_context receiver;
    rdma_context data;
    rdma_context handler_data;
    rdma_context receiver_data;

    rdma_wire_all local_all;   // what server sends to client
    rdma_wire_all remote_all;  // what client sends back
}rdma_endpoint;

extern rdma_endpoint *endpoints;


/* ---------------- Global rdma decl ---------------- */
extern rdma_context z_handler, z_receiver, z_data;
extern rdma_context z_handler_data, z_receiver_data;
extern rdma_wire_all local_all, remote_all;


/* --------- Function prototypes --------- */
int  rdma_context_init(rdma_context *ctx);
int  init_rdma_zone(rdma_context *ctx, const char *path, size_t size, int use_huge);
void rdma_cleanup(rdma_context *ctx);
/* dsm.h */
void qp_to_rtr_rts(struct ibv_qp *qp,
                   const struct ibv_port_attr *pa,
                   const rdma_wire_info *peer,
                   uint32_t local_psn,      /* NEW: your ctx.psn */
                   uint8_t sgid_idx,
                   uint8_t port);

void post_one_recv(rdma_context *ctx);
void poll_one_cqe(rdma_context *ctx, struct ibv_wc *wc);
void rdma_write_core(rdma_context *ctx,
                     uint64_t remote_addr, uint32_t remote_rkey,
                     const void *src, size_t len, uint32_t imm);


int pick_valid_sgid_index(struct ibv_context *ctx, uint8_t port,
                                 uint8_t *out_idx, union ibv_gid *out_gid);

void fill_conn_info_from_ctx(rdma_context *c,
                             uint16_t lid,
                             const uint8_t gid[16],
                             rdma_wire_info *out);


int writen_all_exact(int fd, const void *buf, size_t n);
int readn_all_exact(int fd, void *buf, size_t n);

#endif

#endif // DSM_H