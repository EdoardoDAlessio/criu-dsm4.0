#ifndef DSM_H
#define DSM_H

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t, uint64_t
#include <sys/types.h> // for pid_t
#include "vma.h" 
/****************** Constants ******************/

#include "page.h" //this takes the page size #define PAGE_SIZE 4096
#define HANDSHAKE_MSG "READY"
#define PORT_COMMAND 7777
#define PORT_HANDLER 7778
#define NUM_THREADS 1
#define ACK_WRITE_PROTECT_EXPIRED 0x11
#define BACKLOG 1

#define DBG 1
#define COMMAND_LOOP 1 
#define ENABLE_SERVER 0
#define COMMAND_THREAD ENABLE_SERVER & COMMAND_LOOP
#define EP 1

#define ENABLE_LOGGING 0
#define DEMO 1
#if ENABLE_LOGGING
#define PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#include "log.h"
#define PRINT(...) pr_info(__VA_ARGS__)
#endif

#define MAX_PAGE_COUNT 100000 //general pages
#define MAX_PAGES 100 //malloc pages

/****************** Global Variables (defined in dsm.c) ******************/

extern unsigned long global_addr;
extern unsigned long aligned;
extern int total_pages;

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
};


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
    int fd_handler[NUM_THREADS];
};

struct page_list {
    unsigned long saddr;
    int owner;
    int state;
	int page_numbers; //if you have a continuous range, each page will tell how many pages are toghether
	int index_of_allocs; // != 0 if it's from malloc, the value gives the index of PageAlloc in allocs array
};

typedef struct {
    uintptr_t aligned_addr;
    uintptr_t addr;
    size_t npages;
    char symbol_name[32];
} PageAlloc;


/****************** Extern Variables ******************/

extern struct page_list page_list_data[MAX_PAGE_COUNT];
extern int total_pages;

/****************** Function Declarations ******************/

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
int connect_to_port(const char *server_ip, int port);
int dsm_client_dual_connect(struct dsm_connection *conn, const char *server_ip);
int perform_struct_handshake(int send_fd, int recv_fd, bool is_sender);

// userfaultfd setup
int init_userfaultfd_api(int uffd);
void register_page(int uffd, void *addr);
int register_region_with_uffd(int uffd, void *addr, size_t length);
void enable_wp(int uffd, void *addr);
void disable_wp(int uffd, void *addr);

// DSM helpers
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
int read_invalidate(int restored_pid, void *addr);
int stealUFFD(int restored_pid);
int infection_test(int restored_pid);
int handle_page_data_request(int restored_pid, int uffd, int sk, struct msg_info *dsm_msg);

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
#endif // DSM_H
