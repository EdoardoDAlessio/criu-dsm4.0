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
#define ENABLE_LOGGING 1

#if ENABLE_LOGGING
#define PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define PRINT(...) do {} while (0)
#endif

#define MAX_PAGE_COUNT 100000

/****************** Global Variables (defined in dsm.c) ******************/

extern unsigned long global_addr;
extern unsigned long aligned;

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


enum page_status {
    MODIFIED,
    SHARED, 
    INVALID,
};

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
};

/****************** Extern Variables ******************/

extern struct page_list page_list_data[MAX_PAGE_COUNT];
extern int total_pages;

/****************** Function Declarations ******************/

//vma setup
void register_and_write_protect_coalesced(int uffd);
void reconstruct_vm_area_list(int restored_pid, struct vm_area_list *list);
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
void enable_wp(int uffd, void *addr);
void disable_wp(int uffd, void *addr);

// DSM helpers
unsigned long leakGlobalPage(int restored_pid, unsigned long offset);
int replaceGlobalWithAnonPage(int restored_pid, void *addr);
int print_global_value_from_page(void *page_buf, size_t page_len) ;
int send_get_page(struct msg_info dsm_msg, int fd_handler, void *page_out);
int test_page_content(int restored_pid, int uffd, struct msg_info *dsm_msg);
int runMADVISE(int restored_pid, void *addr);
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
#endif // DSM_H
