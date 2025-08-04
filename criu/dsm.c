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

#include "dsm.h"

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
#define ACK_WRITE_PROTECT_EXPIRED 0x11
// Setup global variable address 


unsigned long global_addr = 0x555555558080;
unsigned long aligned = 0x555555558080 & ~(PAGE_SIZE - 1);/*
unsigned long global_addr = 0x5555555580c0;
unsigned long aligned = 0x5555555580c0 & ~(PAGE_SIZE - 1);
unsigned long global_addr = 0x7fffffffe5dc;
unsigned long aligned = 0x7fffffffe5dc & ~(PAGE_SIZE - 1);*/
/***************** END USERFAULTFD HEADERS ************************/



/*********************************** VMA RECONSTRUCTION ********************* */

#include "vma.h"
#include "mem.h"       // Required for xmalloc()
#include "cr_options.h"

void print_vm_area_list(struct vm_area_list *list) {
    struct vma_area *vma;
   list_for_each_entry(vma, &list->h, list) {
		pr_info("VMA: 0x%lx-0x%lx prot=%x\n",
			vma->e->start, vma->e->end, vma->e->prot);
	}
}

struct vma_area *vma_area_alloc(void)
{
    struct vma_area *vma;
    vma = xmalloc(sizeof(*vma));
    if (!vma) return NULL;
    INIT_LIST_HEAD(&vma->list);
    vma->e = xmalloc(sizeof(VmaEntry));
    if (!vma->e) {
        xfree(vma);
        return NULL;
    }
    memset(vma->e, 0, sizeof(VmaEntry));
    return vma;
}
/*
static void add_vma(struct vm_area_list *list, unsigned long start, unsigned long end)
{
    struct vma_area *vma = vma_area_alloc();
    if (!vma) return;
    vma->e->start = start;
    vma->e->end = end;
    list_add_tail(&vma->list, &list->h);  // Append to the vm_area_list
    list->nr++;                           // Increment the count of VMAs
}
void reconstruct_vm_area_list(int restored_pid, struct vm_area_list *list) {
    char path[64];
    char line[512];
	FILE *fp;
	int prot = 0;
    unsigned long start, end;
	struct vma_area * vma;
    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);
    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return;
    }
	while (fgets(line, sizeof(line), fp)) {
		char perms[5] = {0};
		vma = vma_area_alloc();
		if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
			if (perms[0] == 'r') prot |= PROT_READ;
			if (perms[1] == 'w') prot |= PROT_WRITE;
			if (perms[2] == 'x') prot |= PROT_EXEC;
			if (!vma)
				continue;

			vma->e->start = start;
			vma->e->end = end;
			vma->e->prot = prot;

			list_add_tail(&vma->list, &list->h);
			list->nr++;
		}
	}
	//Save global vma for future infection
	//g_vm_area_list = list;
    fclose(fp);
}*/

struct page_list page_list_data[MAX_PAGE_COUNT];
int total_pages = 0;

void reconstruct_vm_area_list(int restored_pid, struct vm_area_list *list) {
    char path[64];
    char line[512];
    FILE *fp;
    unsigned long start, end;
    char perms[5], dev[6], mapname[PATH_MAX];
    unsigned long offset;
    int inode, is_anon;
    struct vma_area *vma;

    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);
    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        int prot = 0;
        mapname[0] = '\0';  // Ensure mapname is cleared each line

        if (sscanf(line, "%lx-%lx %4s %lx %5s %d %[^\n]",
                   &start, &end, perms, &offset, dev, &inode, mapname) < 6)
            continue;

        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;

        // Only consider anonymous mappings (empty or space-only pathname)
        is_anon = (strlen(mapname) == 0 || mapname[0] == '\0');

        if (is_anon && (prot & PROT_READ) && (prot & PROT_WRITE)) {
            size_t npages = (end - start) / PAGE_SIZE;
            if (total_pages + npages > MAX_PAGE_COUNT) {
                fprintf(stderr, "⚠️  Too many pages, increase MAX_PAGE_COUNT\n");
                break;
            }

            for (size_t i = 0; i < npages; i++) {
                page_list_data[total_pages + i].saddr = start + i * PAGE_SIZE;
                page_list_data[total_pages + i].owner = 0;
                page_list_data[total_pages + i].state = SHARED;
            }
            total_pages += npages;

            PRINT("[TRACK] 0x%lx - 0x%lx (%zu pages)\n", start, end, npages);
        }

        // Fill vma list regardless of uffd track status (for infection, mapping etc.)
        vma = vma_area_alloc();
        if (!vma)
            continue;

        vma->e->start = start;
        vma->e->end = end;
        vma->e->prot = prot;
        list_add_tail(&vma->list, &list->h);
        list->nr++;
    }

    //g_vm_area_list = list;
    fclose(fp);
    PRINT("✅ Total trackable pages: %d\n", total_pages);
}


void scan_and_prepare_coalesced_globals(unsigned long base_addr, pid_t restored_pid, int uffd, page_status status) {
    FILE *fp = fopen("/tmp/readelf.txt", "r");
    char line[512], type[32], bind[32], vis[32], name[256], symbol[128];
    int idx, section_idx, matched;
    unsigned long offset, start, end, aligned_start, aligned_end, size;
    if (!fp) {
        perror("fopen readelf_file /tmp/readelf.txt");
        return;
    }

   
    while (fgets(line, sizeof(line), fp)) {
        
         // Skip empty or comment lines
        //if (strlen(line) < 10 || !isdigit(line[0])) 
            //continue;

        // Try parsing relevant fields from readelf line
        matched = sscanf(line, "%d: %lx %lx %s %s %s %d %s", &idx, &offset, &size, type, bind, vis, &section_idx, name);


        if (matched == 8 && strcmp(type, "OBJECT") == 0 && strcmp(bind, "GLOBAL") == 0 && strcmp(vis, "DEFAULT") == 0) {
            

            start = base_addr + offset;
            end   = start + size;

            aligned_start = start & ~(PAGE_SIZE - 1);
            aligned_end   = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

            printf("✅ Symbol: %-30s  Offset: 0x%10lx  Size: %10lu, Aligned page start:%lx\n", name, offset, size, aligned_start);

            for (unsigned long addr = aligned_start; addr < aligned_end; addr += PAGE_SIZE) {
                // Check for duplicates in page_list_data[]
                int already_seen = 0;
                for (int i = 0; i < total_pages; i++) {
                    if (page_list_data[i].saddr == addr) {
                        already_seen = 1;
                        break;
                    }
                }

                if (0 & !already_seen) {
                    replaceGlobalWithAnonPage(restored_pid, (void *) addr);
                    register_page( uffd, (void *) addr);
                    
                    if( status == SHARED ) 
                        enable_wp( uffd, (void *) addr );
                    //else if( status == INVALID )       madvise(  );

                    page_list_data[total_pages].saddr = addr;
                    page_list_data[total_pages].owner = 0;
                    page_list_data[total_pages].state = status;
                    total_pages++;

                    PRINT("📌 Added global page: 0x%lx (from symbol: %s)\n", addr, symbol);
                }
            }
        }else {
            PRINT("⛔ Skipping line: %s", line);  // Optional: for debugging
        }


      
    }

    fclose(fp);
}



void register_and_write_protect_coalesced(int restored_pid, int uffd, page_status status) {
	int i, j;
	struct uffdio_register uffdio_register;
	struct uffdio_writeprotect uf_wp;
    /*struct uffdio_api uffdio_api = {
        .api = UFFD_API,
        .features = UFFD_FEATURE_PAGEFAULT_FLAG_WP
    };

    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
        perror("ioctl/uffdio_api");
        exit(EXIT_FAILURE);
    }

    if (uffdio_api.api != UFFD_API) {
        fprintf(stderr, "❌ unsupported userfaultfd api\n");
        exit(EXIT_FAILURE);
    }*/

    i = 0;
    while (i < total_pages) {
        unsigned long range_start = page_list_data[i].saddr;
        size_t range_len = PAGE_SIZE, num_pages;
        (void) num_pages;
        j = i + 1;

        // Expand as long as pages are contiguous
        while (j < total_pages && page_list_data[j].saddr == page_list_data[j - 1].saddr + PAGE_SIZE) {
            range_len += PAGE_SIZE;
            j++;
        }

		num_pages = range_len / PAGE_SIZE;

        // Print the range and page count
        PRINT("➡️  Registering range: 0x%lx - 0x%lx (%zu pages)\n", range_start, range_start + range_len, num_pages);

        // Register contiguous range
		uffdio_register.range.start = range_start;
		uffdio_register.range.len   = range_len;
		uffdio_register.mode        = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
       

        if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1) {
            perror("❌ ioctl/uffdio_register");
            fprintf(stderr, "   at range 0x%lx - 0x%lx\n", range_start, range_start + range_len);
        }

        if( status == SHARED ){
            PRINT("Registering with WP mode\n");
            // Write-protect the range
            uf_wp.range.start = range_start;
            uf_wp.range.len   = range_len;
            uf_wp.mode        = UFFDIO_WRITEPROTECT_MODE_WP;

            if (ioctl(uffd, UFFDIO_WRITEPROTECT, &uf_wp) == -1) {
                perror("❌ ioctl/write_protect");
                fprintf(stderr, "   at range 0x%lx - 0x%lx\n", range_start, range_start + range_len);
            }
        }else if (status == INVALID) {
            if (runMADVISE(restored_pid, (void *)range_start, range_len))
                perror("runMADVISE command loop");
            else
                PRINT("✅ Successfully run madvise on range at 0x%lx (%zu bytes)\n", range_start, range_len);
        }

       

        // Set all involved pages as status
        for (int k = i; k < j; k++) {
            page_list_data[k].state = status;
        }

        i = j;  // move to the next non-contiguous page
    }
}
unsigned long get_base_address(int restored_pid) {
    char path[64], line[512];
    FILE *fp;
    unsigned long start;

    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);

    fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to open /proc/<pid>/maps");
        return 0;
    }

    // Just read the first line and parse the starting address
    if (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-", &start) == 1) {
            fclose(fp);
            return start;
        }
    }

    fclose(fp);
    fprintf(stderr, "⚠️ Could not read base address from maps\n");
    return 0;
}



void read_proc_maps(int restored_pid) {
    char path[64];
	FILE *fp;
	char line[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);

    fp = fopen(path, "r");
    if (!fp) {
        perror("Failed to open /proc/<pid>/maps");
        return;
    }

    PRINT("=== Memory Map of PID %d ===\n", restored_pid);
    
    while (fgets(line, sizeof(line), fp)) {
        PRINT("%s", line);
    }

    fclose(fp);
}

/***********************************END VMA RECONSTRUCTION ********************* */


/********************************* CONNECTION FUNCTIONS ***************************************/

//SERVER
int create_server_socket(int port) {
    int fd, opt = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, BACKLOG) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

int wait_for_connection(int listen_fd) {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    int conn_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (conn_fd < 0) {
        perror("accept");
        return -1;
    }
    return conn_fd;
}

int dsm_setup_dual_connections(struct dsm_connection *conn) {
    int fd_handler_listen = create_server_socket(PORT_HANDLER);
    int fd_command_listen = create_server_socket(PORT_COMMAND);

    if (fd_handler_listen < 0 || fd_command_listen < 0)
        return -1;

    PRINT("[DSM Server] Waiting for handler thread connection on port %d...\n", PORT_HANDLER);
    conn->fd_handler = wait_for_connection(fd_handler_listen);
    if (conn->fd_handler < 0) return -1;

    PRINT("[DSM Server] Waiting for command thread connection on port %d...\n", PORT_COMMAND);
    conn->fd_command = wait_for_connection(fd_command_listen);
    if (conn->fd_command < 0) return -1;

    close(fd_handler_listen);
    close(fd_command_listen);

    PRINT("[DSM Server] Connections established:\n");
    PRINT("  fd_handler = %d\n", conn->fd_handler);
    PRINT("  fd_command = %d\n", conn->fd_command);

    return 0;
}

//CLIENT
int connect_to_port(const char *server_ip, int port)
{
	int sockfd;
	struct sockaddr_in serv_addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
		fprintf(stderr, "[DSM Client] Invalid IP: %s\n", server_ip);
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	PRINT("[DSM Client] Connecting to %s:%d...\n", server_ip, port);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("connect");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

int dsm_client_dual_connect(struct dsm_connection *conn, const char *server_ip) {
	conn->fd_command = connect_to_port(server_ip, PORT_HANDLER);
	conn->fd_handler = connect_to_port(server_ip, PORT_COMMAND);

	if (conn->fd_command < 0 || conn->fd_handler < 0) {
		perror("[DSM Client] Failed to connect to server ports");
		if (conn->fd_command >= 0) close(conn->fd_command);
		if (conn->fd_handler >= 0) close(conn->fd_handler);
		return -1;
	}

	/*
	// Perform handshake on each connection to verify both are alive and valid
	if (perform_struct_handshake(conn->fd_command, conn->fd_command, true) < 0) {
		fprintf(stderr, "[DSM Client] Command connection handshake failed\n");
		close(conn->fd_command);
		close(conn->fd_handler);
		return -1;
	}

	if (perform_struct_handshake(conn->fd_handler, conn->fd_handler, true) < 0) {
		fprintf(stderr, "[DSM Client] Handler connection handshake failed\n");
		close(conn->fd_command);
		close(conn->fd_handler);
		return -1;
	}*/

	PRINT("[DSM Client] fd_command = %d, fd_handler = %d\n", conn->fd_command, conn->fd_handler);
	PRINT("[DSM Client] Dual connection established successfully.\n");

	return 0;
}

int perform_struct_handshake(int send_fd, int recv_fd, bool is_sender) {
    struct msg_info msg_in, msg_out;
    ssize_t sent, received;

    if (is_sender) {
        // 1. Send handshake message
        msg_out.msg_type = MSG_HANDSHAKE;
        msg_out.page_addr = 0xdeadbeef;
        msg_out.page_size = 4096;
        msg_out.msg_id = 12345;

        sent = send(send_fd, &msg_out, sizeof(msg_out), 0);
        if (sent != sizeof(msg_out)) {
            perror("[HANDSHAKE] Failed to send handshake");
            return -1;
        }

        PRINT("[HANDSHAKE] Sent MSG_HANDSHAKE on fd %d\n", send_fd);

        // 2. Receive ACK
        received = recv(recv_fd, &msg_in, sizeof(msg_in), 0);
        if (received != sizeof(msg_in)) {
            perror("[HANDSHAKE] Failed to receive ACK");
            return -1;
        }

        if (msg_in.msg_type != MSG_ACK) {
            fprintf(stderr, "[HANDSHAKE] Invalid ACK type: %d\n", msg_in.msg_type);
            return -1;
        }

        PRINT("[HANDSHAKE] Received MSG_ACK from fd %d\n", recv_fd);
    } else {
        // 1. Receive handshake
        received = recv(recv_fd, &msg_in, sizeof(msg_in), 0);
        if (received != sizeof(msg_in)) {
            perror("[HANDSHAKE] Failed to receive handshake");
            return -1;
        }

        if (msg_in.msg_type != MSG_HANDSHAKE) {
            fprintf(stderr, "[HANDSHAKE] Unexpected message type: %d\n", msg_in.msg_type);
            return -1;
        }

        PRINT("[HANDSHAKE] Received MSG_HANDSHAKE from fd %d\n", recv_fd);

        // 2. Send ACK
        msg_out.msg_type = MSG_ACK;
        msg_out.page_addr = 0;
        msg_out.page_size = 0;
        msg_out.msg_id = 0;

        sent = send(send_fd, &msg_out, sizeof(msg_out), 0);
        if (sent != sizeof(msg_out)) {
            perror("[HANDSHAKE] Failed to send ACK");
            return -1;
        }

        PRINT("[HANDSHAKE] Sent MSG_ACK to fd %d\n", send_fd);
    }

    return 0; // success
}

/********************************* END CONNECTION FUNCTIONS ***************************************/


/******************************** USERFAULT FUNCTIONS ****************************/
int init_userfaultfd_api(int uffd) {
	struct uffdio_api uffdio_api;
	uffdio_api.api = UFFD_API;
	uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;

	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
		perror("ioctl/UFFDIO_API");
		return -1;
	}

	if (uffdio_api.api != UFFD_API) {
		fprintf(stderr, "Unsupported userfaultfd API version (got %llu, expected %llu)\n",
		        uffdio_api.api, UFFD_API);
		return -1;
	}

	if (!(uffdio_api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
		fprintf(stderr, "UFFDIO_WRITEPROTECT feature not supported by kernel\n");
		return -1;
	}

	PRINT("✅ userfaultfd API initialized with WP support\n");
	return 0;
}	

void register_page(int uffd, void *addr) {
	struct uffdio_register reg;
	
	PRINT("Address registering page %p\n", (void*) addr);

	reg.range.start = (unsigned long)addr;
	reg.range.len = PAGE_SIZE;
	reg.mode =  UFFDIO_REGISTER_MODE_WP | UFFDIO_REGISTER_MODE_MISSING;

	PRINT("Registering addr = %p (aligned = %ld)\n", addr, (unsigned long)addr % PAGE_SIZE);
	PRINT("UFFD REGISTER: %d\n", uffd);

	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		perror("UFFDIO_REGISTER");
		exit(1);
	}

}

void enable_wp(int uffd, void *addr)
{
	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = UFFDIO_WRITEPROTECT_MODE_WP
	};

	PRINT("UFFD enable: %d\n", uffd);

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
		perror("UFFDIO_WRITEPROTECT (enable)");
	else
		PRINT("Successfully protected global page at %p\n", addr);
}	

void disable_wp(int uffd, void *addr)
{
	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = 0  // no WP flag
	};

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
		perror("UFFDIO_WRITEPROTECT (disable)");
	else
		PRINT("Successfully disabled write protection on page at %p\n", addr);
}

/******************************** END USERFAULT FUNCTIONS ****************************/

/******************************** INFECTION FUNCTIONS *******************************/

unsigned long leakGlobalPage(int restored_pid, unsigned long offset)
{
    int state, rc;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;
    unsigned long *args;
    unsigned long result;

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return 0;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(unsigned long)) < 0) {
        pr_err("❌ Infection failed\n");
        goto fail;
    }

    args = compel_parasite_args(ctl, unsigned long);
    //*args = offset;
	*args = 0x4080; // Offset of `global` symbol from readelf

	rc = compel_rpc_call(PARASITE_CMD_LEAK_GLOBAL_PAGE, ctl);
    if (rc < 0) {
        pr_err("❌ RPC call failed\n");
        goto fail;
    }

	rc = compel_rpc_sync(PARASITE_CMD_LEAK_GLOBAL_PAGE, ctl);
    if (rc < 0) {
        pr_err("❌ RPC call failed\n");
        goto fail;
    }
	

	PRINT("✅ Leaked global page = 0x%lx\n", *args);

    result = (unsigned long)*args;
    PRINT("✅ Leaked global page = 0x%lx\n", result);

    if (compel_stop_daemon(ctl))
        pr_err("Failed to stop daemon\n");
    else
        PRINT("Daemon stopped (leak)\n");

    if (compel_cure(ctl))
        pr_err("Failed to cure\n");
    else
        PRINT("Cured! (leak)\n");

    if (compel_resume_task(restored_pid, state, state))
        pr_err("Failed to resume task\n");
    else
        PRINT("Resumed post leak\n");
    return result;

fail:
    if (compel_stop_daemon(ctl))
        pr_err("Failed to stop daemon\n");
    else
        PRINT("Daemon stopped (leak)\n");

    if (compel_cure(ctl))
        pr_err("Failed to cure\n");
    else
        PRINT("Cured! (leak)\n");

    if (compel_resume_task(restored_pid, state, state))
        pr_err("Failed to resume task\n");
    else
        PRINT("Resumed post leak\n");

    return 0;
}


int replaceGlobalWithAnonPage(int restored_pid, void *addr){
    int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *args;
	(void) state;
	(void) args;

	PRINT("[DSM] replaceGlobalWithAnonPage request...\n");

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))){
		pr_err("❌ Compel prepare failed\n");
		return -1;
	} 

	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(ctl, 1, sizeof(long)) < 0) {
		xfree(ctl);
		return -1;
	}

	//Prepare the addr to pass
	args = compel_parasite_args(ctl, long);
	*args = (long)addr;
	if (compel_rpc_call(PARASITE_CMD_REMAP_ANON, ctl) < 0) {
		pr_err("❌ RPC call to run replaceGlobalWithAnonPage failed\n");
		goto fail;
	}
	if (compel_rpc_sync(PARASITE_CMD_REMAP_ANON, ctl) < 0) {
		pr_err("❌ Failed to sync back from replaceGlobalWithAnonPage\n");
		goto fail;
	}
	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	PRINT("State:%d\n", state);
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	
	return 0;

fail:
    if (compel_stop_daemon(ctl))
        pr_err("Failed to stop daemon\n");
    else
        PRINT("Daemon stopped (remap)\n");

    if (compel_cure(ctl))
        pr_err("Failed to cure\n");
    else
        PRINT("Cured! (remap)\n");

    if (compel_resume_task(restored_pid, state, state))
        pr_err("Failed to resume task\n");
    else
        PRINT("Resumed post remap\n");

    return -1   ;
}


int infection_test(int restored_pid)
{
	struct parasite_ctl *ctl = NULL;
	struct infect_ctx *ictx;
	int state;

	PRINT("\n=== [TEST] Single Infection Test ===\n");

	// Stop the target task
	state = compel_stop_task(restored_pid);
	PRINT("Stopped task, state=%d\n", state);

	// Prepare parasite control context
	ctl = compel_prepare(restored_pid);
	if (!ctl) {
		fprintf(stderr, "❌ compel_prepare failed\n");
		return -1;
	}

	// Set up the RPC interface
	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	// Inject the parasite
	if (compel_infect(ctl, 1, 0) < 0) {
		fprintf(stderr, "❌ compel_infect failed\n");
		goto fail;
	}

	// Run a test RPC command
	if (compel_rpc_call_sync(PARASITE_CMD_TEST_PRINT, ctl) < 0) {
		fprintf(stderr, "❌ RPC TEST_PRINT failed\n");
		goto fail;
	}

	PRINT("✅ Infection and RPC successful\n");

	// Clean up parasite and resume target
	if (compel_stop_daemon(ctl))
		fprintf(stderr, "⚠️ Failed to stop daemon\n");

	if (compel_cure(ctl))
		fprintf(stderr, "⚠️ Failed to cure\n");

	if (compel_resume_task(restored_pid, state, state))
		fprintf(stderr, "⚠️ Failed to resume task\n");

	return 0;
fail:
	if (ctl) {
		if (compel_stop_daemon(ctl)) fprintf(stderr, "⚠️ Failed to stop daemon\n");
		if (compel_cure(ctl)) fprintf(stderr, "⚠️ Failed to cure\n");
	}
	compel_resume_task(restored_pid, state, state);
	return -1;
}

int stealUFFD(int restored_pid)
{
	int state, uffd = -1;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	(void) state;

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))){
		PRINT("Can't prepare for infection\n");
		return -1;
	} 
	/*
	 * First -- the infection context. Most of the stuff
	 * is already filled by compel_prepare(), just set the
	 * log descriptor for parasite side, library cannot
	 * live w/o it.
	 */
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;
	parasite_setup_c_header(ctl);

	if (compel_infect(ctl, 1, sizeof(int)) < 0) {
		PRINT("Failed infection steal UFFD\n");
		xfree(ctl);
		return -1;
	}	
	if (compel_rpc_call(PARASITE_CMD_STEAL_UFFD, ctl) < 0) {
		pr_err("❌ RPC call to steal UFFD failed\n");
		goto fail;
	}
	if (compel_util_recv_fd(ctl, &uffd) < 0) {
		pr_err("❌ Failed to receive UFFD from parasite\n");
		goto fail;
	}
	if (compel_rpc_sync(PARASITE_CMD_STEAL_UFFD, ctl) < 0) {
		pr_err("❌ Failed to sync\n");
		goto fail;
	}
	pr_info("✅ UFFD = %d\n", uffd);

	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	else PRINT("Daemon stopped (steal UFFD)\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	else PRINT("Cured! (steal UFFD)\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	else PRINT("Resumed post steal UFFD\n");

	return uffd;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
	return -1;
}

int read_invalidate(int restored_pid, void *addr)
{
	int state, uffd = -1;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *args;
	(void) state;
	(void) args;

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))) return -1;

	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(ctl, 1, sizeof(int)) < 0) {
		xfree(ctl);
		return -1;
	}

	//test
	if (compel_rpc_call_sync(PARASITE_CMD_TEST_PRINT, ctl) < 0)	pr_err("RPC test failed\n");
	//Prepare the addr to pass
	args = compel_parasite_args(ctl, long);
	*args = (long)addr;

	if (compel_rpc_call(PARASITE_CMD_INVALIDATE_PAGE, ctl) < 0) {
		pr_err("❌ RPC call to READ INVALIDATE failed\n");
		goto fail;
	}

	if (compel_rpc_sync(PARASITE_CMD_INVALIDATE_PAGE, ctl) < 0) {
		pr_err("❌ Failed to sync on read invalidate\n");
		goto fail;
	}

	//ioctl_test
	//if (compel_rpc_call_sync(PARASITE_CMD_REGISTER_GLOBAL, ctl) < 0)	pr_err("parasite register global failed\n");
	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	else PRINT("Daemon stopped (read)\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	else PRINT("Cured! (read)\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	else PRINT("Resumed post read\n");

	PRINT("ctl freed post read\n");

	return uffd;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
	return -1;
}

int runMADVISE(int restored_pid, void *addr, size_t len){
	int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	struct madvise_args *args;
	(void) state;
	(void) args;

	PRINT("[DSM] Sending remote madvise(MADV_DONTNEED) request...\n");

	state = compel_stop_task(restored_pid);
	if (!(ctl = compel_prepare(restored_pid))){
		pr_err("❌ Compel prepare failed\n");
		return -1;
	} 

	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(ctl, 1, sizeof(long)) < 0) {
		xfree(ctl);
		return -1;
	}

	//Prepare the addr to pass
    args = compel_parasite_args(ctl, struct madvise_args);
	args->addr = (long)addr;
    args->length = len;  

	if (compel_rpc_call(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
		pr_err("❌ RPC call to run MADVISE failed\n");
		goto fail;
	}
	if (compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
		pr_err("❌ Failed to sync back from MADVISE\n");
		goto fail;
	}
	if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
	if (compel_cure(ctl)) pr_err("Can't cure\n");
	if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
	
	return 0;
fail:
	state = compel_stop_daemon(ctl);
	state = compel_cure(ctl);
	state = compel_resume_task(restored_pid, state, state);
	return -1;
}

void print_mutex(const unsigned char *page_data, size_t offset) {
    const pthread_mutex_t *mutex = (const pthread_mutex_t *)(page_data + offset);
    int lock = *((int *)mutex);               // __lock
    int owner = *(((int *)mutex) + 2);        // __owner
    fprintf(stderr, "[MUTEX] __lock = %d, __owner = %d\n", lock, owner);
}

int change_mutex_content(int restored_pid, int uffd, struct msg_info *dsm_msg) {
    int state, p[2];
    int * lock_ptr;
    long *args;
    unsigned char page_content[4096];
    size_t offset = 0xc0;  // ← known offset of the mutex in the page
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    PRINT("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    // Set the page address for the parasite
    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    // 🔍 Inspect and forcibly unlock the mutex
    if (offset >= 4096 - sizeof(pthread_mutex_t)) {
        fprintf(stderr, "Offset to mutex out of bounds\n");
    } else {
        // Print current mutex state
        print_mutex(page_content, offset);

        // Set __lock = 0 forcibly
        lock_ptr = (int *)(page_content + offset);
        *lock_ptr = 0;

        fprintf(stderr, "[DSM] 🔓 Forcibly unlocked mutex by setting __lock = 0\n");

        // Optionally reprint to confirm
        print_mutex(page_content, offset);
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);

    return 0;
}


int test_mutex_content(int restored_pid, int uffd, struct msg_info *dsm_msg) {
    int state, p[2];
    long *args;
    unsigned char page_content[4096];
    size_t offset;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    PRINT("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    // Set the page address for the parasite
    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    // ✅ Use print_mutex to inspect the mutex state
    offset = 0xc0;  // You must define `aligned` as base of the page
    if (offset >= 4096 - sizeof(pthread_mutex_t)) {
        fprintf(stderr, "Offset to mutex out of bounds\n");
    } else {
        print_mutex(page_content, offset);
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);

    return 0;
}

int runUnlockMutex(int restored_pid, void *mutex_addr) {
    int state;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;
    long *args;

    PRINT("[DSM] Sending remote unlock request to forcibly clear __lock...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    // Prepare the addr to pass
    args = compel_parasite_args(ctl, long);
    *args = (long)mutex_addr;

    if (compel_rpc_call(PARASITE_CMD_UNLOCK_MUTEX, ctl) < 0) {
        pr_err("❌ RPC call to unlock mutex failed\n");
        goto fail;
    }

    if (compel_rpc_sync(PARASITE_CMD_UNLOCK_MUTEX, ctl) < 0) {
        pr_err("❌ Failed to sync back from unlock\n");
        goto fail;
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    return 0;

fail:
    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    return -1;
}

int test_full_page_content(int restored_pid, int uffd, struct msg_info *dsm_msg) {
    int state, p[2];
    long *args;
    int *page_ints;
    unsigned char page_content[4096];
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    PRINT("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    // Set the page address for the parasite
    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        goto fail_pipe;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        goto fail_pipe;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        goto fail_pipe;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        goto fail_pipe;
    }

    // ✅ Print entire page as int[]
    page_ints = (int *)page_content;
    PRINT("[DSM] Dumping full 4KB page content as int array:\n");
    for (int i = 0; i < 4096 / sizeof(int); i++) {
        PRINT("  [%03d] = %d (0x%x)\n", i, page_ints[i], page_ints[i]);
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);
    return 0;

fail_pipe:
    close(p[0]);
    close(p[1]);
    return -1;
}


int test_page_content(int restored_pid, int uffd, struct msg_info *dsm_msg) {
    int state, value, p[2];
    long *args;
    unsigned char page_content[4096];
	size_t offset;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    PRINT("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    // Set the page address for the parasite
    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

	 if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    // ✅ Extract and print the value at GLOBAL_ADDR
    offset = 0xc0;
	if (offset >= 4096 - sizeof(int)) {
		fprintf(stderr, "Offset out of bounds\n");
	} else {
		memcpy(&value, &page_content[offset], sizeof(int));
		PRINT("[DSM] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);
	}

   /*
    // Handle invalidation or WP
    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        PRINT("Message is GET_PAGE_INVALIDATE -> Drop the page to INVALIDATE\n");
        if (compel_rpc_call_sync(PARASITE_CMD_TEST_PRINT, ctl) < 0) {
            fprintf(stderr, "❌ MADV_DONTNEED failed\n");
        }
    } else {
		PRINT("Message is GET_PAGE -> Enable wp to SHARED \n");
		enable_wp( uffd, (void *)dsm_msg->page_addr);
    }*/

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);

    return 0;
}

int print_global_value_from_page(void *page_buf, size_t page_len) {
    int value;
    size_t offset;

    if (!page_buf) {
        fprintf(stderr, "[print_global_value_from_page] Null buffer\n");
        return -1;
    }

    if (page_len < PAGE_SIZE) {
        fprintf(stderr, "[print_global_value_from_page] Buffer too small (len=%zu)\n", page_len);
        return -1;
    }

    offset = global_addr - aligned;
    if (offset >= PAGE_SIZE - sizeof(int)) {
        fprintf(stderr, "[print_global_value_from_page] Offset out of bounds (offset=%zu)\n", offset);
        return -1;
    }

    memcpy(&value, ((unsigned char *)page_buf) + offset, sizeof(int));
    PRINT("[DEBUG] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);

    return value;
}


int send_get_page(struct msg_info dsm_msg, int fd_handler, void *page_out) {
    size_t n;

    // 1. Send request
    if (send(fd_handler, &dsm_msg, sizeof(dsm_msg), 0) != sizeof(dsm_msg)) {
        perror("[CLIENT] Failed to send MSG_GET_PAGE_DATA");
        return -1;
    }

    // 2. Receive the page
    n = recv(fd_handler, page_out, 4096, MSG_WAITALL);
    if (n != 4096) {
        fprintf(stderr, "[CLIENT] Failed to receive full page (got %zd bytes)\n", n);
        return -1;
    }

    return 0;
}

#if 1
int handle_page_data_request(int restored_pid, int uffd, int sk, struct msg_info *dsm_msg) {
    int state, value, p[2];
    long *args;
    unsigned char page_content[4096];
    size_t offset;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    PRINT("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        xfree(ctl);
        return -1;
    }

    args = compel_parasite_args(ctl, long);
    *args = dsm_msg->page_addr;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (read(p[0], page_content, 4096) != 4096) {
        perror("read from parasite pipe");
        close(p[0]);
        close(p[1]);
        return -1;
    }

    // Send page to requesting client
    send(sk, page_content, 4096, 0);
    PRINT("✅ Page_transfer_complete to client\n");

    // Show value at global_addr for debugging
    offset = global_addr - aligned;
    if (offset >= 4096 - sizeof(int)) {
        fprintf(stderr, "Offset out of bounds\n");
    } else {
        memcpy(&value, &page_content[offset], sizeof(int));
        PRINT("[DSM] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);
    }

    // Handle invalidation or write protection
    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        PRINT("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n");
        if (compel_rpc_call_sync(PARASITE_CMD_RUN_MADVISE_SINGLE_PAGE, ctl) < 0) {
            fprintf(stderr, "❌ MADV_DONTNEED failed\n");
        }else PRINT("Madvise to invalidate page %p\n", (void *)dsm_msg->page_addr);
    } else {
        PRINT("Message is GET_PAGE → Enable WP to SHARED\n");
        enable_wp( uffd, (void *)dsm_msg->page_addr);
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");

    close(p[0]);
    close(p[1]);

    return 0;
}
#endif
/******************************** END INFECTION FUNCTIONS *******************************/

/******************************** CONTROLLER HELPER FUNCTIONS *******************************/

void read_pid(int* restored_pid)
{
	FILE *f = fopen("/tmp/criu-restored.pid", "r");
	if (!f || fscanf(f, "%d", restored_pid) != 1) {
		perror("fscanf");
		exit(EXIT_FAILURE);
	}
	fclose(f);
}

void send_sigcont(int pid){
	// Resume the stopped process
	if (kill(pid, SIGCONT) != 0) {
		perror("kill(SIGCONT)");
		exit(EXIT_FAILURE);
	}
	PRINT("[DSM Server] Sent SIGCONT to PID %d.\n", pid);
}

void send_sigstop(int pid){
	// Resume the stopped process
	if (kill(pid, SIGSTOP) != 0) {
		perror("kill(SIGSTOP)");
		exit(EXIT_FAILURE);
	}
	PRINT("[DSM Server] Sent SIGSTOP to PID %d.\n", pid);
}

void kill_and_exit(int pid){
	// Resume the stopped process
	if (kill(pid, 9) != 0) {
		perror("kill(9)");
		exit(EXIT_FAILURE);
	}
	PRINT("[DSM Server] Sent kill -9 to PID %d.\n", pid);
	// exit
	exit(0);
}

/******************************** END CONTROLLER HELPER FUNCTIONS *******************************/

/******************************** TESTING FUNCTIONS *******************************/

void command_loop(int restored_pid, int uffd, struct dsm_connection* conn) {
	long *args;
	int bin;
    unsigned char page_data[4096];
	struct msg_info dsm_msg = {0};
	(void) bin;
	(void) args;	
	(void) dsm_msg;	

    if( !DBG ){
        sleep(8);
        pr_info("Waking up thread\n");
        send_sigcont(restored_pid);
        return;
    }

    while (1) {
        int choice;
        printf("\n[DSM] Enter command:\n>");
        printf("  0 = reapply write-protection\n> ");
        printf("  1 = remote madvise(MADV_DONTNEED)\n> ");
		printf("  21 = restart process (send SIGCONT)\n> ");
		printf("  22 = stop process (send SIGSTOP)\n> ");
		printf("  3 = restart process (send compel cure)\n> ");
		printf("  4 = exit\n> ");
		printf("  5 = simple infection test\n> ");
		printf("  61 = test vmsplice\n> ");
        printf("  62 = test vmsplice full page\n> ");
        printf("  63 = Full page dump test (interactive)\n> ");
        printf("  64 = all pages registered\n> ");
		printf("  7 = SIMULATE GET_PAGE_DATA\n> ");
		printf("  8 = SIMULATE GET_PAGE_DATA_AND_INVALIDATE\n> ");
		printf("  9 = SIMULATE INVALIDATE\n> ");
		printf("  10 = WAKE UP REMOTE THREAD\n> ");
		printf("  11 = STOP REMOTE THREAD\n> ");
        printf("  12 = Show mutex page content\n> ");
        printf("  13 = Change mutex lock\n> ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            printf("Invalid input\n");
            while (getchar() != '\n'); // flush
            continue;
        }

        if (choice == 0) {
            printf("[DSM] Reapplying write-protection on global page...\n");
			enable_wp( uffd, (void *) aligned);
        } else if (choice == 1) {
			printf("[DSM] Sending remote madvise(MADV_DONTNEED) request...\n");
			if( runMADVISE( restored_pid, (void *) aligned, 4096))
				perror("runMADVISE command loop");
			else
				printf("Successfully run madvise on page at %p\n", (void *) aligned);
        } else if (choice == 21){
			// Resume the stopped process
			send_sigcont(restored_pid);
		} else if (choice == 22){
			// Stop the resumed process
			send_sigstop(restored_pid);
		}else if( choice == 3 ) {
			// Resume the stopped process
			if (compel_resume_task(restored_pid, 3, 3)) pr_err("Can't resume\n");
			printf("[DSM Server] Sent compel resume to PID %d.\n", restored_pid);
		} else if( choice == 4 ) {
			kill_and_exit(restored_pid);
		} else if( choice == 5 ) {
			//Infection test
			printf("Do infection test\n");
			infection_test(restored_pid);			
		}else if( choice == 61 ){
			//vmsplice test
			printf("Do vmsplice test at %p\n", (void *)aligned);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			printf("Do vmsplice test at %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_page_content(restored_pid, uffd, &dsm_msg);
		}else if( choice == 62 ){
			//vmsplice test
			printf("Do vmsplice test at %p\n", (void *)aligned);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			printf("Do vmsplice test at %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_full_page_content(restored_pid, uffd, &dsm_msg);
		}else if( choice == 63 ){
            // Full page dump test (interactive)
            unsigned long input_addr;
            printf("[DSM] Enter address to dump (in hex, e.g. 0x555555559380): ");
            fflush(stdout);
            if (scanf("%lx", &input_addr) != 1) {
                fprintf(stderr, "❌ Invalid input\n");
                kill_and_exit(restored_pid);
            }printf("[DSM] Address entered: %lx \n",input_addr );

            // Prepare dsm_msg
            dsm_msg.msg_type = MSG_SEND_INVALIDATE;  // or anything suitable
            dsm_msg.page_addr = input_addr;
            dsm_msg.msg_id = 1;

            printf("[DSM] Dumping page at address: 0x%lx\n", input_addr);

            test_full_page_content(restored_pid, uffd, &dsm_msg);
        }else if( choice == 64 ){
            // ✅ Now list all registered pages
            printf("\n📋 Registered pages in page_list_data:\n");
            for (int i = 0; i < total_pages; ++i) {
                printf("  [%03d] %p\n", i, (void *)page_list_data[i].saddr);
            }
        }else if (choice == 7) {
			// SIMULATE GET_PAGE_DATA
			dsm_msg.msg_type = MSG_GET_PAGE_DATA;
			dsm_msg.page_addr = aligned;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
            if (send_get_page(dsm_msg, conn->fd_handler, page_data) == 0) {
                print_global_value_from_page(page_data, sizeof(page_data));
            }
		} else if (choice == 8) {
			// SIMULATE GET_PAGE_DATA_AND_INVALIDATE
			dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
			dsm_msg.page_addr = aligned;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
            if (send_get_page(dsm_msg, conn->fd_handler, page_data) == 0) {
                print_global_value_from_page(page_data, sizeof(page_data));
            }
            printf("[CLIENT] Sent MSG_GET_PAGE_DATA_INVALID to server.\n");
		} else if (choice == 9) {
			// SIMULATE INVALIDATE
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			printf("[CLIENT] Sent MSG_SEND_INVALIDATE to server.\n");
		}else if (choice == 10) {
			dsm_msg.msg_type = MSG_WAKE_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			printf("[CLIENT] Sent MSG_WAKE_THREAD to server.\n");
		}else if (choice == 11) {
			dsm_msg.msg_type = MSG_STOP_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			printf("[CLIENT] Sent MSG_STOP_THREAD to server.\n");
		}else if (choice == 12) {
            //vmsplice test
			printf("Print mutex content test at %p\n", (void *)0x0c0);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			printf("Do vmsplice test at page %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_mutex_content(restored_pid, uffd, &dsm_msg);
        }else if (choice == 13){
			printf("Change mutex content %p\n", (void *)0x5555555580c0);
			runUnlockMutex(restored_pid, (void *)0x5555555580c0);
        }else {
            printf("[DSM] Unknown command: %d\n", choice);
        }
    }
}

/******************************** TESTING FUNCTIONS *******************************/


