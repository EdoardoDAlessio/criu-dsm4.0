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
#include "dsm_log.h"
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
#define ACK_WRITE_PROTECT_EXPIRED 0x11
// Setup global variable address 
int log_level = 2; //default log level
void *zero_page = NULL;
unsigned long barrier_local = 0;
unsigned long barrier_remote = 0;
unsigned long barrier_start_address = 0;
unsigned long barrier_end_address = 0;
unsigned long mutex_lock_start_address = 0;
unsigned long mutex_lock_end_address = 0;
unsigned long mutex_unlock_start_address = 0;
unsigned long mutex_unlock_end_address = 0;

unsigned long page_thread0 = 0;
unsigned long page_thread1 = 0;
//barrier_state_t barrier = {0};
barrier_state barrier = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .epoch = 0,
    .released_epoch = -1,
};
int remote_threads_barrier_arrived = 0;
unsigned long global_addr = 0x555555558080;
unsigned long aligned = 0x555555558080 & ~(PAGE_SIZE - 1);

unsigned long start_address, end_address;
pthread_mutex_t pagefaults_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t mutex_l = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  mutex_cond   = PTHREAD_COND_INITIALIZER;
unsigned long ticket_next = 0;
unsigned long ticket_serving = 0;

// Global or shared debug map
pthread_mutex_t fault_lock = PTHREAD_MUTEX_INITIALIZER;
unsigned long active_fault_addr = 0;
unsigned long remote_barrier_addr = 0;
unsigned long local_barrier_addr = 0;
int active_fault_tid = -1;
page_list page_list_data[MAX_PAGE_COUNT];
int total_pages = 0;
int uffd, restored_pid, local_threads, pidfd;
int fault_counter = 0;
/*
unsigned long global_addr = 0x5555555580c0;
unsigned long aligned = 0x5555555580c0 & ~(PAGE_SIZE - 1);
unsigned long global_addr = 0x7fffffffe5dc;
unsigned long aligned = 0x7fffffffe5dc & ~(PAGE_SIZE - 1);*/
/***************** END USERFAULTFD HEADERS ************************/

void barrier_init(void) {
    pthread_mutex_init(&barrier.lock, NULL);
    pthread_cond_init(&barrier.cond, NULL);
}


#if RDMA_ENABLE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "dsm.h"
rdma_context z_handler, z_receiver, z_data;
rdma_context z_handler_data, z_receiver_data;
rdma_wire_all local_all;
rdma_wire_all remote_all;
rdma_endpoint endpoints[N_CLIENTS];

int readn_all_exact(int fd, void *buf, size_t n)
{
    char *p;
    ssize_t r;
    size_t left;
    p = (char*)buf;
    left = n;
    while (left > 0) {
        r = recv(fd, p, left, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        p += r;
        left -= (size_t)r;
    }
    return 0;
}

int writen_all_exact(int fd, const void *buf, size_t n)
{
    const char *p;
    ssize_t w;
    size_t left;
    p = (const char*)buf;
    left = n;
    while (left > 0) {
        w = send(fd, p, left, 0);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += w;
        left -= (size_t)w;
    }
    return 0;
}

int rdma_context_init(rdma_context *r)
{
    struct ibv_device **dev_list;
    int num_devices;
    struct ibv_qp_init_attr qia;
    struct ibv_qp_attr attr;

    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list || num_devices == 0) { fprintf(stderr, "[RDMA] No devices\n"); return -1; }
    r->ctx = ibv_open_device(dev_list[0]);
    ibv_free_device_list(dev_list);
    if (!r->ctx) { perror("ibv_open_device"); return -1; }

    r->pd = ibv_alloc_pd(r->ctx);
    if (!r->pd) { perror("ibv_alloc_pd"); ibv_close_device(r->ctx); return -1; }

    r->cq = ibv_create_cq(r->ctx, 256, NULL, NULL, 0);
    if (!r->cq) { perror("ibv_create_cq"); ibv_dealloc_pd(r->pd); ibv_close_device(r->ctx); return -1; }

    memset(&qia, 0, sizeof(qia));
    qia.send_cq = r->cq;
    qia.recv_cq = r->cq;
    qia.qp_type = IBV_QPT_RC;
    qia.cap.max_send_wr  = 128;
    qia.cap.max_recv_wr  = 128;
    qia.cap.max_send_sge = 1;
    qia.cap.max_recv_sge = 1;

    r->qp = ibv_create_qp(r->pd, &qia);
    if (!r->qp) { perror("ibv_create_qp"); ibv_destroy_cq(r->cq); ibv_dealloc_pd(r->pd); ibv_close_device(r->ctx); return -1; }

    memset(&attr, 0, sizeof(attr));
    attr.qp_state        = IBV_QPS_INIT;
    attr.pkey_index      = 0;
    attr.port_num        = 1;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

    if (ibv_modify_qp(r->qp, &attr,
                      IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
        perror("ibv_modify_qp INIT");
        ibv_destroy_qp(r->qp); ibv_destroy_cq(r->cq); ibv_dealloc_pd(r->pd); ibv_close_device(r->ctx);
        return -1;
    }

    memset(&r->port_attr, 0, sizeof(r->port_attr));
    if (ibv_query_port(r->ctx, 1, &r->port_attr)) { perror("ibv_query_port"); return -1; }

    memset(&r->gid, 0, sizeof(r->gid));
    if (ibv_query_gid(r->ctx, 1, 0, &r->gid)) { /* ok if zero on IB */ }

    r->psn = (uint32_t)(rand() & 0xFFFFFFu);

    return 0;
}

int init_rdma_zone(rdma_context *ctx, const char *path, size_t size, int use_huge)
{
    void *addr;
    int fd;

    fd = -1;
    if (use_huge) {
        fd = open(path ? path : "/tmp/rdma_zone.bin", O_CREAT | O_RDWR, 0666);
        if (fd < 0) { perror("open"); return -1; }
        if (ftruncate(fd, (off_t)size) < 0) { perror("ftruncate"); close(fd); return -1; }
        addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_HUGETLB, fd, 0);
    } else {
        addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    }
    if (addr == MAP_FAILED) { perror("mmap"); if (fd>=0) close(fd); return -1; }
    if (fd >= 0) close(fd);

    ctx->mr = ibv_reg_mr(ctx->pd, addr, size,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (!ctx->mr) { perror("ibv_reg_mr"); munmap(addr, size); return -1; }

    ctx->base_addr = addr;
    ctx->length    = size;
    ctx->rkey      = ctx->mr->rkey;
    ctx->lkey      = ctx->mr->lkey;
    return 0;
}

void fill_conn_info_from_ctx(rdma_context *c,
                             uint16_t lid,
                             const uint8_t gid[16],
                             rdma_wire_info *out)
{
    memset(out, 0, sizeof(*out));
    out->qp_num = htonl(c->qp->qp_num);
    out->lid    = htons(lid);
    memcpy(out->gid, gid, 16);
    out->psn    = htonl(c->psn);
    out->rkey   = htonl(c->rkey);
    out->vaddr  = htobe64((uint64_t)(uintptr_t)c->base_addr);
}

void qp_to_rtr_rts(struct ibv_qp *qp,
                   const struct ibv_port_attr *pa,
                   const rdma_wire_info *peer,
                   uint32_t local_psn,
                   uint8_t sgid_idx,
                   uint8_t port)
{
    struct ibv_qp_attr a;
    int flags;

    /* RTR */
    memset(&a, 0, sizeof(a));
    a.qp_state           = IBV_QPS_RTR;
    a.path_mtu           = pa->active_mtu;
    a.dest_qp_num        = ntohl(peer->qp_num);
    a.rq_psn             = ntohl(peer->psn);
    a.max_dest_rd_atomic = 1;
    a.min_rnr_timer      = 12;
    a.ah_attr.port_num   = port;

    if (pa->link_layer == IBV_LINK_LAYER_INFINIBAND) {
        a.ah_attr.is_global = 0;
        a.ah_attr.dlid      = ntohs(peer->lid);
    } else {
        a.ah_attr.is_global      = 1;
        a.ah_attr.grh.hop_limit  = 1;
        a.ah_attr.grh.sgid_index = sgid_idx;
        memcpy(&a.ah_attr.grh.dgid, peer->gid, 16);
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
            IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
            IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    if (ibv_modify_qp(qp, &a, flags)) { perror("modify_qp RTR"); exit(1); }

    /* RTS */
    memset(&a, 0, sizeof(a));
    a.qp_state      = IBV_QPS_RTS;
    a.timeout       = 14;
    a.retry_cnt     = 7;
    a.rnr_retry     = 7;
    a.sq_psn        = (local_psn & 0xFFFFFFu);
    a.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    if (ibv_modify_qp(qp, &a, flags)) { perror("modify_qp RTS"); exit(1); }
}

void post_one_recv(rdma_context *ctx)
{
    struct ibv_sge sge;
    struct ibv_recv_wr wr;
    struct ibv_recv_wr *bad;
    uint32_t len;

    len = (ctx->length >= 4) ? 4u : (uint32_t)ctx->length;
    memset(&sge, 0, sizeof(sge));
    sge.addr   = (uintptr_t)ctx->base_addr;
    sge.length = len;
    sge.lkey   = ctx->lkey;

    memset(&wr, 0, sizeof(wr));
    wr.wr_id   = (uintptr_t)ctx;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    bad = NULL;
    if (ibv_post_recv(ctx->qp, &wr, &bad)) {
        fprintf(stderr, "[RDMA] ibv_post_recv failed\n");
    }
}

void poll_one_cqe(rdma_context *ctx, struct ibv_wc *wc)
{
    int n;
    for (;;) {
        n = ibv_poll_cq(ctx->cq, 1, wc);
        if (n != 0) break;
    }
    if (n < 0) { fprintf(stderr, "CQ poll error\n"); exit(1); }
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "CQE error: %s (opcode=%d)\n", ibv_wc_status_str(wc->status), wc->opcode);
        exit(1);
    }
}

int pick_valid_sgid_index(struct ibv_context *ctx, uint8_t port,
                                 uint8_t *out_idx, union ibv_gid *out_gid)
{
    int idx;
    union ibv_gid g;

    for (idx = 0; idx < 16; idx++) {
        if (ibv_query_gid(ctx, port, idx, &g) != 0)
            continue;

        /* skip all-zero gid */
        if (((uint64_t*)g.raw)[0] == 0 && ((uint64_t*)g.raw)[1] == 0)
            continue;

        *out_idx = (uint8_t)idx;
        if (out_gid) *out_gid = g;
        PRINT("[RDMA] pick_valid_sgid_index: using gid_index=%d "
               "gid=%02x:%02x:%02x:%02x:%02x:%02x:... (port=%u)\n",
               idx,
               g.raw[0], g.raw[1], g.raw[2], g.raw[3], g.raw[4], g.raw[5],
               (unsigned)port);
        return 0;
    }
    fprintf(stderr, "[RDMA] No valid GID found on port %u\n", (unsigned)port);
    return -1;
}


void rdma_write_core(rdma_context *ctx,
                     uint64_t remote_addr, uint32_t remote_rkey,
                     const void *src, size_t len, uint32_t imm)
{
    struct ibv_send_wr wr;
    struct ibv_send_wr *bad;
    struct ibv_sge s;
    struct ibv_wc wc;

    memset(&wr, 0, sizeof(wr));
    memset(&s, 0, sizeof(s));

    s.addr = (uintptr_t)src;
    s.length = (uint32_t)len;
    s.lkey = ctx->lkey;

    wr.sg_list = &s;
    wr.num_sge = 1;
    wr.opcode = imm ? IBV_WR_RDMA_WRITE_WITH_IMM : IBV_WR_RDMA_WRITE;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = remote_addr;
    wr.wr.rdma.rkey = remote_rkey;
    if (imm) wr.imm_data = htonl(imm);

    bad = NULL;
    ibv_post_send(ctx->qp, &wr, &bad);
    poll_one_cqe(ctx, &wc);
}
#elif 0

#include "dsm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>

#define RDMA_PORT 1

#define DIE_IF(cond, msg) \
    do { if (cond) { perror(msg); exit(EXIT_FAILURE); } } while (0)

int rdma_context_init(rdma_context *c)
{
    struct ibv_device **devs;
    int n;
    struct ibv_qp_init_attr qia;
    struct ibv_qp_attr a;
    int ret;

    memset(c, 0, sizeof(*c));

    devs = ibv_get_device_list(&n);
    DIE_IF(!devs || !n, "no RDMA devices");

    c->ctx = ibv_open_device(devs[0]);
    DIE_IF(!c->ctx, "ibv_open_device");
    ibv_free_device_list(devs);

    DIE_IF(ibv_query_port(c->ctx, RDMA_PORT, &c->port_attr), "ibv_query_port");
    DIE_IF(ibv_query_gid(c->ctx, RDMA_PORT, 0, &c->gid), "ibv_query_gid");

    c->pd = ibv_alloc_pd(c->ctx);
    DIE_IF(!c->pd, "ibv_alloc_pd");

    c->cq = ibv_create_cq(c->ctx, 16, NULL, NULL, 0);
    DIE_IF(!c->cq, "ibv_create_cq");

    DIE_IF(posix_memalign(&c->base_addr, 4096, 4096) != 0, "memalign");
    c->length = 4096;
    c->mr = ibv_reg_mr(c->pd, c->base_addr, c->length,
                       IBV_ACCESS_LOCAL_WRITE |
                       IBV_ACCESS_REMOTE_WRITE |
                       IBV_ACCESS_REMOTE_READ);
    DIE_IF(!c->mr, "ibv_reg_mr");
    c->rkey = c->mr->rkey;
    c->lkey = c->mr->lkey;

    memset(&qia, 0, sizeof(qia));
    qia.send_cq = c->cq;
    qia.recv_cq = c->cq;
    qia.qp_type = IBV_QPT_RC;
    qia.cap.max_send_wr = 16;
    qia.cap.max_recv_wr = 16;
    qia.cap.max_send_sge = 1;
    qia.cap.max_recv_sge = 1;
    qia.cap.max_inline_data = 128;

    c->qp = ibv_create_qp(c->pd, &qia);
    DIE_IF(!c->qp, "ibv_create_qp");

    memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_INIT;
    a.port_num = RDMA_PORT;
    a.pkey_index = 0;
    a.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
                        IBV_ACCESS_REMOTE_WRITE |
                        IBV_ACCESS_REMOTE_READ;
    ret = ibv_modify_qp(c->qp, &a,
                        IBV_QP_STATE |
                        IBV_QP_PKEY_INDEX |
                        IBV_QP_PORT |
                        IBV_QP_ACCESS_FLAGS);
    DIE_IF(ret, "INIT");

    srand((unsigned)time(NULL));
    c->psn = rand() & 0xffffff;
    c->max_inline = qia.cap.max_inline_data;

    return 0;
}

void rdma_cleanup(rdma_context *c)
{
    if (!c) return;
    if (c->qp) ibv_destroy_qp(c->qp);
    if (c->cq) ibv_destroy_cq(c->cq);
    if (c->mr) ibv_dereg_mr(c->mr);
    if (c->pd) ibv_dealloc_pd(c->pd);
    if (c->ctx) ibv_close_device(c->ctx);
    free(c->base_addr);
}
int pick_valid_sgid_index(struct ibv_context *ctx, uint8_t port,
                                 uint8_t *out_idx, union ibv_gid *out_gid)
{
    int idx;
    union ibv_gid g;

    for (idx = 0; idx < 16; idx++) {
        if (ibv_query_gid(ctx, port, idx, &g) != 0)
            continue;

        /* skip all-zero gid */
        if (((uint64_t*)g.raw)[0] == 0 && ((uint64_t*)g.raw)[1] == 0)
            continue;

        *out_idx = (uint8_t)idx;
        if (out_gid) *out_gid = g;
        PRINT("[RDMA] pick_valid_sgid_index: using gid_index=%d "
               "gid=%02x:%02x:%02x:%02x:%02x:%02x:... (port=%u)\n",
               idx,
               g.raw[0], g.raw[1], g.raw[2], g.raw[3], g.raw[4], g.raw[5],
               (unsigned)port);
        return 0;
    }
    fprintf(stderr, "[RDMA] No valid GID found on port %u\n", (unsigned)port);
    return -1;
}

/* dsm.c */
void qp_to_rtr_rts(struct ibv_qp *qp,
                   const struct ibv_port_attr *pa,
                   const rdma_wire_info *peer,
                   uint32_t local_psn,
                   uint8_t sgid_idx,
                   uint8_t port)
{
    struct ibv_qp_attr a;
    int flags;

    memset(&a, 0, sizeof(a));
    /* --- RTR --- */
    a.qp_state           = IBV_QPS_RTR;
    a.path_mtu           = pa->active_mtu;
    a.dest_qp_num        = ntohl(peer->qp_num);
    a.rq_psn             = ntohl(peer->psn);        /* expect peer’s SQ PSN */
    a.max_dest_rd_atomic = 1;
    a.min_rnr_timer      = 12;
    a.ah_attr.port_num   = port;

    if (pa->link_layer == IBV_LINK_LAYER_INFINIBAND) {
        a.ah_attr.is_global = 0;
        a.ah_attr.dlid      = ntohs(peer->lid);
    } else {
        a.ah_attr.is_global        = 1;
        a.ah_attr.grh.hop_limit    = 1;
        a.ah_attr.grh.sgid_index   = sgid_idx;
        memcpy(&a.ah_attr.grh.dgid, peer->gid, 16);
    }

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
            IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
            IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    if (ibv_modify_qp(qp, &a, flags)) { perror("RTR"); exit(1); }

    /* --- RTS --- */
    memset(&a, 0, sizeof(a));
    a.qp_state      = IBV_QPS_RTS;
    a.timeout       = 14;
    a.retry_cnt     = 7;
    a.rnr_retry     = 7;
    a.sq_psn        = local_psn & 0xFFFFFF;   /* MUST match what you sent in local.psn */
    a.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
            IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    if (ibv_modify_qp(qp, &a, flags)) { perror("RTS"); exit(1); }
}



void post_one_recv(rdma_context *ctx)
{
    struct ibv_sge s;
    struct ibv_recv_wr wr;
    struct ibv_recv_wr *bad;

    memset(&s, 0, sizeof(s));
    s.addr = (uintptr_t)ctx->base_addr;
    s.length = 4;
    s.lkey = ctx->lkey;

    memset(&wr, 0, sizeof(wr));
    wr.sg_list = &s;
    wr.num_sge = 1;

    bad = NULL;
    ibv_post_recv(ctx->qp, &wr, &bad);
}

void poll_one_cqe(rdma_context *ctx, struct ibv_wc *wc)
{
    int n;
    for (;;) {
        n = ibv_poll_cq(ctx->cq, 1, wc);
        if (n == 1) break;
    }
}

void rdma_write_core(rdma_context *ctx,
                     uint64_t remote_addr, uint32_t remote_rkey,
                     const void *src, size_t len, uint32_t imm)
{
    struct ibv_send_wr wr;
    struct ibv_send_wr *bad;
    struct ibv_sge s;
    struct ibv_wc wc;

    memset(&wr, 0, sizeof(wr));
    memset(&s, 0, sizeof(s));

    s.addr = (uintptr_t)src;
    s.length = (uint32_t)len;
    s.lkey = ctx->lkey;

    wr.sg_list = &s;
    wr.num_sge = 1;
    wr.opcode = imm ? IBV_WR_RDMA_WRITE_WITH_IMM : IBV_WR_RDMA_WRITE;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = remote_addr;
    wr.wr.rdma.rkey = remote_rkey;
    if (imm) wr.imm_data = htonl(imm);

    bad = NULL;
    ibv_post_send(ctx->qp, &wr, &bad);
    poll_one_cqe(ctx, &wc);
}

int readn_all_exact(int fd, void *buf, size_t n) {
    char *p = (char*)buf; size_t left = n; ssize_t r;
    while (left) { r = recv(fd, p, left, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1; 
        p += r; left -= (size_t)r; }
    return 0;
}
int writen_all_exact(int fd, const void *buf, size_t n) {
    const char *p = (const char*)buf; size_t left = n; ssize_t w;
    while (left) { w = send(fd, p, left, 0);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1; 
        p += w; left -= (size_t)w; }
    return 0;
}

#endif

/*********************************** VMA RECONSTRUCTION ********************* */

#include "vma.h"
#include "mem.h"       // Required for xmalloc()
#include "cr_options.h"

struct vm_area_list* my_vm_area_list;

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



void mark_fault_start(unsigned long addr, const char *who, pid_t tid) {
    pthread_mutex_lock(&fault_lock);
    if (active_fault_addr == addr) {
        fprintf(stderr,
            "⚠️  [RACE] %s (tid=%d) started handling page %lx "
            "while already active by tid=%d!\n",
            who, tid, addr, active_fault_tid);
    } else {
        active_fault_addr = addr;
        active_fault_tid = tid;
        fprintf(stderr, "[TRACE] %s begins page %lx (tid=%d)\n", who, addr, tid);
    }
    pthread_mutex_unlock(&fault_lock);
}

void mark_fault_end(unsigned long addr, const char *who, pid_t tid) {
    pthread_mutex_lock(&fault_lock);
    if (active_fault_addr == addr && active_fault_tid == tid) {
        active_fault_addr = 0;
        active_fault_tid = -1;
        fprintf(stderr, "[TRACE] %s done page %lx (tid=%d)\n", who, addr, tid);
    } else {
        fprintf(stderr,
            "⚠️  [UNSYNC END] %s (tid=%d) ended handling %lx, but current active=%lx by %d\n",
            who, tid, addr, active_fault_addr, active_fault_tid);
    }
    pthread_mutex_unlock(&fault_lock);
}

void init_zero_page(void) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    if (!page_size) page_size = 4096; // fallback

    // Allocate a page-aligned anonymous mapping
    zero_page = mmap(NULL, page_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (zero_page == MAP_FAILED) {
        perror("mmap zero_page");
        exit(1);
    }

    // Fill it with zeros
    memset(zero_page, 0, page_size);
}


// Register region with userfaultfd for missing page faults
int register_region_with_uffd(int uffd, void *addr, size_t length) {
    struct uffdio_register reg;
    
    if (uffd == -1) return -1;
    
    // Register for both missing page faults and write protection
    reg.range.start = (unsigned long)addr;
    reg.range.len = length;
    reg.mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
    //reg.mode = UFFDIO_REGISTER_MODE_WP;
    
    if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
        PRINT("Failing to register %p \n", addr);
        perror("ioctl UFFDIO_REGISTERR");
        exit(-1);
        //return -1;
    }
    
    PRINT("[DSM] Successfully registered region: %p - %p (%zu bytes)\n", addr, (char*)addr + length, length);
    return 0;
}

void enable_region_wp( int uffd, void *addr, size_t length) {
	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = length,
		.mode = UFFDIO_WRITEPROTECT_MODE_WP  
	};
    
    if (uffd == -1) exit(-1);


	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1){
		perror("UFFDIO_WRITEPROTECT (enable_region)");
        exit(-1);
    }
	else
		PRINT("[DSM] Successfully ENABLE WP on region: %p - %p (%zu bytes)\n", addr, (char*)addr + length, length);
}

void disable_region_wp( int uffd, void *addr, size_t length) {

	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = 0  // no WP flag
	};

    if (uffd == -1) exit(-1);

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1)
		perror("UFFDIO_WRITEPROTECT (disable_region)");
	else
		PRINT("[DSM] Successfully DISABLE WP on region: %p - %p (%zu bytes)\n", addr, (char*)addr + length, length);
}






int check_process_state(int pid) {
    int ret; 
    char stat_path[64], state;
    FILE *f;
    
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    f = fopen(stat_path, "r");
    if (!f) return -1;
    
    ret = fscanf(f, "%*d %*s %c", &state);
    fclose(f);
    PRINT("Process state:%c\n", state);
    if (state == 'D') {
        pr_warn("Process %d in uninterruptible sleep\n", pid);
        return 1; // Problematic state
    }
    ret = 0;
    return ret;
}




static PageAlloc allocs[MAX_PAGES];
static size_t alloc_count = 0;

void read_store_malloced_pages(void) {
    FILE *fp = fopen("/tmp/mmapalloc_log", "r");
    char type;
    uintptr_t aligned_addr, addr;
    size_t size;

    if (!fp) {
        perror("fopen");
        return;
    }   

    while (fscanf(fp, " %c %lx %lx %zu", &type, &aligned_addr, &addr, &size) == 4) {
        size_t npages = size / PAGE_SIZE;

        if (type == 'm') {
            if (alloc_count >= MAX_PAGES) {
                fprintf(stderr, "⚠️ alloc array full, skipping\n");
                exit(-1);
            }
            allocs[alloc_count].aligned_addr = aligned_addr;
            allocs[alloc_count].addr = addr;
            allocs[alloc_count].npages = npages;
            alloc_count++;
        } else if (type == 'f') {
            // look for matching entry
            for (size_t i = 0; i < alloc_count; i++) {
                if (allocs[i].aligned_addr == aligned_addr && allocs[i].npages == npages) {
                    // remove by shifting down
                    for (size_t j = i; j < alloc_count - 1; j++) {
                        allocs[j] = allocs[j+1];
                    }
                    alloc_count--;
                    break;
                }
            }
        }
    }

    fclose(fp);

    // Debug print what we have left
    PRINT("== Active mallocs ==\n");
    for (size_t i = 0; i < alloc_count; i++) {
        PRINT("aligned_addr: 0x%lx, addr: 0x%lx, npages: %zu\n",
               (unsigned long)allocs[i].aligned_addr, 
               (unsigned long)allocs[i].addr, 
               allocs[i].npages);
    }
}


static int dump_one_page_with_parasite(struct parasite_ctl *ctl, unsigned long page_base, unsigned char out[PAGE_SIZE]){
    int p[2] = {-1, -1};
    int rc = -1;
    unsigned long *pargs;

    if (pipe(p) < 0) {
        perror("pipe");
        return -1;
    }

    // Set parasite arg = page_base
    pargs = compel_parasite_args(ctl, unsigned long);
    *pargs = page_base;

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE call failed\n");
        goto out;
    }
    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "Failed to send pipe fd\n");
        goto out;
    }
    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "RPC DUMP_SINGLE sync failed\n");
        goto out;
    }

    if (read(p[0], out, PAGE_SIZE) != PAGE_SIZE) {
        perror("read page from parasite");
        goto out;
    }

    rc = 0;
out:
    if (p[0] != -1) close(p[0]);
    if (p[1] != -1) close(p[1]);
    return rc;
}


// Read a target-process long at `addr` using an ALREADY-INFECTED `ctl`.
static int read_long_at_addr_infected(struct parasite_ctl *ctl, unsigned long addr, long *out_val){
    unsigned long page_base0 = addr & ~(unsigned long)(PAGE_SIZE - 1);
    size_t offset = (size_t)(addr - page_base0), first, second;
    unsigned char page0[PAGE_SIZE], tmp[sizeof(long)];

    if (!ctl || !out_val) return -1;

    if (dump_one_page_with_parasite(ctl, page_base0, page0) < 0)
        return -1;

    if (offset + sizeof(long) <= PAGE_SIZE) {
        memcpy(out_val, page0 + offset, sizeof(long));
        return 0;
    } else {
        // Cross-page case: dump next page and stitch
        unsigned char page1[PAGE_SIZE];
        if (dump_one_page_with_parasite(ctl, page_base0 + PAGE_SIZE, page1) < 0)
            return -1;

        first  = PAGE_SIZE - offset;
        second = sizeof(long) - first;
        memcpy(tmp,           page0 + offset, first);
        memcpy(tmp + first,   page1,          second);
        memcpy(out_val, tmp, sizeof(long));
        return 0;
    }
}

unsigned long register_special_pages(void){
    uintptr_t addr = 0;
    FILE *f = fopen("/tmp/dsm_special_page.txt", "r");
    if (!f) {
        fprintf(stderr, "[register_special_pages] Cannot open /tmp/dsm_special_page.txt: %s\n",
                strerror(errno));
        return 0;
    }

    
    if (fscanf(f, "%lx", &addr) != 1) {
        fprintf(stderr, "[register_special_pages] Failed to read address from file\n");
        fclose(f);
        return 0;
    }
    fclose(f);

    fprintf(stderr, "[register_special_pages] Special page address read: 0x%lx\n", addr);
    return (unsigned long)addr;
}


void register_all(int uffd, int restored_pid, unsigned long base_addr, struct vm_area_list *list, page_status status) {
    char path[64], line[512], type[32], bind[32], vis[32], name[32], symbol[128], perms[5], dev[6], mapname[PATH_MAX];
    FILE *fp, *fp_readelf = fopen("/tmp/readelf.txt", "r");
    int inode, is_anon, is_criumfd, idx, section_idx, matched, malloced;
    struct vma_area *vma;
    unsigned long offset, start, end, aligned_start, aligned_end, size;

    //Parasite
    int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *args;
    struct madvise_args *madvise_arg;

	(void) state;
	(void) args;


    //Check infectability
    if (check_process_state(restored_pid) == 1) {
        pr_err("Process in uninterruptible sleep - cannot proceed\n");
        return;
    }

    //Infect once for all 
	state = compel_stop_task(restored_pid);
	PRINT("Compel task stopped\n");
	if (!(ctl = compel_prepare(restored_pid))){
		pr_err("❌ Compel prepare failed\n");
		return;
	} 
	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;
	if (compel_infect(ctl, 1, sizeof(long)) < 0) {
		xfree(ctl);
		return;
	}
    /*END INFECTION*/

    //1. First scan maps
    snprintf(path, sizeof(path), "/proc/%d/maps", restored_pid);
    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        int prot = 0;
        mapname[0] = '\0';  // Ensure mapname is cleared each line

        if (sscanf(line, "%lx-%lx %4s %lx %5s %d %[^\n]", &start, &end, perms, &offset, dev, &inode, mapname) < 6)
            continue;

        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        
        is_anon = (strlen(mapname) == 0 || mapname[0] == '\0');
        

        if ( is_anon & (prot & PROT_READ) && (prot & PROT_WRITE)) {
            size_t npages = (end - start) / PAGE_SIZE;
            // Only consider anonymous mappings (empty or space-only pathname)
            is_criumfd = !strcmp( mapname, "/memfd:CRIUMFD (deleted)" );
          
            if( is_criumfd ){
                /*
                There is an address that appears to be part of a memfd region. If attempted to register
                the failing mapping will show /memfd:CRIUMFD (deleted), which indicates this is a memory 
                file descriptor created by CRIU for its internal operations.
                Therefore we will exclude it manually from the selection with is_criumfd
                */

                continue;
            }

            if (total_pages + npages > MAX_PAGE_COUNT) {
                fprintf(stderr, "⚠️  Too many pages, increase MAX_PAGE_COUNT\n");
                break;
            }

            /**/
            for (size_t i = 0; i < npages; i++) {
                page_list_data[total_pages + i].owner_mask = 0;
                page_list_data[total_pages + i].index_of_allocs = 0;
                page_list_data[total_pages + i].state = status;
                page_list_data[total_pages + i].saddr = start + i * PAGE_SIZE;
                
                
                if( !is_anon ){
                    //PRINT("\t\tInfection to remapping anon\n");
                    //Infection for remapping to anonimous page to allow uffdio registerability
                    args = compel_parasite_args(ctl, long);
                    *args = (long) page_list_data[total_pages + i].saddr;
                    if (compel_rpc_call(PARASITE_CMD_REMAP_ANON, ctl) < 0) {
                        pr_err("❌ RPC call to run replaceGlobalWithAnonPage failed\n");
                        goto fail;
                    }
                    if (compel_rpc_sync(PARASITE_CMD_REMAP_ANON, ctl) < 0) {
                        pr_err("❌ Failed to sync back from replaceGlobalWithAnonPage\n");
                        goto fail;
                    }
                }
                //try
                //register_page( uffd, (void*)start + i * PAGE_SIZE);
                //enable_wp( uffd, (void *) start + i * PAGE_SIZE );
            }
            total_pages += npages;

            PRINT("%lx-%lx %4s %lx %5s %d 11%s11\n", start, end, perms, offset, dev, inode, mapname);
            
            //tracking
            register_region_with_uffd(uffd, (void*)start, end - start );
            

            ///todo change the location of enabling
            if( status == SHARED ) enable_region_wp( uffd, (void*)start, end - start );
            //else if( status == MODIFIED ) disable_region_wp( uffd, (void*)start, end - start );
            else if( status == INVALID ){
                //Prepare the addr to pass
                madvise_arg = compel_parasite_args(ctl, struct madvise_args);
                madvise_arg->addr = (long)start;
                madvise_arg->length = end - start;  

                if (compel_rpc_call(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
                    pr_err("❌ RPC call to run MADVISE (register all) failed\n");
                    goto fail;
                }
                if (compel_rpc_sync(PARASITE_CMD_RUN_MADVISE, ctl) < 0) {
                    pr_err("❌ Failed to sync back from MADVISE (register all)\n");
                    goto fail;
                }
            }

            PRINT("[TRACK] is anon:%d, 0x%lx - 0x%lx (%zu pages)\n", is_anon, start, end, npages);
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

    fclose(fp);
    PRINT("✅ Total trackable pages from maps: %d\n", total_pages);


    read_store_malloced_pages();


    if (!fp_readelf) {
        perror("fopen readelf_file /tmp/readelf.txt");
        return;
    }

   
    while (fgets(line, sizeof(line), fp_readelf)) {
        
        // Try parsing relevant fields from readelf line
        matched = sscanf(line, "%d: %lx %lx %s %s %s %d %s", &idx, &offset, &size, type, bind, vis, &section_idx, name);


        if (matched == 8 && strcmp(type, "OBJECT") == 0 && strcmp(bind, "GLOBAL") == 0 && strcmp(vis, "DEFAULT") == 0) {
            start = base_addr + offset;
            end   = start + size;
            aligned_start = start & ~(PAGE_SIZE - 1);
            aligned_end   = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

            PRINT("---> Symbol: %-30s  Offset: 0x%10lx  Size: %10lu, Real address:%lx, Aligned page start:%lx\n", name, offset, size, start, aligned_start);


            malloced = 0;
            if( size == 8 ){ 
                /*is the size of a pointer, maybe it's a pointer
                Check if content is pointing to one of the /tmp/mmapalloc_log from the ld_preload of malloc, 
                aka if the value is in the file, then it's a pointer of a malloc area
                */
                long candidate_ptr_val = 0;
                
                if (read_long_at_addr_infected(ctl, start, &candidate_ptr_val) == 0) {
                    PRINT("🔎 8-byte value at 0x%lx = %ld (0x%lx, Aligned:0x%lx)\n", start, candidate_ptr_val, (unsigned long)candidate_ptr_val,  (unsigned long)candidate_ptr_val & ~(PAGE_SIZE - 1));
                }


                for( int i = 0; i < alloc_count; i++ ){
                    //uintptr_t s = allocs[i].addr;
                    //uintptr_t e = s + allocs[i].npages * PAGE_SIZE;
                    
                    if( (uintptr_t) allocs[i].addr == (uintptr_t)candidate_ptr_val ){
                        malloced = i+1; //malloced is both the flag rapresenting that we found the malloc and both the index + 1 in the array 
                        break;
                    }
                }

        
            }
            
            if( malloced ){
                PRINT("✅ Looks like a pointer into a malloc region.\n");
                malloced--;

                for (int i = 0; i < total_pages; i++) {
                    if (page_list_data[i].saddr == allocs[malloced].aligned_addr) {
                        page_list_data[i].index_of_allocs = malloced;
                            
                        for( int j = 0; j < allocs[malloced].npages; j++  ){
                            //So we need to change all the status of these pages, because we don't need to track them anymore
                            page_list_data[i + j].state = DIVIDED; //if they where register they would be in order
                            disable_wp( uffd, (void*) page_list_data[i + j].saddr );
                        }


                        // Copy at most sizeof(symbol_name)-1 characters
                        strncpy(allocs[malloced].symbol_name, name, sizeof(allocs[malloced].symbol_name));
                        // Ensure null-termination
                        //allocs[malloced].symbol_name[sizeof(allocs[malloced].symbol_name) - 1] = '\0';
                        break;
                    }
                }

                PRINT("✅ Saved symbol:%s, aligned_address:%lx, pages:%ld allocs_index:%d\n\n", allocs[malloced].symbol_name,  allocs[malloced].aligned_addr , allocs[malloced].npages , malloced );
            }
            else if(0) {
                PRINT("Here\n");
                for (unsigned long addr = aligned_start; addr < aligned_end; addr += PAGE_SIZE) {
                    // Check for duplicates in page_list_data[]
                    int already_seen = 0;
                    for (int i = 0; i < total_pages; i++) {
                        if (page_list_data[i].saddr == addr) {
                            already_seen = 1;
                            break;
                        }
                    }

                    if ( !already_seen) {

                        PRINT("--> Symbol: %-30s  Offset: 0x%10lx  Size: %10lu, Addr:%lx, NEW PAGE, NOT IN page_list_data\n", name, offset, size, addr);
                
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
                        
                        register_page( uffd, (void *) addr);
                        
                        
                        if( status == SHARED ) enable_wp( uffd, (void *) addr );
                        else if( status == INVALID )  {
                            args = compel_parasite_args(ctl, long);
                            *args = (long)addr;
                            if (compel_rpc_call_sync(PARASITE_CMD_RUN_MADVISE_SINGLE_PAGE, ctl) < 0) {
                                fprintf(stderr, "❌ MADV_DONTNEED (register all) failed\n");
                            }else PRINT("Madvise (in register all) to invalidate page %p\n", (void *)addr);
                        }
                        //else if( status == MODIFIED ) disable( uffd, (void *) addr );

                        page_list_data[total_pages].saddr = addr;
                        page_list_data[total_pages].owner_mask = 0;
                        page_list_data[total_pages].state = status;
                        total_pages++;

                        PRINT("📌 Added global page: 0x%lx (from symbol: %s)\n", addr, symbol);
                    }
                }
            }

            
        }else PRINT("⛔ Skipping line: %s", line);  // Optional: for debugging     
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    PRINT("State:%d\n", state);
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    if (check_process_state(restored_pid) == 1) {
        pr_err("Process in uninterruptible sleep - cannot proceed\n");
        return;
    }

    fclose(fp_readelf);
    return ;

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

}

#if 0
void reconstruct_vm_area_list(int uffd, int restored_pid, struct vm_area_list *list, page_status status) {
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
                page_list_data[total_pages + i].owner_mask = 0;
                page_list_data[total_pages + i].index_of_allocs = 0;
                page_list_data[total_pages + i].state = status;
            }
            total_pages += npages;

            //TODO tracking
            egister_region_with_uffd(uffd, (void*)start, end - start );
            
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

#endif

#if 0
void scan_and_prepare_coalesced_globals(unsigned long base_addr, pid_t restored_pid, int uffd, page_status status) {
    FILE *fp_readelf = fopen("/tmp/readelf.txt", "r");
    char line[512], type[32], bind[32], vis[32], name[256], symbol[128];
    int idx, section_idx, matched;
    unsigned long offset, start, end, aligned_start, aligned_end, size;

    int state;
	struct parasite_ctl *ctl;
	struct infect_ctx *ictx;
	long *args;
	(void) state;
	(void) args;

    if (check_process_state(restored_pid) == 1) {
        pr_err("Process in uninterruptible sleep - cannot proceed\n");
        return;
    }


	state = compel_stop_task(restored_pid);
	PRINT("Compel task stopped\n");
	if (!(ctl = compel_prepare(restored_pid))){
		pr_err("❌ Compel prepare failed\n");
		return;
	} 

	parasite_setup_c_header(ctl);
	ictx = compel_infect_ctx(ctl);
	ictx->log_fd = STDERR_FILENO;

	if (compel_infect(ctl, 1, sizeof(long)) < 0) {
		xfree(ctl);
		return;
	}


    if (!fp_readelf) {
        perror("fopen readelf_file /tmp/readelf.txt");
        return;
    }

   
    while (fgets(line, sizeof(line), fp_readelf)) {
        
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

            PRINT("✅ Symbol: %-30s  Offset: 0x%10lx  Size: %10lu, Aligned page start:%lx\n", name, offset, size, aligned_start);

            for (unsigned long addr = aligned_start; addr < aligned_end; addr += PAGE_SIZE) {
                // Check for duplicates in page_list_data[]
                int already_seen = 0;
                for (int i = 0; i < total_pages; i++) {
                    if (page_list_data[i].saddr == addr) {
                        already_seen = 1;
                        break;
                    }
                }

                if ( !already_seen) {

                    PRINT("✅ Symbol: %-30s  Offset: 0x%10lx  Size: %10lu, Addr:%lx, NEW PAGE, NOT IN page_list_data\n", name, offset, size, addr);
               
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
                   
                    //replaceGlobalWithAnonPage(restored_pid, (void *) addr);



                    register_page( uffd, (void *) addr);
                    
                    
                    if( status == SHARED ) 
                        enable_wp( uffd, (void *) addr );
                    //else if( status == INVALID )       madvise(  );

                    page_list_data[total_pages].saddr = addr;
                    page_list_data[total_pages].owner_mask = 0;
                    page_list_data[total_pages].state = status;
                    total_pages++;

                    PRINT("📌 Added global page: 0x%lx (from symbol: %s)\n", addr, symbol);
                }
            }
        }else {
            PRINT("⛔ Skipping line: %s", line);  // Optional: for debugging
        }


      
    }

    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    PRINT("State:%d\n", state);
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    if (check_process_state(restored_pid) == 1) {
        pr_err("Process in uninterruptible sleep - cannot proceed\n");
        return;
    }

    fclose(fp_readelf);
    return ;

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

#endif 
int get_list_page_index(unsigned long addr){
    for (int i = 0; i < total_pages; i++) {
        unsigned long start = page_list_data[i].saddr;

        // Check if the given address falls inside this region
        if (addr == start ) {
          /*PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld (range 0x%lx - 0x%lx)\n",
                   addr, page_list_data[i].state, new_state, i, start, end - 1);

            if (new_owner  != -2) page_list_data[i].owner_mask = new_owner;
            if (new_state  != -2) page_list_data[i].state = new_state;
            if (new_index  != -2) page_list_data[i].index_of_allocs = new_index;*/

            return i; // success
        }
    }

    PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n", addr);
    return -1;
}


int update_page_info(unsigned long addr, int new_owner, int new_state, int new_index){
    for (int i = 0; i < total_pages; i++) {
        unsigned long start = page_list_data[i].saddr;
        unsigned long end   = start + PAGE_SIZE - 1;

        // Check if the given address falls inside this region
        if (addr == start ) {
            PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %d (range 0x%lx - 0x%lx)\n",
                   addr, page_list_data[i].state, new_state, i, start, end - 1);

            if( new_state == page_list_data[i].state  ){
                return -2;
            }

            if (new_owner  != -2) page_list_data[i].owner_mask = new_owner;
            if (new_state  != -2) page_list_data[i].state = new_state;
            if (new_index  != -2) page_list_data[i].index_of_allocs = new_index;

            

            return 0; // success
        }
    }

    PRINT("[DSM] ❌ Address 0x%lx not found in page_list_data[]\n", addr);
    return -1;
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


int dsm_connectivity_test(struct dsm_connection *conn, bool is_server)  {
    struct msg_info msg_in = {0}, msg_out = {0};
    ssize_t n;

    /* ============================
     * Test 1: SERVER->CLIENT path
     * ============================ */
    if (is_server) {
        // 1. Server sends on handler
        msg_out.msg_type = MSG_HANDSHAKE;
        msg_out.page_addr = 0xABCDEF01;
        msg_out.page_size = 4096;
        msg_out.msg_id = 1;

        PRINT("[DSM-CONN] [SERVER] (Test1) Sending PING on fd_handler=%d\n", conn->fd_handler);
        n = send(conn->fd_handler, &msg_out, sizeof(msg_out), 0);
        if (n != sizeof(msg_out)) { perror("[SERVER] send PING"); return -1; }

        // 2. Server receives ACK on command
        n = recv(conn->fd_command, &msg_in, sizeof(msg_in), 0);
        if (n != sizeof(msg_in)) { perror("[SERVER] recv ACK"); return -1; }
        if (msg_in.msg_type != MSG_ACK) { fprintf(stderr, "[SERVER] Invalid ACK\n"); return -1; }

        PRINT("[DSM-CONN] [SERVER] (Test1) OK: handler->command ✅\n");
    } else {
        // 1. Client receives PING on command
        n = recv(conn->fd_command, &msg_in, sizeof(msg_in), 0);
        if (n != sizeof(msg_in)) { perror("[CLIENT] recv PING"); return -1; }
        if (msg_in.msg_type != MSG_HANDSHAKE) { fprintf(stderr, "[CLIENT] Unexpected msg\n"); return -1; }

        PRINT("[DSM-CONN] [CLIENT] (Test1) Received PING on fd_command=%d\n", conn->fd_command);

        // 2. Client replies ACK on handler
        msg_out.msg_type = MSG_ACK;
        n = send(conn->fd_handler, &msg_out, sizeof(msg_out), 0);
        if (n != sizeof(msg_out)) { perror("[CLIENT] send ACK"); return -1; }

        PRINT("[DSM-CONN] [CLIENT] (Test1) Sent ACK on fd_handler=%d\n", conn->fd_handler);
    }

    /* ============================
     * Test 2: CLIENT->SERVER path
     * ============================ */
    if (!is_server) {
        // 1. Client sends on command
        msg_out.msg_type = MSG_HANDSHAKE;
        msg_out.page_addr = 0xBEEFDEAD;
        msg_out.page_size = 4096;
        msg_out.msg_id = 2;

        PRINT("[DSM-CONN] [CLIENT] (Test2) Sending PING on fd_command=%d\n", conn->fd_command);
        n = send(conn->fd_command, &msg_out, sizeof(msg_out), 0);
        if (n != sizeof(msg_out)) { perror("[CLIENT] send PING2"); return -1; }

        // 2. Client receives ACK on handler
        n = recv(conn->fd_handler, &msg_in, sizeof(msg_in), 0);
        if (n != sizeof(msg_in)) { perror("[CLIENT] recv ACK2"); return -1; }
        if (msg_in.msg_type != MSG_ACK) { fprintf(stderr, "[CLIENT] Invalid ACK2\n"); return -1; }

        PRINT("[DSM-CONN] [CLIENT] (Test2) OK: command->handler ✅\n");
    } else {
        // 1. Server receives PING on handler
        n = recv(conn->fd_handler, &msg_in, sizeof(msg_in), 0);
        if (n != sizeof(msg_in)) { perror("[SERVER] recv PING2"); return -1; }
        if (msg_in.msg_type != MSG_HANDSHAKE) { fprintf(stderr, "[SERVER] Unexpected msg2\n"); return -1; }

        PRINT("[DSM-CONN] [SERVER] (Test2) Received PING on fd_handler=%d\n", conn->fd_handler);

        // 2. Server replies ACK on command
        msg_out.msg_type = MSG_ACK;
        n = send(conn->fd_command, &msg_out, sizeof(msg_out), 0);
        if (n != sizeof(msg_out)) { perror("[SERVER] send ACK2"); return -1; }

        PRINT("[DSM-CONN] [SERVER] (Test2) Sent ACK on fd_command=%d\n", conn->fd_command);
    }

    PRINT("[DSM-CONN] [%s] Connectivity fully verified (4 paths OK) 🎉\n",
          is_server ? "SERVER" : "CLIENT");
    return 0;
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
    uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID;

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

    if (!(uffdio_api.features & UFFD_FEATURE_THREAD_ID)) {
        fprintf(stderr, "UFFD_FEATURE_THREAD_ID not supported by kernel\n");
        return -1;
    }

    PRINT("✅ userfaultfd API initialized with WP and THREAD_ID support\n");
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

int enable_wp(int uffd, void *addr)
{
	struct uffdio_writeprotect wp = {
		.range.start = (unsigned long)addr,
		.range.len = PAGE_SIZE,
		.mode = UFFDIO_WRITEPROTECT_MODE_WP
	};

	DSM_DEBUG_UFFD("UFFD enable: %d\n", uffd);

	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) == -1){
		perror("UFFDIO_WRITEPROTECT (enable)");
        return -1;
    }
	DSM_DEBUG_UFFD("Successfully protected global page at %p\n", addr);
    return 0;
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
		DSM_DEBUG_UFFD("Successfully disabled write protection on page at %p\n", addr);
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

	PRINT("[DSM] replaceGlobalWithAnonPage request to address: %p...\n", addr);

    /**/if (check_process_state(restored_pid) == 1) {
            pr_err("Process in uninterruptible sleep - cannot proceed\n");
            return -1;
        }
	state = compel_stop_task(restored_pid);
	PRINT("Compel task stopped\n");
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
	if (check_process_state(restored_pid) == 1) {
            pr_err("Process in uninterruptible sleep - cannot proceed\n");
            return -1;
        }
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

#if 1

#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif

int init_pidfd(int restored_pid) {
    int pidfd = syscall(SYS_pidfd_open, restored_pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open");
        return -1;
    }
    PRINT("[DSM] pidfd for PID %d created: %d\n", restored_pid, pidfd);
    return pidfd;
}


int run_proc_MADVISE(int pidfd, int restored_pid, void *addr, size_t len) {
    struct iovec iov;
    long ret;

    PRINT("[DSM] Sending remote process_madvise(MADV_DONTNEED) with pidfd %d request to pid %d at %p (len=%zu)...\n",
          pidfd, restored_pid, addr, len);

    
    // Prepare iovec for the target memory region
    iov.iov_base = addr;
    iov.iov_len = len;

    // Call process_madvise on the target mm
    ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
    if (ret < 0) {
        fprintf(stderr, "❌ process_madvise failed: %s (errno=%d)\n", strerror(errno), errno);
        close(pidfd);
        return -1;
    }

    PRINT("✅ process_madvise succeeded (ret=%ld)\n", ret);
    return 0;
}

int runMADVISE(int restored_pid, void *addr, size_t len) {
    int pidfd;
    struct iovec iov;
    long ret;

    PRINT("[DSM] Sending remote process_madvise(MADV_DONTNEED) request to pid %d at %p (len=%zu)...\n",
          restored_pid, addr, len);

    // Get a pidfd for the target process
    pidfd = syscall(SYS_pidfd_open, restored_pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open");
        return -1;
    }

    // Prepare iovec for the target memory region
    iov.iov_base = addr;
    iov.iov_len = len;

    // Call process_madvise on the target mm
    ret = syscall(SYS_process_madvise, pidfd, &iov, 1, MADV_DONTNEED, 0);
    if (ret < 0) {
        fprintf(stderr, "❌ process_madvise failed: %s (errno=%d)\n", strerror(errno), errno);
        close(pidfd);
        return -1;
    }

    PRINT("✅ process_madvise succeeded (ret=%ld)\n", ret);
    close(pidfd);
    return 0;
}


#else
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
#endif
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

int interactive_page_inspect(struct msg_info *dsm_msg, int fd_handler, int mode)
{
    unsigned long addr = 0;
    unsigned char page_content[PAGE_SIZE];
    int rows = 0;
    int *page_ints;
    float *page_floats;
    double *page_doubles;

    PRINT("🔍 Enter target virtual page address (hex, e.g. 0x7f537a016000): ");
    if (scanf("%lx", &addr) != 1) {
        fprintf(stderr, "❌ Invalid address input.\n");
        return -1;
    }

    dsm_msg->msg_type = MSG_GET_PAGE_DATA;
    dsm_msg->page_addr = addr;
    dsm_msg->page_size = PAGE_SIZE;
    dsm_msg->msg_id = 1234; // arbitrary ID for tracking

    PRINT("[DSM] Requesting page 0x%lx from remote node...\n", addr);

    if (send_get_page(*dsm_msg, fd_handler, page_content) != 0) {
        fprintf(stderr, "❌ Failed to get page data.\n");
        return -1;
    }

    PRINT("✅ Page 0x%lx successfully retrieved!\n", addr);
  

    PRINT("How many rows (4 values per row)? ");
    if (scanf("%d", &rows) != 1) {
        PRINT("Invalid input. Defaulting to 16 rows.\n");
        rows = 16;
    }

    PRINT("\n");

    // --------------------------------------------
    // MODE 1: Integers
    // --------------------------------------------
    if (mode == 0) {
        page_ints = (int *)page_content;
        PRINT("[DSM] Dumping %d values as int array:\n", rows * 4);
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("  [%03d] = %d (0x%x), [%03d] = %d (0x%x), "
                  "[%03d] = %d (0x%x), [%03d] = %d (0x%x)\n",
                  i, page_ints[i], page_ints[i],
                  i+1, page_ints[i+1], page_ints[i+1],
                  i+2, page_ints[i+2], page_ints[i+2],
                  i+3, page_ints[i+3], page_ints[i+3]);
        }
    }

    // --------------------------------------------
    // MODE 0: Floats
    // --------------------------------------------
    else if (mode == 1) {
        page_floats = (float *)page_content;
        PRINT("[DSM] Dumping %d values as float array:\n", rows * 4);
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("  [%03d] = %f (0x%08x), [%03d] = %f (0x%08x), "
                  "[%03d] = %f (0x%08x), [%03d] = %f (0x%08x)\n",
                  i, page_floats[i], *(unsigned int*)&page_floats[i],
                  i+1, page_floats[i+1], *(unsigned int*)&page_floats[i+1],
                  i+2, page_floats[i+2], *(unsigned int*)&page_floats[i+2],
                  i+3, page_floats[i+3], *(unsigned int*)&page_floats[i+3]);
        }
    }

    // --------------------------------------------
    // MODE 2: Doubles
    // --------------------------------------------
    else if (mode == 2) {
        page_doubles = (double *)page_content;
        PRINT("[DSM] Dumping %d values as double array:\n", rows * 4);
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("  [%03d] = %lf (0x%016lx), [%03d] = %lf (0x%016lx), "
                  "[%03d] = %lf (0x%016lx), [%03d] = %lf (0x%016lx)\n",
                  i, page_doubles[i], *(uint64_t*)&page_doubles[i],
                  i+1, page_doubles[i+1], *(uint64_t*)&page_doubles[i+1],
                  i+2, page_doubles[i+2], *(uint64_t*)&page_doubles[i+2],
                  i+3, page_doubles[i+3], *(uint64_t*)&page_doubles[i+3]);
        }
    }

    PRINT("\n✅ Page content inspection complete.\n");
    return 0;
}

int test_full_page_content(int restored_pid, int uffd, struct msg_info *dsm_msg, int mode ) {
    int state, p[2], rows;
    long *args;
    int *page_ints;
    float *page_floats;
    double *page_doubles;
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

    
    if (mode == 1) {

        // ✅ Print entire page as int[]
        page_ints = (int *)page_content;

        PRINT("How many rows?\n");
        if (scanf("%d", &rows) != 1) {
            PRINT("Invalid input\n");
            rows = 1024;
        }

        PRINT("[DSM] Dumping %d values as int array:\n", rows * 4);
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("  [%03d] = %d (0x%x), [%03d] = %d (0x%x), "
                "[%03d] = %d (0x%x), [%03d] = %d (0x%x)\n",
                i, page_ints[i], page_ints[i],
                i+1, page_ints[i+1], page_ints[i+1],
                i+2, page_ints[i+2], page_ints[i+2],
                i+3, page_ints[i+3], page_ints[i+3]);
        }

    } else if (mode == 0) {

        // ✅ Print entire page as float[]
        page_floats = (float *)page_content;

        PRINT("How many rows?\n");
        if (scanf("%d", &rows) != 1) {
            PRINT("Invalid input\n");
            rows = 1024;
        }

        PRINT("[DSM] Dumping %d values as float array:\n", rows * 4);
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("  [%03d] = %f (0x%08x), [%03d] = %f (0x%08x), "
                "[%03d] = %f (0x%08x), [%03d] = %f (0x%08x)\n",
                i, page_floats[i], *(unsigned int*)&page_floats[i],
                i+1, page_floats[i+1], *(unsigned int*)&page_floats[i+1],
                i+2, page_floats[i+2], *(unsigned int*)&page_floats[i+2],
                i+3, page_floats[i+3], *(unsigned int*)&page_floats[i+3]);
        }

    } else if (mode == 2) {

        // ✅ Print entire page as double[]
        page_doubles = (double *)page_content;

        PRINT("How many rows?\n");
        if (scanf("%d", &rows) != 1) {
            PRINT("Invalid input\n");
            rows = 512; // 512 * 8 bytes * 4 = 16KB printed max
        }

        PRINT("[DSM] Dumping %d values as double array:\n", rows * 4);
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("  [%03d] = %lf (0x%016lx), [%03d] = %lf (0x%016lx), "
                "[%03d] = %lf (0x%016lx), [%03d] = %lf (0x%016lx)\n",
                i, page_doubles[i], *(uint64_t*)&page_doubles[i],
                i+1, page_doubles[i+1], *(uint64_t*)&page_doubles[i+1],
                i+2, page_doubles[i+2], *(uint64_t*)&page_doubles[i+2],
                i+3, page_doubles[i+3], *(uint64_t*)&page_doubles[i+3]);
        }

    } else {
        PRINT("[DSM] Unknown mode: %d\n", mode);
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
		//PRINT("[DSM] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);
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
        perror("[SERVER] Failed to send MSG_GET_PAGE_DATA");
        return -1;
    }

    // 2. Receive the page
    n = recv(fd_handler, page_out, 4096, MSG_WAITALL);
    if (n != 4096) {
        fprintf(stderr, "[SERVER] Failed to receive full page (got %zd bytes)\n", n);
        return -1;
    }

    return 0;
}



#if 1


int wait_readable(int fd, int timeout_ms) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r = poll(&pfd, 1, timeout_ms);
    if (r <= 0) return -1;
    return (pfd.revents & POLLIN) ? 0 : -1;
}

ssize_t all_read(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -2; // EOF before all data
        p += n;
        len -= n;
    }
    return 0;
}

int send_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}


#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#endif

#if RDMA_ENABLE && 0


#elif 1
int handle_page_data_request(int restored_pid, int uffd, int sk, struct msg_info *dsm_msg) {
    unsigned char page_content[PAGE_SIZE];
    struct iovec local_iov, remote_iov;
    ssize_t nread;

    PRINT("[DSM] Using process_vm_readv() to fetch remote page (pid=%d, addr=%p)\n",
          restored_pid, (void*)dsm_msg->page_addr);

    // --- Prepare iovecs ---
    local_iov.iov_base = page_content;
    local_iov.iov_len  = PAGE_SIZE;
    remote_iov.iov_base = (void*)dsm_msg->page_addr;
    remote_iov.iov_len  = PAGE_SIZE;

    // --- Read the page directly from target process ---
    nread = process_vm_readv(restored_pid,
                             &local_iov, 1,
                             &remote_iov, 1,
                             0);
    if (nread != PAGE_SIZE) {
        if (nread < 0)
            PRINT("❌ process_vm_readv failed: %s\n", strerror(errno));
        else
            PRINT("⚠️ process_vm_readv read partial data: %ld bytes\n", nread);
        return -1;
    }

    PRINT("✅ Read %ld bytes from target process memory\n", nread);

    // --- Send page data to client ---
    if (send_all(sk, page_content, PAGE_SIZE) < 0) {
        perror("send_all(page_content)");
        return -1;
    }

    PRINT("✅ Page_transfer_complete to client (addr=%p)\n", (void*)dsm_msg->page_addr);

    // --- Post-transfer page management ---
    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        PRINT("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n");
        if (run_proc_MADVISE(pidfd, restored_pid, (void*)dsm_msg->page_addr, PAGE_SIZE) == 0)
            PRINT("process_madvise to invalidate page %p\n", (void*)dsm_msg->page_addr);
        else{
            PRINT("❌ MADV_DONTNEED failed: %s\n", strerror(errno));
            kill_and_exit(restored_pid);
        }
        PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n",
            dsm_msg->page_addr, page_list_data[dsm_msg->msg_id].state, INVALID, dsm_msg->msg_id);
        page_list_data[dsm_msg->msg_id].state = INVALID;	
    } else {
        PRINT("Message is GET_PAGE_DATA → Enable WP to SHARED\n");
        if (enable_wp(uffd, (void*)dsm_msg->page_addr)){
            PRINT("⚠️ enable_wp failed\n");
            kill_and_exit(restored_pid);
        }
        //update_page_info(dsm_msg->page_addr, 1, SHARED, -2);
        PRINT("[DSM] Updating page at 0x%lx state:%d→%d, entry %ld \n",
            dsm_msg->page_addr, page_list_data[dsm_msg->msg_id].state, SHARED, dsm_msg->msg_id);
        page_list_data[dsm_msg->msg_id].state = SHARED;	
    }

    return 0;
}



#elif 1
int handle_page_data_request(int restored_pid, int uffd, int sk, struct msg_info *dsm_msg) {
    int state;
    int p[2];
    unsigned char page_content[PAGE_SIZE];
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;
    long *args;

    PRINT("[DSM] Sending get page to rpc daemon (DUMP_SINGLE) request...\n");

    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        PRINT("❌ compel_prepare failed\n");
        return -1;
    }

    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;

    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        PRINT("❌ compel_infect failed\n");
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
        PRINT("❌ RPC DUMP_SINGLE call failed\n");
        goto fail_close;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        PRINT("❌ Failed to send pipe fd\n");
        goto fail_close;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        PRINT("❌ RPC DUMP_SINGLE sync failed\n");
        goto fail_close;
    }

    close(p[1]); // close write end on parent

    PRINT("[DSM] Waiting for parasite page data on fd=%d\n", p[0]);

    if (wait_readable(p[0], 5000) < 0) {
        PRINT("❌ Timeout waiting for parasite page data\n");
        goto fail_close;
    }

    if (all_read(p[0], page_content, PAGE_SIZE) < 0) {
        perror("all_read parasite pipe");
        goto fail_close;
    }

    PRINT("✅ Received 4096 bytes from parasite, sending to client (fd=%d)\n", sk);

    if (send_all(sk, page_content, PAGE_SIZE) < 0) {
        perror("send_all(page_content)");
        goto fail_close;
    }

    PRINT("✅ Page_transfer_complete to client (addr=%p)\n", (void*)dsm_msg->page_addr);

    // Optional: perform invalidation or re-enable WP
    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        PRINT("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n");
        if (compel_rpc_call_sync(PARASITE_CMD_RUN_MADVISE_SINGLE_PAGE, ctl) < 0)
            PRINT("❌ MADV_DONTNEED failed\n");
        else
            PRINT("Madvise to invalidate page %p\n", (void *)dsm_msg->page_addr);
        update_page_info(dsm_msg->page_addr, 1, INVALID, -2);
    } else {
        PRINT("Message is GET_PAGE_DATA → Enable WP to SHARED\n");
        if (enable_wp(uffd, (void *)dsm_msg->page_addr))
            PRINT("⚠️ enable_wp failed\n");
        update_page_info(dsm_msg->page_addr, 1, SHARED, -2);
    }

    if (compel_stop_daemon(ctl))
        PRINT("⚠️ Can't stop daemon\n");
    if (compel_cure(ctl))
        PRINT("⚠️ Can't cure\n");
    if (compel_resume_task(restored_pid, state, state))
        PRINT("⚠️ Can't resume task\n");

    close(p[0]);
    return 0;

fail_close:
    close(p[0]);
    close(p[1]);
    return -1;
}

#elif 0
int handle_page_data_request(int restored_pid, int uffd, int sk, struct msg_info *dsm_msg) {
    int state, value, p[2];
    long *args;
    unsigned char page_content[4096];
    size_t offset;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    
    (void) value;
    (void) offset;


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

    #if 0
    // Show value at global_addr for debugging
    offset = global_addr - aligned;
    if (offset >= 4096 - sizeof(int)) {
        fprintf(stderr, "Offset out of bounds\n");
    } else {
        memcpy(&value, &page_content[offset], sizeof(int));
        //PRINT("[DSM] Value at GLOBAL_ADDR (0x%lx): %d (0x%x)\n", global_addr, value, value);
    }
    #endif

    // Handle invalidation or write protection

    if (dsm_msg->msg_type == MSG_GET_PAGE_DATA_INVALID) {
        PRINT("Message is GET_PAGE_INVALIDATE → Drop the page to INVALIDATE\n");
        if (compel_rpc_call_sync(PARASITE_CMD_RUN_MADVISE_SINGLE_PAGE, ctl) < 0) {
            fprintf(stderr, "❌ MADV_DONTNEED failed\n");
        }else PRINT("Madvise to invalidate page %p\n", (void *)dsm_msg->page_addr);
        if( update_page_info(dsm_msg->page_addr, 1, INVALID, -2) != 0) kill_and_exit(restored_pid);
    } else {
        PRINT("Message is GET_PAGE_DATA → Enable WP to SHARED\n");
        enable_wp( uffd, (void *)dsm_msg->page_addr);
        if( update_page_info(dsm_msg->page_addr, 1, SHARED, -2) == -2){
            PRINT("mah\n");
            kill_and_exit(restored_pid);
        }
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

int compare_local_remote_pages(int restored_pid, int uffd, struct msg_info *dsm_msg, int fd_handler) {
    int state, p[2], rows, differences;
    long *args;
    float *local_page_floats, *remote_page_floats;
    unsigned char local_page_content[4096];
    unsigned char remote_page_content[4096];
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;
    
    PRINT("[DSM] Requesting both local and remote pages for address: 0x%lx\n", dsm_msg->page_addr);
    
    // =========================
    // 1. GET REMOTE PAGE FIRST
    // =========================
    PRINT("\n[DSM] Getting REMOTE page via network...\n");
    if (send_get_page(*dsm_msg, fd_handler, remote_page_content) != 0) {
        PRINT("❌ Failed to get remote page at %lx\n", dsm_msg->page_addr);
        return -1;
    }
    PRINT("✅ Remote page received successfully\n");
    
    // =========================
    // 2. GET LOCAL PAGE
    // =========================
    PRINT("\n[DSM] Getting LOCAL page via parasite injection...\n");
    
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
        goto fail_cleanup;
    }
    
    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "❌ RPC DUMP_SINGLE call failed\n");
        goto fail_pipe;
    }
    
    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "❌ Failed to send pipe fd\n");
        goto fail_pipe;
    }
    
    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "❌ RPC DUMP_SINGLE sync failed\n");
        goto fail_pipe;
    }
    
    if (read(p[0], local_page_content, 4096) != 4096) {
        perror("❌ read from parasite pipe");
        goto fail_pipe;
    }
    
    PRINT("✅ Local page retrieved successfully\n");
    
    // =========================
    // 3. PRINT BOTH PAGES AS FLOATS
    // =========================
    local_page_floats = (float *)local_page_content;
    remote_page_floats = (float *)remote_page_content;
    
    // Get number of rows to display
    rows = 0;
    PRINT("\nHow many rows of floats to display? (each row = 4 floats): ");
    if (scanf("%d", &rows) != 1 || rows <= 0) {
        PRINT("Invalid input, defaulting to 256 rows\n");
        rows = 256;
    }
    
    // Ensure we don't exceed page boundaries
    if (rows * 4 > 1024) {
        PRINT("⚠️  Limiting to 256 rows (1024 floats max per page)\n");
        rows = 256;
    }
    
    PRINT("\n================================================================================\n");
    PRINT("COMPARISON: LOCAL vs REMOTE PAGE (Address: 0x%lx)\n", dsm_msg->page_addr);
    PRINT("================================================================================\n");
    PRINT("Format: [idx] LOCAL_val (hex) | REMOTE_val (hex) [MATCH/DIFF]\n");
    PRINT("--------------------------------------------------------------------------------\n");
    
    differences = 0;
    for (int i = 0; i < rows * 4; i += 4) {
        PRINT("\nRow %03d:\n", i/4);
        
        for (int j = 0; j < 4; j++) {
            int idx = i + j;
            float local_val = local_page_floats[idx];
            float remote_val = remote_page_floats[idx];
            unsigned int local_hex = *(unsigned int*)&local_val;
            unsigned int remote_hex = *(unsigned int*)&remote_val;
            
            const char *status = (local_hex == remote_hex) ? "✅ MATCH" : "❌ DIFF ";
            if (local_hex != remote_hex) differences++;
            
            PRINT("  [%03d] %12.6f (0x%08x) | %12.6f (0x%08x) %s\n",
                   idx, local_val, local_hex, remote_val, remote_hex, status);
        }
    }
    
    PRINT("\n================================================================================\n");
    PRINT("SUMMARY: %d differences found out of %d floats compared\n", differences, rows * 4);
    if (differences == 0) {
        PRINT("🎉 Pages are IDENTICAL!\n");
    } else {
        PRINT("⚠️  Pages have %d different float values\n", differences);
    }
    PRINT("================================================================================\n\n");
    
    // Cleanup parasite
    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    
    close(p[0]);
    close(p[1]);
    return 0;

fail_pipe:
    close(p[0]);
    close(p[1]);
fail_cleanup:
    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    return -1;
}


// Function to perform bitwise OR between two pages and return result
int or_pages(unsigned char *local_page, unsigned char *remote_page, unsigned char *result_page, int display_floats) {
    if (!local_page || !remote_page || !result_page) {
        PRINT("❌ Invalid page pointers provided\n");
        return -1;
    }
    
    PRINT("\n🔧 PERFORMING BITWISE OR OPERATION\n");
    PRINT("==================================\n");
    
    // Perform bitwise OR for each byte
    for (int i = 0; i < 4096; i++) {
        result_page[i] = local_page[i] | remote_page[i];
    }
    
    PRINT("✅ OR operation completed successfully\n");
    
    // Optional: Display result as floats
    if (display_floats) {
        float *result_floats = (float *)result_page;
        int rows = 0;
        
        PRINT("\nHow many rows of OR'd floats to display? (each row = 4 floats): ");
        if (scanf("%d", &rows) != 1 || rows <= 0) {
            PRINT("Invalid input, defaulting to 64 rows\n");
            rows = 64;
        }
        
        // Ensure we don't exceed page boundaries
        if (rows * 4 > 1024) {
            PRINT("⚠️  Limiting to 256 rows (1024 floats max per page)\n");
            rows = 256;
        }
        
        PRINT("\n================================================================================\n");
        PRINT("BITWISE OR RESULT PAGE (LOCAL | REMOTE)\n");
        PRINT("================================================================================\n");
        PRINT("Format: [idx] OR_result (hex)\n");
        PRINT("--------------------------------------------------------------------------------\n");
        
        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("\nRow %03d:\n", i/4);
            
            for (int j = 0; j < 4; j++) {
                int idx = i + j;
                float or_val = result_floats[idx];
                unsigned int or_hex = *(unsigned int*)&or_val;
                
                PRINT("  [%03d] %12.6f (0x%08x)\n", idx, or_val, or_hex);
            }
        }
        
        PRINT("\n================================================================================\n");
        PRINT("OR operation display completed\n");
        PRINT("================================================================================\n\n");
    }
    
    return 0;
}
int compare_and_or_pages(int restored_pid, int uffd,
                         struct msg_info *dsm_msg,
                         int fd_handler,
                         unsigned char *or_result,
                         int mode)
{
    int state, p[2], rows, differences, total_vals;
    long *args;
    float  *local_page_floats,  *remote_page_floats;
    double *local_page_doubles, *remote_page_doubles;
    unsigned char local_page_content[4096];
    unsigned char remote_page_content[4096];
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;

    PRINT("[DSM] Requesting both local and remote pages for address: 0x%lx\n", dsm_msg->page_addr);

    // =========================
    // 1. GET REMOTE PAGE FIRST
    // =========================
    PRINT("\n[DSM] Getting REMOTE page via network...\n");
    if (send_get_page(*dsm_msg, fd_handler, remote_page_content) != 0) {
        PRINT("❌ Failed to get remote page at %lx\n", dsm_msg->page_addr);
        return -1;
    }
    PRINT("✅ Remote page received successfully\n");

    // =========================
    // 2. GET LOCAL PAGE
    // =========================
    PRINT("\n[DSM] Getting LOCAL page via parasite injection...\n");

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
        goto fail_cleanup;
    }

    if (compel_rpc_call(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "❌ RPC DUMP_SINGLE call failed\n");
        goto fail_pipe;
    }

    if (compel_util_send_fd(ctl, p[1]) != 0) {
        fprintf(stderr, "❌ Failed to send pipe fd\n");
        goto fail_pipe;
    }

    if (compel_rpc_sync(PARASITE_CMD_DUMP_SINGLE, ctl) < 0) {
        fprintf(stderr, "❌ RPC DUMP_SINGLE sync failed\n");
        goto fail_pipe;
    }

    if (read(p[0], local_page_content, 4096) != 4096) {
        perror("❌ read from parasite pipe");
        goto fail_pipe;
    }

    PRINT("✅ Local page retrieved successfully\n");

    // =========================
    // 3. PRINT BOTH PAGES (FLOAT or DOUBLE)
    // =========================
    PRINT("\nHow many rows to display for comparison? (each row = 4 values): ");
    if (scanf("%d", &rows) != 1 || rows <= 0) {
        PRINT("Invalid input, defaulting to 64 rows\n");
        rows = 64;
    }

    PRINT("\n================================================================================\n");
    PRINT("COMPARISON: LOCAL vs REMOTE PAGE (Address: 0x%lx)\n", dsm_msg->page_addr);
    PRINT("================================================================================\n");
    PRINT("Format: [idx] LOCAL_val (hex) | REMOTE_val (hex) [MATCH/DIFF]\n");
    PRINT("--------------------------------------------------------------------------------\n");

    differences = 0;

    if(mode < 0 ){
        PRINT("\nChoose print mode:\n");
        PRINT("  [0] float (4 bytes)\n");
        PRINT("  [] int (4 bytes)\n");
        PRINT("  [1] double (8 bytes)\n");
        PRINT("Enter mode: ");

        if (scanf("%d", &mode) != 1 || mode < 0 || mode > 2) {
            fprintf(stderr, "Invalid mode. Defaulting to float (0).\n");
            mode = 0;
        }
    }
   

    if (mode == 0) {
        // ========== FLOAT MODE ==========
        local_page_floats  = (float  *)local_page_content;
        remote_page_floats = (float  *)remote_page_content;

        for (int i = 0; i < rows * 4; i += 4) {
            PRINT("\nRow %03d:\n", i / 4);
            for (int j = 0; j < 4; j++) {
                int idx = i + j;
                float local_val  = local_page_floats[idx];
                float remote_val = remote_page_floats[idx];
                unsigned int local_hex  = *(unsigned int *)&local_val;
                unsigned int remote_hex = *(unsigned int *)&remote_val;
                const char *status = (local_hex == remote_hex) ? "✅ MATCH" : "❌ DIFF ";
                if (local_hex != remote_hex) differences++;
                PRINT("  [%03d] %12.6f (0x%08x) | %12.6f (0x%08x) %s\n",
                       idx, local_val, local_hex, remote_val, remote_hex, status);
            }
        }

    } else if (mode == 1) {
        // ========== DOUBLE MODE ==========
        local_page_doubles  = (double *)local_page_content;
        remote_page_doubles = (double *)remote_page_content;

        // each double = 8 bytes → 512 doubles per page
        total_vals = rows * 4;
        if (total_vals > 512) total_vals = 512;

        for (int i = 0; i < total_vals; i += 4) {
            PRINT("\nRow %03d:\n", i / 4);
            for (int j = 0; j < 4; j++) {
                int idx = i + j;
                double local_val  = local_page_doubles[idx];
                double remote_val = remote_page_doubles[idx];
                unsigned long local_hex  = *(unsigned long *)&local_val;
                unsigned long remote_hex = *(unsigned long *)&remote_val;
                const char *status = (local_hex == remote_hex) ? "✅ MATCH" : "❌ DIFF ";
                if (local_hex != remote_hex) differences++;
                PRINT("  [%03d] %14.8lf (0x%016lx) | %14.8lf (0x%016lx) %s\n",
                       idx, local_val, local_hex, remote_val, remote_hex, status);
            }
        }

    } else {
        PRINT("❌ Unknown mode (%d). Use 0 = float, 1 = double.\n", mode);
    }

    PRINT("\n================================================================================\n");
    if (mode == 0)
        PRINT("SUMMARY: %d differences found out of %d floats compared\n", differences, rows * 4);
    else
        PRINT("SUMMARY: %d differences found out of %d doubles compared\n", differences, rows * 4);

    if (differences == 0)
        PRINT("🎉 Pages are IDENTICAL!\n");
    else
        PRINT("⚠️  Pages have %d differing values\n", differences);
    PRINT("================================================================================\n\n");

    // =========================
    // 4. PERFORM OR OPERATION
    // =========================
    if (or_result != NULL) {
        char response;
        PRINT("Do you want to perform bitwise OR operation? (y/n): ");
        if (scanf(" %c", &response) == 1 && (response == 'y' || response == 'Y')) {
            if (or_pages(local_page_content, remote_page_content, or_result, 1) == 0)
                PRINT("✅ OR operation completed and stored in result buffer\n");
            else
                PRINT("❌ OR operation failed\n");
        }
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
fail_cleanup:
    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    return -1;
}



// Function to fill local page using UFFDIO_COPY
int fill_local_page_uffdio(int uffd, unsigned long addr, unsigned char *merged_page_data, int restored_pid) {
    struct uffdio_copy copy;
    
    /**/

    if( runMADVISE( restored_pid, (void *) addr, 4096))
            perror("runMADVISE command loop");
        else
            PRINT("Successfully run madvise on page at %p\n", (void *) addr);
    
    if (!merged_page_data) {
        PRINT("❌ Invalid page data pointer\n");
        return -1;
    }
    
    PRINT("\n💾 FILLING LOCAL PAGE WITH REMOTE DATA\n");
    PRINT("======================================\n");
    PRINT("Target address: 0x%lx\n", addr);
    PRINT("Data source: remote page (REMOTE)\n");
    
    // Set up the copy structure
    copy.src  = (unsigned long)merged_page_data;
    copy.dst  = addr;
    copy.len  = PAGE_SIZE;
    copy.mode = UFFDIO_COPY_MODE_WP;  // Copy with write protection
    
    PRINT("Performing UFFDIO_COPY...\n");
    PRINT("  src: 0x%llx (remote data)\n", copy.src);
    PRINT("  dst: 0x%llx (target address)\n", copy.dst);
    PRINT("  len: %llu bytes\n", copy.len);
    PRINT("  mode: UFFDIO_COPY_MODE_WP\n");
    
    // Perform the copy
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) {
        perror("❌ ioctl/copy (merged page fill)");
        return -1;
    }
    
    PRINT("✅ Successfully filled local page with remote data\n");
    PRINT("   Bytes copied: %llu\n", copy.len);
    PRINT("   Local page now contains: REMOTE\n");
    PRINT("======================================\n\n");
    
    return 0;
}


// Function to fill local page with merged data using UFFDIO_COPY
int fill_local_page_with_merged_uffdio(int uffd, unsigned long addr, unsigned char *merged_page_data, int restored_pid) {
    struct uffdio_copy copy;
    
    

    if( runMADVISE( restored_pid, (void *) addr, 4096))
            perror("runMADVISE command loop");
        else
            PRINT("Successfully run madvise on page at %p\n", (void *) aligned);

    if (!merged_page_data) {
        PRINT("❌ Invalid merged page data pointer\n");
        return -1;
    }
    
    PRINT("\n💾 FILLING LOCAL PAGE WITH MERGED DATA\n");
    PRINT("======================================\n");
    PRINT("Target address: 0x%lx\n", addr);
    PRINT("Data source: merged page (LOCAL | REMOTE)\n");
    
    // Set up the copy structure
    copy.src  = (unsigned long)merged_page_data;
    copy.dst  = addr;
    copy.len  = PAGE_SIZE;
    copy.mode = UFFDIO_COPY_MODE_WP;  // Copy with write protection
    
    PRINT("Performing UFFDIO_COPY...\n");
    PRINT("  src: 0x%llx (merged data)\n", copy.src);
    PRINT("  dst: 0x%llx (target address)\n", copy.dst);
    PRINT("  len: %llu bytes\n", copy.len);
    PRINT("  mode: UFFDIO_COPY_MODE_WP\n");
    
    // Perform the copy
    if (ioctl(uffd, UFFDIO_COPY, &copy) == -1) {
        perror("❌ ioctl/copy (merged page fill)");
        return -1;
    }
    
    PRINT("✅ Successfully filled local page with merged data\n");
    PRINT("   Bytes copied: %llu\n", copy.len);
    PRINT("   Local page now contains: LOCAL | REMOTE\n");
    PRINT("======================================\n\n");
    
    return 0;
}


// Function to inject merged page back into local process via parasite
int inject_merged_page_via_parasite(int restored_pid, int uffd, unsigned long addr, unsigned char *merged_page_data) {
    int state, p[2];
    long *args;
    struct parasite_ctl *ctl;
    struct infect_ctx *ictx;
    
    if (!merged_page_data) {
        PRINT("❌ Invalid merged page data pointer\n");
        return -1;
    }
    
    PRINT("\n💉 INJECTING MERGED PAGE VIA PARASITE\n");
    PRINT("====================================\n");
    PRINT("Target address: 0x%lx\n", addr);
    PRINT("Data source: merged page (LOCAL | REMOTE)\n");
    PRINT("Method: Parasite injection (WRITE_SINGLE)\n");
    
    // Stop the target process
    PRINT("🔹 Stopping target process...\n");
    state = compel_stop_task(restored_pid);
    if (!(ctl = compel_prepare(restored_pid))) {
        pr_err("❌ Compel prepare failed\n");
        return -1;
    }
    
    parasite_setup_c_header(ctl);
    ictx = compel_infect_ctx(ctl);
    ictx->log_fd = STDERR_FILENO;
    
    if (compel_infect(ctl, 1, sizeof(long)) < 0) {
        pr_err("❌ Compel infect failed\n");
        xfree(ctl);
        return -1;
    }
    
    PRINT("✅ Parasite injected successfully\n");
    
    // Set the target page address for the parasite
    args = compel_parasite_args(ctl, long);
    *args = addr;
    
    PRINT("🔹 Setting up data pipe...\n");
    if (pipe(p) < 0) {
        perror("pipe");
        goto fail_cleanup;
    }
    
    // Call the WRITE_SINGLE RPC (you'll need to implement this command)
    PRINT("🔹 Calling PARASITE_CMD_WRITE_SINGLE...\n");
    if (compel_rpc_call(PARASITE_CMD_WRITE_SINGLE, ctl) < 0) {
        fprintf(stderr, "❌ RPC WRITE_SINGLE call failed\n");
        goto fail_pipe;
    }
    
    // Send the pipe fd to the parasite
    if (compel_util_send_fd(ctl, p[0]) != 0) {
        fprintf(stderr, "❌ Failed to send pipe fd to parasite\n");
        goto fail_pipe;
    }
    
    // Write the merged page data to the pipe
    PRINT("🔹 Sending merged page data (%ld bytes)...\n", PAGE_SIZE);
    if (write(p[1], merged_page_data, PAGE_SIZE) != PAGE_SIZE) {
        perror("❌ Failed to write merged page data to pipe");
        goto fail_pipe;
    }
    
    // Wait for the parasite to complete the write operation
    if (compel_rpc_sync(PARASITE_CMD_WRITE_SINGLE, ctl) < 0) {
        fprintf(stderr, "❌ RPC WRITE_SINGLE sync failed\n");
        goto fail_pipe;
    }
    
    PRINT("✅ Merged page successfully injected into local process!\n");
    PRINT("   Address 0x%lx now contains merged (LOCAL | REMOTE) data\n", addr);
    
    // Cleanup parasite
    PRINT("🔹 Cleaning up parasite...\n");
    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    
    close(p[0]);
    close(p[1]);
    
    PRINT("====================================\n\n");
    return 0;

fail_pipe:
    close(p[0]);
    close(p[1]);
fail_cleanup:
    if (compel_stop_daemon(ctl)) pr_err("Can't stop daemon\n");
    if (compel_cure(ctl)) pr_err("Can't cure\n");
    if (compel_resume_task(restored_pid, state, state)) pr_err("Can't resume\n");
    return -1;
}

// Enhanced function that tries parasite injection instead of UFFDIO_COPY
int fill_local_page_with_merged_parasite(int uffd, unsigned long addr, unsigned char *merged_page_data, int restored_pid) {
    unsigned long page_addr = addr & ~(PAGE_SIZE - 1);
    if (!merged_page_data) {
        PRINT("❌ Invalid merged page data pointer\n");
        return -1;
    }
    
    PRINT("\n💾 FILLING LOCAL PAGE WITH MERGED DATA\n");
    PRINT("======================================\n");
    PRINT("Target address: 0x%lx\n", addr);
    PRINT("Data source: merged page (LOCAL | REMOTE)\n");
    
    // Check if address is page-aligned
    
    if (page_addr != addr) {
        PRINT("⚠️  Address not page-aligned, using 0x%lx\n", page_addr);
        addr = page_addr;
    }
    
    PRINT("🔸 Using parasite injection method (recommended for present pages)\n");
    
    // Use parasite injection instead of UFFDIO_COPY
    if (inject_merged_page_via_parasite(restored_pid, uffd, addr, merged_page_data) == 0) {
        PRINT("✅ Successfully filled local page using parasite injection!\n");
        PRINT("   Local page now contains merged (LOCAL | REMOTE) data\n");
        PRINT("======================================\n\n");
        return 0;
    } else {
        PRINT("❌ Parasite injection failed\n");
        return -1;
    }
}

// Complete workflow: Compare, OR, and Fill local page
int complete_page_merge_workflow(int restored_pid, int uffd, struct msg_info *dsm_msg, int fd_handler) {
    unsigned char or_result_page[4096];
    char response;
    
    PRINT("\n🚀 COMPLETE PAGE MERGE WORKFLOW\n");
    PRINT("===============================\n");
    PRINT("Target address: 0x%lx\n", dsm_msg->page_addr);
    PRINT("Steps: 1) Compare pages  2) OR merge  3) Fill local\n\n");

 
    
    // Step 1 & 2: Compare pages and create OR merge
    if (compare_and_or_pages(restored_pid, uffd, dsm_msg, fd_handler, or_result_page, -1) != 0) {
        PRINT("❌ Page comparison and OR merge failed\n");
        return -1;
    }
    
    // Step 3: Ask user if they want to fill the local page
    PRINT("Do you want to fill the local page with the merged data? (y/n): ");
    if (scanf(" %c", &response) == 1 && (response == 'y' || response == 'Y')) {
        if (fill_local_page_with_merged_uffdio(uffd, dsm_msg->page_addr, or_result_page, restored_pid) == 0) {
            PRINT("🎉 COMPLETE SUCCESS!\n");
            PRINT("Local page at 0x%lx now contains merged (LOCAL | REMOTE) data\n", dsm_msg->page_addr);
        } else {
            PRINT("❌ Failed to fill local page with merged data\n");
            return -1;
        }
    } else {
        PRINT("Skipping local page fill. Merged data remains in buffer.\n");
    }
    
    return 0;
}




/******************************** END CONTROLLER HELPER FUNCTIONS *******************************/

/******************************** TESTING FUNCTIONS *******************************/

void command_loop(int restored_pid, int uffd, struct dsm_connection* conn) {
	long *args;
	int bin;
    unsigned char page_data[4096];
	struct msg_info dsm_msg = {0};
    const char *menu =
    "\n[DSM] Enter command:\n"
    ">  0  = reapply write-protection\n"
    ">  1  = remote madvise(MADV_DONTNEED)\n"
    "> 21  = restart process (send SIGCONT)\n"
    "> 22  = stop process (send SIGSTOP)\n"
    "> 23  = restart local and remote processes (send SIGCONT & WAKE UP REMOTE THREAD)\n"
    ">  3  = restart process (send compel cure)\n"
    ">  4  = exit\n"
    ">  5  = simple infection test\n"
    "> 61  = test vmsplice\n"
    "> 62  = test vmsplice full page\n"
    ">631  = Full page dump test (interactive) [as int]\n"
    ">632  = Full page dump test (interactive) [as double]\n"
    ">633  = Full page dump test (interactive) [as float]\n"
    "> 64  = all pages registered\n"
    "> 65  = DIVIDED page dump test (interactive)\n"
    "> 66  = DIVIDED page local/remote (interactive)\n"
    "> 67  = DIVIDED page local/remote and OR operation (interactive)\n"
    "> 68  = DIVIDED page local/remote and OR operation and possibly update local copy (fixed address)\n"
    "> 69  = DIVIDED page local/remote and OR operation and possibly update local copy (interactive)\n"
    ">  7  = SIMULATE GET_PAGE_DATA\n"
    "> 71  = GET_PAGE_DATA (interactive) [as int]\n"
    "> 72  = GET_PAGE_DATA (interactive) [as float]\n"
    "> 73  = GET_PAGE_DATA (interactive) [as double]\n"
    "> 74  = REAL GET_PAGE_DATA with LOCAL COPY (interactive)\n"
    ">  8  = SIMULATE GET_PAGE_DATA_AND_INVALIDATE\n"
    ">  9  = SIMULATE INVALIDATE\n"
    "> 10  = WAKE UP REMOTE THREAD\n"
    "> 11  = STOP REMOTE THREAD\n"
    "> 12  = Show mutex page content\n"
    "> 13  = Change mutex lock\n"
    "> 55  = Barrier release\n";


	(void) bin;
	(void) args;	
	(void) dsm_msg;	

    if( 0 && !DBG ){
        sleep(8);
        pr_info("Waking up thread\n");
        send_sigcont(restored_pid);
        return;
    }
  
    sleep(1);
    fputs(menu, stdout);   /* prints whole menu at once */
    PRINT("[DEBUG] isatty(stdin)=%d\n", isatty(0));
    fflush(stdout);

    while (1) {
        char line[64];
        int choice;
        char *endptr;

        PRINT("\n[DSM] Enter command:\n> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            perror("fgets");
            clearerr(stdin);
            continue;
        }

        // Trim newline
        line[strcspn(line, "\n")] = '\0';

        // If user entered nothing, skip
        if (strlen(line) == 0)
            continue;

        // Convert to int safely
        choice = strtol(line, &endptr, 10);
        if (*endptr != '\0') {
            PRINT("[WARN] Invalid input: '%s'\n", line);
            continue;
        }

        PRINT("[DEBUG] parsed choice=%d\n", choice);
    
        /*
        if (scanf("%d", &choice) != 1) {
            PRINT("Invalid input\n");
            while (getchar() != '\n'); // flush
            continue;
        }*/

        if (choice == 0) {
            PRINT("[DSM] Reapplying write-protection on global page...\n");
			enable_wp( uffd, (void *) aligned);
        } else if (choice == 1) {
			PRINT("[DSM] Sending remote madvise(MADV_DONTNEED) request...\n");
			if( runMADVISE( restored_pid, (void *) aligned, 4096))
				perror("runMADVISE command loop");
			else
				PRINT("Successfully run madvise on page at %p\n", (void *) aligned);
        } else if (choice == 21){
			// Resume the stopped process
			send_sigcont(restored_pid);
		} else if (choice == 22){
			// Stop the resumed process
			send_sigstop(restored_pid);
		}else if (choice == 23){
			// Resume the stopped process
			send_sigcont(restored_pid);
            //Resume remote process
            dsm_msg.msg_type = MSG_WAKE_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			PRINT("[SERVER] Sent MSG_WAKE_THREAD to server.\n");
		}else if( choice == 3 ) {
			// Resume the stopped process
			if (compel_resume_task(restored_pid, 3, 3)) pr_err("Can't resume\n");
			PRINT("[DSM Server] Sent compel resume to PID %d.\n", restored_pid);
		} else if( choice == 4 ) {
			kill_and_exit(restored_pid);
		} else if( choice == 5 ) {
			//Infection test
			PRINT("Do infection test\n");
			infection_test(restored_pid);			
		}else if( choice == 61 ){
			//vmsplice test
			PRINT("Do vmsplice test at %p\n", (void *)aligned);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			PRINT("Do vmsplice test at %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_page_content(restored_pid, uffd, &dsm_msg);
		}else if( choice == 62 ){
			//vmsplice test
			PRINT("Do vmsplice test at %p\n", (void *)aligned);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			PRINT("Do vmsplice test at %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_full_page_content(restored_pid, uffd, &dsm_msg, 1);
		}else if( choice == 63 ){
            // Full page dump test (interactive)
            unsigned long input_addr;
            PRINT("[DSM] Enter address to dump (in hex, e.g. 0x555555559380): ");
            fflush(stdout);
            if (scanf("%lx", &input_addr) != 1) {
                fprintf(stderr, "❌ Invalid input\n");
                kill_and_exit(restored_pid);
            }PRINT("[DSM] Address entered: %lx \n",input_addr );

            // Prepare dsm_msg
            dsm_msg.msg_type = MSG_SEND_INVALIDATE;  // or anything suitable
            dsm_msg.page_addr = input_addr;
            dsm_msg.msg_id = 1;

            PRINT("[DSM] Dumping page at address: 0x%lx\n", input_addr);

            test_full_page_content(restored_pid, uffd, &dsm_msg, 1);
        }else if( choice == 632){
            // Full page dump test (interactive)
            unsigned long input_addr;
            PRINT("[DSM] Enter address to dump (in hex, e.g. 0x555555559380): ");
            fflush(stdout);
            if (scanf("%lx", &input_addr) != 1) {
                fprintf(stderr, "❌ Invalid input\n");
                kill_and_exit(restored_pid);
            }PRINT("[DSM] Address entered: %lx \n",input_addr );

            // Prepare dsm_msg
            dsm_msg.msg_type = MSG_SEND_INVALIDATE;  // or anything suitable
            dsm_msg.page_addr = input_addr;
            dsm_msg.msg_id = 1;

            PRINT("[DSM] Dumping page at address: 0x%lx\n", input_addr);

            test_full_page_content(restored_pid, uffd, &dsm_msg, 2);
        }else if( choice == 633 ){
            // Full page dump test (interactive)
            unsigned long input_addr;
            PRINT("[DSM] Enter address to dump (in hex, e.g. 0x555555559380): ");
            fflush(stdout);
            if (scanf("%lx", &input_addr) != 1) {
                fprintf(stderr, "❌ Invalid input\n");
                kill_and_exit(restored_pid);
            }PRINT("[DSM] Address entered: %lx \n",input_addr );

            // Prepare dsm_msg
            dsm_msg.msg_type = MSG_SEND_INVALIDATE;  // or anything suitable
            dsm_msg.page_addr = input_addr;
            dsm_msg.msg_id = 1;

            PRINT("[DSM] Dumping page at address: 0x%lx\n", input_addr);

            test_full_page_content(restored_pid, uffd, &dsm_msg, 0);
        }else if( choice == 64 ){
            // ✅ Now list all registered pages
            PRINT("\n📋 Registered pages in page_list_data:\n");
            for (int i = 0; i < total_pages; ++i) {
                PRINT("  [%03d] %p, owner:%ld, state(SH/MOD/INV/DIV):%d\n", i, (void *)page_list_data[i].saddr, page_list_data[i].owner_mask, page_list_data[i].state);
            }
        }else if( choice == 65 ){
            // Full page dump test (interactive)
            unsigned long input_addr = 0x7f8981c8e000;
            PRINT("[DSM] Address to dump: %lx\n", input_addr);

            // Prepare dsm_msg
            dsm_msg.msg_type = MSG_SEND_INVALIDATE;  // or anything suitable
            dsm_msg.page_addr = input_addr;
            dsm_msg.msg_id = 1;

            PRINT("[DSM] Dumping page at address: 0x%lx\n", input_addr);

            test_full_page_content(restored_pid, uffd, &dsm_msg, 0);
        }else if( choice == 66 ){
           
            // Full page dump test (interactive)
            unsigned long input_addr = 0x7f8981c8e000;
            //unsigned char page_data[4096];
            
            PRINT("\n🔍 DUAL PAGE COMPARISON TEST\n");
            PRINT("============================\n");
            PRINT("Target address: 0x%lx\n\n", input_addr);
            
            // Prepare message for both local and remote requests
            dsm_msg.msg_type = MSG_GET_PAGE_DATA;
            dsm_msg.page_addr = input_addr;  
            dsm_msg.page_size = 4096;
            dsm_msg.msg_id = 1001;
            
            PRINT("Starting combined local/remote page comparison...\n");
            
            // Call the combined function
            if (compare_local_remote_pages(restored_pid, uffd, &dsm_msg, conn->fd_handler) != 0) {
                PRINT("❌ Combined page comparison failed\n");
                return;
            }
            
            PRINT("✅ Combined page comparison completed\n");


        }else if( choice == 67 ){
            // Full page dump test (interactive)
            unsigned long input_addr = 0x7f8981c8e000;
            unsigned char or_result_page[4096];
            
            PRINT("\n🔍 DUAL PAGE COMPARISON + OR TEST\n");
            PRINT("==================================\n");
            PRINT("Target address: 0x%lx\n\n", input_addr);
            
            // Prepare message for both local and remote requests
            dsm_msg.msg_type = MSG_GET_PAGE_DATA;
            dsm_msg.page_addr = input_addr;  
            dsm_msg.page_size = 4096;
            dsm_msg.msg_id = 1001;
            
            PRINT("Starting combined local/remote page comparison with OR operation...\n");
            
            // Call the enhanced function
            if (compare_and_or_pages(restored_pid, uffd, &dsm_msg, conn->fd_handler, or_result_page, -1) != 0) {
                PRINT("❌ Combined page comparison and OR failed\n");
                return;
            }
            
            PRINT("✅ Combined page comparison and OR completed\n");
            PRINT("OR result is stored in or_result_page buffer\n");
        }else if( choice == 68 ){
            // Full page dump test (interactive)
            unsigned long input_addr = 0x7f8981c8e000;
            
            PRINT("\n🔄 COMPLETE PAGE MERGE WORKFLOW TEST\n");
            PRINT("====================================\n");
            PRINT("Target address: 0x%lx\n", input_addr);
            PRINT("Workflow: Compare → OR Merge → Fill Local\n\n");
            
            // Prepare message for both local and remote requests
            dsm_msg.msg_type = MSG_GET_PAGE_DATA;
            dsm_msg.page_addr = input_addr;  
            dsm_msg.page_size = 4096;
            dsm_msg.msg_id = 1001;
            
            PRINT("Starting complete page merge workflow...\n");
            
            // Call the complete workflow function
            if (complete_page_merge_workflow(restored_pid, uffd, &dsm_msg, conn->fd_handler) != 0) {
                PRINT("❌ Complete page merge workflow failed\n");
                return;
            }
            
            PRINT("✅ Complete page merge workflow finished successfully\n");
        }else if( choice == 69 ){
            unsigned long input_addr;
            PRINT("[DSM] Enter address to dump (in hex, e.g. 0x555555559380): ");
            fflush(stdout);
            if (scanf("%lx", &input_addr) != 1) {
                fprintf(stderr, "❌ Invalid input\n");
                kill_and_exit(restored_pid);
            }PRINT("[DSM] Address entered: %lx \n",input_addr );
            
            
            PRINT("\n🔄 COMPLETE PAGE MERGE WORKFLOW TEST\n");
            PRINT("====================================\n");
            PRINT("Target address: 0x%lx\n", input_addr);
            PRINT("Workflow: Compare → OR Merge → Fill Local\n\n");
            
            // Prepare message for both local and remote requests
            dsm_msg.msg_type = MSG_GET_PAGE_DATA;
            dsm_msg.page_addr = input_addr;  
            dsm_msg.page_size = 4096;
            dsm_msg.msg_id = 1001;
            
            PRINT("Starting complete page merge workflow...\n");
            
            // Call the complete workflow function
            if (complete_page_merge_workflow(restored_pid, uffd, &dsm_msg, conn->fd_handler) != 0) {
                PRINT("❌ Complete page merge workflow failed\n");
                return;
            }
            
            PRINT("✅ Complete page merge workflow finished successfully\n");
            // Mark page as SHARED and owned by both
            if(  update_page_info(input_addr, -1, SHARED, -2) != 0) kill_and_exit(restored_pid);
            disable_wp( uffd, (void *) input_addr); 
        }else if (choice == 7) {
			// SIMULATE GET_PAGE_DATA
			dsm_msg.msg_type = MSG_GET_PAGE_DATA;
			dsm_msg.page_addr = aligned;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
            if (send_get_page(dsm_msg, conn->fd_handler, page_data) == 0) {
                print_global_value_from_page(page_data, sizeof(page_data));
            }
		}else if (choice == 71) {
            interactive_page_inspect(&dsm_msg, conn->fd_handler, 0);
        }else if (choice == 72) {
            interactive_page_inspect(&dsm_msg, conn->fd_handler, 1);
        }else if (choice == 73) {
            interactive_page_inspect(&dsm_msg, conn->fd_handler, 2);
        }else if (choice == 74) {
            // ACTUAL GET PAGE DATA WITH WRITE ON LOCAL ONE
            unsigned long input_addr;
            PRINT("[DSM] Enter address to dump (in hex, e.g. 0x555555559380): ");
            fflush(stdout);
            if (scanf("%lx", &input_addr) != 1) {
                fprintf(stderr, "❌ Invalid input\n");
                //kill_and_exit(restored_pid);
                continue;
            }

            PRINT("[DSM] Address entered: 0x%lx\n", input_addr);

            dsm_msg.msg_type = MSG_GET_PAGE_DATA;
            dsm_msg.page_addr = input_addr;
            dsm_msg.page_size = PAGE_SIZE;
            dsm_msg.msg_id = 1001;

            // =====================================
            // 1️⃣ Get remote page content
            // =====================================
            if (send_get_page(dsm_msg, conn->fd_handler, page_data) == 0) {
                PRINT("✅ Remote page received successfully.\n");

                // Print preview of the received page (optional)
                //print_global_value_from_page(page_data, sizeof(page_data));

                // =====================================
                // 2️⃣ Copy into local address
                // =====================================
                PRINT("\n[DSM] Writing remote page data into local memory...\n");
                //disable_wp( uffd, (void *) input_addr);
                //memcpy((void *)input_addr, page_data, PAGE_SIZE);
                if( fill_local_page_uffdio(uffd, input_addr, page_data, restored_pid) ){
                    PRINT("❌ Failed to update local page at 0x%lx\n", input_addr);
                    continue;
                }
                if( update_page_info(input_addr, -1, SHARED, -2) != 0) kill_and_exit(restored_pid); // Mark page as SHARED and owned by both, if fail, exit and kill
                PRINT("✅ Successfully updated local page at 0x%lx\n", input_addr);

            }
        }else if (choice == 8) {
			// SIMULATE GET_PAGE_DATA_AND_INVALIDATE
			dsm_msg.msg_type = MSG_GET_PAGE_DATA_INVALID;
			dsm_msg.page_addr = aligned;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
            if (send_get_page(dsm_msg, conn->fd_handler, page_data) == 0) {
                print_global_value_from_page(page_data, sizeof(page_data));
            }
            PRINT("[SERVER] Sent MSG_GET_PAGE_DATA_INVALID to server.\n");
		} else if (choice == 9) {
			// SIMULATE INVALIDATE
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;  // or any test address
			dsm_msg.page_size = 4096;
			dsm_msg.msg_id = 1001;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			PRINT("[SERVER] Sent MSG_SEND_INVALIDATE to server.\n");
		}else if (choice == 10) {
			dsm_msg.msg_type = MSG_WAKE_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			PRINT("[SERVER] Sent MSG_WAKE_THREAD to server.\n");
		}else if (choice == 11) {
			dsm_msg.msg_type = MSG_STOP_THREAD;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			PRINT("[SERVER] Sent MSG_STOP_THREAD to server.\n");
		}else if (choice == 12) {
            //vmsplice test
			PRINT("Print mutex content test at %p\n", (void *)0x0c0);
			//Prepare dsm_msg
			dsm_msg.msg_type = MSG_SEND_INVALIDATE;
			dsm_msg.page_addr = aligned;
			PRINT("Do vmsplice test at page %p\n", (void *)dsm_msg.page_addr);
			dsm_msg.msg_id = 1;
			test_mutex_content(restored_pid, uffd, &dsm_msg);
        }else if (choice == 13){
			PRINT("Change mutex content %p\n", (void *)0x5555555580c0);
			runUnlockMutex(restored_pid, (void *)0x5555555580c0);
        }else if (choice == 55){
            PRINT("Barrier, releasing...\n");
            pthread_mutex_lock(&barrier.lock);
            // mark that remote threads have arrived, this is useful if we come before the local threads have, 
            //so that we don't care if the signal was lost since we can check the variable
            remote_threads_barrier_arrived = 1; 
            pthread_cond_broadcast(&barrier.cond);
			PRINT("Barrier released!\n");
            pthread_mutex_unlock(&barrier.lock);
        }else if (choice == 56){
            PRINT("Barrier, releasing...\n");
            pthread_mutex_lock(&barrier.lock);
            // mark that remote threads have arrived, this is useful if we come before the local threads have, 
            //so that we don't care if the signal was lost since we can check the variable
            remote_threads_barrier_arrived = 1; 
            pthread_cond_broadcast(&barrier.cond);
			PRINT("Local Barrier released!\n");
            dsm_msg.msg_type = MSG_BARRIER_RELEASE;
			send(conn->fd_handler, &dsm_msg, sizeof(dsm_msg), 0);
			PRINT("[SERVER] Sent MSG_BARRIER_RELEASE to client.\n");
            pthread_mutex_unlock(&barrier.lock);
        }else {
            PRINT("[DSM] Unknown command: %d\n", choice);
        }
    }
}

/******************************** TESTING FUNCTIONS *******************************/



void register_ranges_from_file(int uffd) {
    FILE *f2 = fopen("/tmp/ranges.txt", "r");
    char line[256];
    unsigned long start_address, end_address;
    size_t page_size;
    int num_pages;
    void *rdma_base;

    if (!f2) {
        pr_perror("[dsm] /tmp/ranges.txt not found\n");
        return;
    }


    while (fgets(line, sizeof(line), f2)) {
        if (sscanf(line, "base=%lx page_size=%zu num_pages=%d",
                   &start_address, &page_size, &num_pages) != 3) {
            fprintf(stderr, "[dsm] failed to parse line: %s", line);
            continue;
        }
        rdma_base = mmap(NULL, num_pages * page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

        for (int i = 0; i < num_pages; i++) {
            unsigned long aux = start_address + i * page_size;
            PRINT("Registering page %d at address %lx\n", total_pages + i, aux);
            page_list_data[total_pages].saddr = aux;
            page_list_data[total_pages].owner_mask = (1ULL << (N_CLIENTS + 1)) - 1ULL; //all owners, starting shared
            page_list_data[total_pages].state = SHARED;
            page_list_data[total_pages].rdma_addr = rdma_base + i * PAGE_SIZE;

            total_pages++;
        }

        end_address = start_address + page_size * num_pages;
        PRINT("/tmp/ranges.txt: start addr:%lx, end:%lx\n", start_address, end_address);

        register_region_with_uffd(uffd, (void *)start_address, page_size * num_pages);
        enable_region_wp(uffd, (void *)start_address, page_size * num_pages);

    }

    fclose(f2);
}
