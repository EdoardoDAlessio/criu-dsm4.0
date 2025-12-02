// rdma_poc.c (clean re-write)
// Build: gcc -O2 -Wall -Wextra -o rdma_poc rdma_poc.c -libverbs
// Usage:
//   Server: ./rdma_poc 0 <listen_ip> <port>
//   Client: ./rdma_poc 1 <server_ip> <port>
// PoC: TCP bootstrap kept open → exchange QP+MR info (2 MRs) → RC bring-up → RDMA WRITE PING/PONG.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <infiniband/verbs.h>

static inline uint16_t hto16(uint16_t v){ return htons(v); }
static inline uint32_t hto32(uint32_t v){ return htonl(v); }
static inline uint64_t hto64(uint64_t v){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(v & 0xffffffffULL)) << 32) | htonl((uint32_t)(v >> 32));
#else
    return v;
#endif
}
static inline uint16_t to16(uint16_t v){ return ntohs(v); }
static inline uint32_t to32(uint32_t v){ return ntohl(v); }
static inline uint64_t to64(uint64_t v){
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)ntohl((uint32_t)(v & 0xffffffffULL)) << 32) | ntohl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

static void die(const char *msg){ perror(msg); exit(EXIT_FAILURE); }
static void xassert(bool cond, const char *msg){ if(!cond){ fprintf(stderr, "FATAL: %s", msg); exit(EXIT_FAILURE);} }

// ---------- TCP bootstrap ----------
static int tcp_listen(const char *ip, const char *port){
    struct addrinfo hints; memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
    struct addrinfo *res = NULL, *it = NULL; int sfd=-1; int yes=1;
    int rc = getaddrinfo(ip, port, &hints, &res);
    if(rc){ fprintf(stderr, "getaddrinfo: %s", gai_strerror(rc)); exit(1); }
    for(it=res; it; it=it->ai_next){
        sfd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if(sfd<0) continue;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if(bind(sfd, it->ai_addr, it->ai_addrlen)==0 && listen(sfd, 1)==0) break;
        close(sfd); sfd=-1;
    }
    freeaddrinfo(res);
    if(sfd<0) die("tcp_listen");
    return sfd;
}

static int tcp_connect(const char *ip, const char *port){
    struct addrinfo hints; memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL, *it = NULL; int sfd=-1;
    int rc = getaddrinfo(ip, port, &hints, &res);
    if(rc){ fprintf(stderr, "getaddrinfo: %s", gai_strerror(rc)); exit(1); }
    for(it=res; it; it=it->ai_next){
        sfd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if(sfd<0) continue;
        if(connect(sfd, it->ai_addr, it->ai_addrlen)==0) break;
        close(sfd); sfd=-1;
    }
    freeaddrinfo(res);
    if(sfd<0) die("tcp_connect");
    int one=1; setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return sfd;
}

static void tcp_send_all(int fd, const void *buf, size_t len){
    const char *p = (const char*)buf; size_t off=0; 
    while(off<len){ ssize_t n=send(fd,p+off,len-off,0); if(n<=0) die("send"); off+=n; }
}
static void tcp_recv_all(int fd, void *buf, size_t len){
    char *p = (char*)buf; size_t off=0; 
    while(off<len){ ssize_t n=recv(fd,p+off,len-off,MSG_WAITALL); if(n<=0) die("recv"); off+=n; }
}

#define MAX_SGE 1
#define MAX_WR  16

struct __attribute__((packed)) wire_gid { uint8_t raw[16]; };

struct __attribute__((packed)) WireInfo {
    uint32_t qp_num;
    uint16_t lid;
    struct wire_gid gid; // raw 16B
    uint16_t gid_index;  // which GID index peer is using
    uint32_t psn;
    uint64_t mr0_addr; uint32_t mr0_rkey; uint32_t mr0_len; // control
    uint64_t mr1_addr; uint32_t mr1_rkey; uint32_t mr1_len; // data
};

struct RDMA {
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    uint8_t port_num;
    uint16_t lid;
    union ibv_gid sgid; // local gid
    uint16_t gid_index; // chosen local GID index
    int link_layer_ether;
    struct ibv_port_attr port_attr; // cache active_mtu

    void *mr0_buf; size_t mr0_len; struct ibv_mr *mr0;
    void *mr1_buf; size_t mr1_len; struct ibv_mr *mr1;

    struct WireInfo local;
    struct WireInfo remote;
};

static void pick_device_and_port(struct RDMA *r){
    int num=0; struct ibv_device **list = ibv_get_device_list(&num);
    xassert(list && num>0, "No RDMA devices found");
    r->ctx = ibv_open_device(list[0]);
    xassert(r->ctx, "ibv_open_device failed");

    r->port_num = 1;
    memset(&r->port_attr, 0, sizeof(r->port_attr));
    xassert(ibv_query_port(r->ctx, r->port_num, &r->port_attr)==0, "ibv_query_port failed");
    r->lid = r->port_attr.lid;
    r->link_layer_ether = (r->port_attr.link_layer == IBV_LINK_LAYER_ETHERNET);

    memset(&r->sgid, 0, sizeof(r->sgid));
    r->gid_index = 0;
    for (uint16_t i = 0; i < 16; ++i) {
        union ibv_gid g; memset(&g, 0, sizeof(g));
        if (ibv_query_gid(r->ctx, r->port_num, i, &g) == 0) {
            int all_zero = 1; for (int b=0;b<16;b++) if (g.raw[b]) { all_zero=0; break; }
            if (!all_zero) { r->gid_index = i; r->sgid = g; break; }
        }
    }
    if (!r->sgid.raw[0] && !r->sgid.raw[1]) { ibv_query_gid(r->ctx, r->port_num, 0, &r->sgid); r->gid_index = 0; }

    fprintf(stderr, "[RDMA] device=%s port=%u link=%s active_mtu=%d LID=0x%04x GID-idx=%u",
            ibv_get_device_name(list[0]), r->port_num, r->link_layer_ether?"ETH":"IB",
            r->port_attr.active_mtu, r->lid, r->gid_index);

    ibv_free_device_list(list);
}

static void rdma_setup_basic(struct RDMA *r){
    r->pd = ibv_alloc_pd(r->ctx); xassert(r->pd, "alloc_pd");
    r->cq = ibv_create_cq(r->ctx, 64, NULL, NULL, 0); xassert(r->cq, "create_cq");
    struct ibv_qp_init_attr qia; memset(&qia,0,sizeof(qia));
    qia.qp_type = IBV_QPT_RC; qia.send_cq = r->cq; qia.recv_cq = r->cq;
    qia.cap.max_send_wr = MAX_WR; qia.cap.max_recv_wr = MAX_WR;
    qia.cap.max_send_sge = MAX_SGE; qia.cap.max_recv_sge = MAX_SGE;
    r->qp = ibv_create_qp(r->pd, &qia); xassert(r->qp, "create_qp");
}

static void *alloc_page_aligned(size_t len){ void *p=NULL; if(posix_memalign(&p, 4096, len)) return NULL; memset(p,0,len); return p; }

static void rdma_register_regions(struct RDMA *r){
    r->mr0_len = 4096; r->mr1_len = 4096;
    r->mr0_buf = alloc_page_aligned(r->mr0_len);
    r->mr1_buf = alloc_page_aligned(r->mr1_len);
    xassert(r->mr0_buf && r->mr1_buf, "alloc buffers");
    int acc = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    r->mr0 = ibv_reg_mr(r->pd, r->mr0_buf, r->mr0_len, acc); xassert(r->mr0, "reg_mr0");
    r->mr1 = ibv_reg_mr(r->pd, r->mr1_buf, r->mr1_len, acc); xassert(r->mr1, "reg_mr1");

    memset(&r->local, 0, sizeof(r->local));
    r->local.qp_num = r->qp->qp_num;
    r->local.lid    = r->lid;
    memcpy(r->local.gid.raw, r->sgid.raw, 16);
    r->local.gid_index = r->gid_index;
    r->local.psn = (uint32_t)(rand() & 0xffffff);
    r->local.mr0_addr = (uintptr_t)r->mr0_buf; r->local.mr0_rkey = r->mr0->rkey; r->local.mr0_len = (uint32_t)r->mr0_len;
    r->local.mr1_addr = (uintptr_t)r->mr1_buf; r->local.mr1_rkey = r->mr1->rkey; r->local.mr1_len = (uint32_t)r->mr1_len;
}

static void wireinfo_hton(struct WireInfo *w){
    w->qp_num = hto32(w->qp_num); w->lid = hto16(w->lid); w->gid_index = hto16(w->gid_index); w->psn = hto32(w->psn);
    w->mr0_addr = hto64(w->mr0_addr); w->mr0_rkey = hto32(w->mr0_rkey); w->mr0_len = hto32(w->mr0_len);
    w->mr1_addr = hto64(w->mr1_addr); w->mr1_rkey = hto32(w->mr1_rkey); w->mr1_len = hto32(w->mr1_len);
}
static void wireinfo_ntoh(struct WireInfo *w){
    w->qp_num = to32(w->qp_num); w->lid = to16(w->lid); w->gid_index = to16(w->gid_index); w->psn = to32(w->psn);
    w->mr0_addr = to64(w->mr0_addr); w->mr0_rkey = to32(w->mr0_rkey); w->mr0_len = to32(w->mr0_len);
    w->mr1_addr = to64(w->mr1_addr); w->mr1_rkey = to32(w->mr1_rkey); w->mr1_len = to32(w->mr1_len);
}

static void qp_to_init(struct RDMA *r){
    struct ibv_qp_attr a; memset(&a,0,sizeof(a)); int flags=0;
    a.qp_state = IBV_QPS_INIT; flags |= IBV_QP_STATE;
    a.pkey_index = 0; flags |= IBV_QP_PKEY_INDEX;
    a.port_num = r->port_num; flags |= IBV_QP_PORT;
    a.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ; flags |= IBV_QP_ACCESS_FLAGS;
    xassert(ibv_modify_qp(r->qp, &a, flags)==0, "modify_qp INIT");
}

static void qp_to_rtr(struct RDMA *r){
    struct ibv_qp_attr a; memset(&a,0,sizeof(a)); int flags = 0;
    a.qp_state = IBV_QPS_RTR; flags |= IBV_QP_STATE;
    a.path_mtu = r->port_attr.active_mtu; flags |= IBV_QP_PATH_MTU;
    a.dest_qp_num = r->remote.qp_num; flags |= IBV_QP_DEST_QPN;
    a.rq_psn = r->remote.psn; flags |= IBV_QP_RQ_PSN;
    a.max_dest_rd_atomic = 1; flags |= IBV_QP_MAX_DEST_RD_ATOMIC;
    a.min_rnr_timer = 12; flags |= IBV_QP_MIN_RNR_TIMER;

    a.ah_attr.port_num = r->port_num; a.ah_attr.sl = 0; a.ah_attr.src_path_bits = 0;
    if(r->link_layer_ether){
        a.ah_attr.is_global = 1;
        memcpy(a.ah_attr.grh.dgid.raw, r->remote.gid.raw, 16);
        a.ah_attr.grh.sgid_index = r->gid_index;
        a.ah_attr.grh.hop_limit = 64;
        a.ah_attr.grh.traffic_class = 0;
        a.ah_attr.grh.flow_label = 0;
    } else {
        a.ah_attr.is_global = 0;
        a.ah_attr.dlid = r->remote.lid;
    }
    xassert(ibv_modify_qp(r->qp, &a, flags)==0, "modify_qp RTR");
}

static void qp_to_rts(struct RDMA *r){
    struct ibv_qp_attr a; memset(&a,0,sizeof(a)); int flags=0;
    a.qp_state = IBV_QPS_RTS; flags |= IBV_QP_STATE;
    a.timeout = 14; flags |= IBV_QP_TIMEOUT;
    a.retry_cnt = 7; flags |= IBV_QP_RETRY_CNT;
    a.rnr_retry = 7; flags |= IBV_QP_RNR_RETRY;
    a.sq_psn = r->local.psn; flags |= IBV_QP_SQ_PSN;
    a.max_rd_atomic = 1; flags |= IBV_QP_MAX_QP_RD_ATOMIC;
    xassert(ibv_modify_qp(r->qp, &a, flags)==0, "modify_qp RTS");
}

static void exchange_wireinfo(int sock, struct RDMA *r, int is_server){
    struct WireInfo loc = r->local; wireinfo_hton(&loc);
    if(is_server){
        tcp_send_all(sock, &loc, sizeof(loc));
        tcp_recv_all(sock, &r->remote, sizeof(r->remote));
    } else {
        tcp_recv_all(sock, &r->remote, sizeof(r->remote));
        tcp_send_all(sock, &loc, sizeof(loc));
    }
    wireinfo_ntoh(&r->remote);
}

static void post_rdma_write(struct RDMA *r, uint64_t remote_addr, uint32_t rkey, const void *src, size_t len){
    struct ibv_sge sge; memset(&sge,0,sizeof(sge));
    sge.addr=(uintptr_t)src; sge.length=(uint32_t)len; sge.lkey=r->mr1->lkey;
    struct ibv_send_wr wr; memset(&wr,0,sizeof(wr));
    wr.opcode = IBV_WR_RDMA_WRITE; wr.sg_list=&sge; wr.num_sge=1; wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr.rdma.remote_addr = remote_addr; wr.wr.rdma.rkey = rkey;
    struct ibv_send_wr *bad=NULL; xassert(ibv_post_send(r->qp, &wr, &bad)==0, "post RDMA WRITE");
}

static void wait_one_completion(struct RDMA *r){
    struct ibv_wc wc; int n;
    do { n = ibv_poll_cq(r->cq, 1, &wc); } while(n==0);
    xassert(n>0, "poll_cq error");
    xassert(wc.status==IBV_WC_SUCCESS, "CQ completion not successful");
}

static void do_handshake(int sock, struct RDMA *r, int is_server){
    (void)sock; // still open for control
    const char *PING = "PING"; const char *PONG = "PONG";
    if(is_server){
        memcpy(r->mr1_buf, PING, 5);
        post_rdma_write(r, r->remote.mr0_addr, r->remote.mr0_rkey, r->mr1_buf, 5);
        wait_one_completion(r);
        fprintf(stderr, "[RDMA] Server wrote PING → remote MR0");
        volatile char *ctrl = (volatile char*)r->mr0_buf;
        fprintf(stderr, "[RDMA] Server waiting for PONG in local MR0...");
        while (strncmp((const char*)ctrl, PONG, 4) != 0) { sched_yield(); }
        fprintf(stderr, "[RDMA] Server received PONG in MR0. Handshake OK.");
    } else {
        volatile char *ctrl = (volatile char*)r->mr0_buf;
        fprintf(stderr, "[RDMA] Client waiting for PING in local MR0...");
        while (strncmp((const char*)ctrl, PING, 4) != 0) { sched_yield(); }
        fprintf(stderr, "[RDMA] Client got PING. Writing PONG back...");
        memcpy(r->mr1_buf, PONG, 5);
        post_rdma_write(r, r->remote.mr0_addr, r->remote.mr0_rkey, r->mr1_buf, 5);
        wait_one_completion(r);
        fprintf(stderr, "[RDMA] Client wrote PONG → remote MR0. Handshake OK.");
    }
}

int main(int argc, char **argv){
    if(argc != 4){
        fprintf(stderr, "Usage: %s <role 0=server 1=client> <ip> <port>", argv[0]);
        return 1;
    }
    srand((unsigned)time(NULL));

    int role = atoi(argv[1]);
    const char *ip = argv[2];
    const char *port = argv[3];

    int sock=-1, lfd=-1;
    if (role == 0) {
        lfd = tcp_listen(ip, port);
        struct sockaddr_in peer; socklen_t pl = sizeof(peer);
        sock = accept(lfd, (struct sockaddr *)&peer, &pl);
        if (sock < 0) die("accept");
        close(lfd);
        fprintf(stderr, "[CTRL] Accepted TCP from %s:%u", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
    } else if (role == 1) {
        sock = tcp_connect(ip, port);
        fprintf(stderr, "[CTRL] Connected to %s:%s", ip, port);
    } else {
        fprintf(stderr, "role must be 0 or 1");
        return 1;
    }

    struct RDMA r; memset(&r,0,sizeof(r));
    pick_device_and_port(&r);
    rdma_setup_basic(&r);
    rdma_register_regions(&r);

    qp_to_init(&r);
    exchange_wireinfo(sock, &r, role == 0);
    qp_to_rtr(&r);
    qp_to_rts(&r);

    memset(r.mr0_buf, 0, r.mr0_len);
    memset(r.mr1_buf, 0, r.mr1_len);
    do_handshake(sock, &r, role == 0);

    fprintf(stderr, "[CTRL] TCP control link open on fd=%d. Press ENTER to exit.", sock);
    getchar();

    close(sock);
    ibv_dereg_mr(r.mr0); ibv_dereg_mr(r.mr1);
    ibv_destroy_qp(r.qp);
    ibv_destroy_cq(r.cq);
    ibv_dealloc_pd(r.pd);
    ibv_close_device(r.ctx);
    free(r.mr0_buf); free(r.mr1_buf);
    return 0;
}
