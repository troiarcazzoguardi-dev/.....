#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <x86intrin.h>

#include <bpf/xsk.h>
#include <bpf/libbpf.h>

/* ================= CONFIG ================= */
#define MAX_PKT_SIZE 1500
#define MAX_RATE_PPS 50000000
#define XSK_FRAMES 8192
#define XSK_FRAME_SIZE 2048
#define XSK_UMEM_SIZE (XSK_FRAMES*XSK_FRAME_SIZE)
#define BATCH_SIZE 64

/* ================= OPTIONS ================= */
struct opts {
    int port;
    int rate;
    int duration;
    bool af_xdp;
    char iface[IFNAMSIZ];
    char target[64];
};

/* ================= PACKET ================= */
struct packet { uint8_t buf[MAX_PKT_SIZE]; size_t len; };

/* ================= CHECKSUM ================= */
static uint16_t checksum(uint16_t *buf, size_t len){
    uint32_t sum=0;
    while(len>1){sum+=*buf++;len-=2;}
    if(len) sum += *(uint8_t*)buf;
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    return ~sum;
}

/* ================= CLI ================= */
static void parse_cli(int argc,char **argv,struct opts *o){
    memset(o,0,sizeof(*o));
    o->rate=1000000;
    int c;
    while((c=getopt(argc,argv,"p:r:d:i:X"))!=-1){
        switch(c){
            case 'p': o->port=atoi(optarg); break;
            case 'r': o->rate=atoi(optarg); break;
            case 'd': o->duration=atoi(optarg); break;
            case 'i': strncpy(o->iface,optarg,IFNAMSIZ-1); break;
            case 'X': o->af_xdp=true; break;
            default: exit(1);
        }
    }
    if(!o->port || !o->duration || !o->iface[0] || optind>=argc) exit(1);
    if(o->rate>MAX_RATE_PPS) o->rate=MAX_RATE_PPS;
    strncpy(o->target,argv[optind],sizeof(o->target)-1);
}

/* ================= SRC IP ================= */
static uint32_t autodetect_src(uint32_t dst){
    int s=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in tmp={.sin_family=AF_INET,.sin_port=htons(9),.sin_addr.s_addr=dst};
    connect(s,(void*)&tmp,sizeof(tmp));
    struct sockaddr_in name;
    socklen_t len=sizeof(name);
    getsockname(s,(void*)&name,&len);
    close(s);
    return name.sin_addr.s_addr;
}

/* ================= PACKET BUILD ================= */
static void build_udp(struct packet *p,struct opts *o){
    struct iphdr *ip=(void*)p->buf;
    struct udphdr *udp=(void*)(p->buf+sizeof(*ip));
    uint8_t *payload=p->buf+sizeof(*ip)+sizeof(*udp);
    const char *msg="HPINGX-ACADEMIC";
    size_t plen=strlen(msg);
    memcpy(payload,msg,plen);
    udp->source=htons(12345);
    udp->dest=htons(o->port);
    udp->len=htons(sizeof(*udp)+plen);
    ip->ihl=5; ip->version=4; ip->ttl=64; ip->protocol=IPPROTO_UDP;
    inet_pton(AF_INET,o->target,&ip->daddr);
    ip->saddr=autodetect_src(ip->daddr);
    ip->tot_len=htons(sizeof(*ip)+sizeof(*udp)+plen);
    ip->check=checksum((uint16_t*)ip,sizeof(*ip));
    p->len=sizeof(*ip)+sizeof(*udp)+plen;
}

/* ================= XDP LOAD ================= */
static void load_xdp(const char *iface){
    struct bpf_object *obj=bpf_object__open_file("xdp_tx_kern.o",NULL);
    bpf_object__load(obj);
    struct bpf_program *prog=bpf_object__find_program_by_name(obj,"xdp_tx_prog");
    int ifidx=if_nametoindex(iface);
    bpf_set_link_xdp_fd(ifidx,bpf_program__fd(prog),0);
}

/* ================= TSC PACE ================= */
static inline void tsc_sleep(uint64_t cycles){
    uint64_t start=__rdtsc();
    while(__rdtsc()-start<cycles) { _mm_pause(); }
}

/* ================= AF_XDP THREAD ================= */
struct xsk_thread_arg { struct packet *pkt; struct opts *o; int cpu; };
static void *xsk_tx_thread(void *arg){
    struct xsk_thread_arg *a=(struct xsk_thread_arg*)arg;
    struct packet *p=a->pkt; struct opts *o=a->o;

    void *umem; posix_memalign(&umem,getpagesize(),XSK_UMEM_SIZE);
    memcpy(umem,p->buf,p->len);
    struct xsk_umem *u;
    struct xsk_ring_prod tx;
    struct xsk_socket *xsk;
    struct xsk_umem_config uc={.frame_size=XSK_FRAME_SIZE,.comp_size=XSK_FRAMES};
    xsk_umem__create(&u,umem,XSK_UMEM_SIZE,NULL,NULL,&uc);
    struct xsk_socket_config sc={.tx_size=XSK_FRAMES,.bind_flags=XDP_USE_NEED_WAKEUP};
    xsk_socket__create(&xsk,o->iface,a->cpu,u,NULL,&tx,&sc);

    cpu_set_t set; CPU_ZERO(&set); CPU_SET(a->cpu,&set); sched_setaffinity(0,sizeof(set),&set);
    uint64_t sent=0;
    uint64_t burst_cycles=(uint64_t)(2.5e4); // da calibrare in laboratorio

    time_t start=time(NULL);
    while(time(NULL)-start<o->duration){
        uint32_t idxs[BATCH_SIZE]; int n=xsk_ring_prod__reserve(&tx,BATCH_SIZE,idxs);
        for(int i=0;i<n;i++){ xsk_ring_prod__tx_desc(&tx,idxs[i])->addr=0;
                                xsk_ring_prod__tx_desc(&tx,idxs[i])->len=p->len;}
        xsk_ring_prod__submit(&tx,n);
        sendto(xsk_socket__fd(xsk),NULL,0,MSG_DONTWAIT,NULL,0);
        sent+=n;
        tsc_sleep(burst_cycles);
    }
    printf("CPU %d sent %lu packets\n",a->cpu,sent);
    return NULL;
}

/* ================= MAIN ================= */
int main(int argc,char **argv){
    struct opts o; struct packet pkt;
    parse_cli(argc,argv,&o);
    build_udp(&pkt,&o);
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(0,&set); sched_setaffinity(0,sizeof(set),&set);

    load_xdp(o.iface);

    if(o.af_xdp){
        int ncpu=sysconf(_SC_NPROCESSORS_ONLN);
        pthread_t threads[ncpu];
        struct xsk_thread_arg args[ncpu];
        for(int i=0;i<ncpu;i++){
            args[i].pkt=&pkt; args[i].o=&o; args[i].cpu=i;
            pthread_create(&threads[i],NULL,xsk_tx_thread,&args[i]);
        }
        for(int i=0;i<ncpu;i++) pthread_join(threads[i],NULL);
    }

    return 0;
}
