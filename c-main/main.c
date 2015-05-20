#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <locale.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <sched.h>
#include <numa.h>
#include <pthread.h>
#include <getopt.h>

/* Import our rust library. */
#include <pktproc.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define PS_MAX_NODES        4
#define PS_MAX_CPUS         64
#define PS_MAX_DEVICES      16
#define PS_MAX_QUEUES       128

#define RTE_LOGTYPE_MAIN    RTE_LOGTYPE_USER1

#define MAX_LATENCY         10000  /* from 0 usec to 9.999 msec */
#define MAX_FLOWS           16384
#define MAX_PATH            260
#define INET_ADDRSTRLEN     16
#define INET6_ADDRSTRLEN    46
#define ETH_EXTRA_BYTES     24  // preamble, padding bytes
#define IP_TYPE_TCP         6
#define IP_TYPE_UDP         17

/* custom flag definitions to examine pcap packet */
#define IPPROTO_IPv6_FRAG_CUSTOM    44
#define IPPROTO_ICMPv6_CUSTOM       58
#define IPPROTO_OSPF_CUSTOM         89

struct pspgen_context {
    /* About myself */
    int num_cpus;
    int my_node;
    int my_cpu;
    uint64_t tsc_hz;

    int num_attached_ports;
    int num_txq_per_port;
    int attached_ports[PS_MAX_DEVICES];  /** The list of node-local ports. */
    int ring_idx;                        /** The queue ID for RX/TX in this core. */
    struct rte_mempool *tx_mempools[PS_MAX_DEVICES];

    int batch_size;
    int loop_count;

    /* States */
    rte_atomic16_t working;
    uint64_t time_limit;
    uint64_t elapsed_sec;

    /* Statistics */
    uint64_t total_tx_packets;
    uint64_t total_tx_batches;
    uint64_t total_tx_bytes;
    uint64_t last_total_tx_packets;
    uint64_t last_total_tx_batches;
    uint64_t last_total_tx_bytes;
    uint64_t total_rx_packets;
    uint64_t total_rx_batches;
    uint64_t total_rx_bytes;
    uint64_t last_total_rx_packets;
    uint64_t last_total_rx_batches;
    uint64_t last_total_rx_bytes;
    uint64_t tx_packets[PS_MAX_DEVICES];
    uint64_t tx_batches[PS_MAX_DEVICES];
    uint64_t tx_bytes[PS_MAX_DEVICES];
    uint64_t rx_packets[PS_MAX_DEVICES];
    uint64_t rx_batches[PS_MAX_DEVICES];
    uint64_t rx_bytes[PS_MAX_DEVICES];

    uint64_t last_usec;
    struct tm begin;  /* beginning time in wall-clock */

    uint64_t latency_buckets[MAX_LATENCY];
    FILE *latency_log;
};
static struct pspgen_context *contexts[PS_MAX_CPUS] = {NULL,};

struct port_info {
    uint16_t port_id;
    uint8_t mac_addr[6];
};

/* Global options. */
static bool debug = false;

/* Available devices in the system */
static int num_devices = -1;
static struct rte_eth_dev_info devices[PS_MAX_DEVICES];
static struct ether_addr my_ethaddrs[PS_MAX_DEVICES];

/* Used devices */
static int num_devices_registered = 0;
static int devices_registered[PS_MAX_DEVICES];

static int ps_num_hyperthreading_siblings(void) {
    // TODO: make it portable
    static rte_spinlock_t _ht_func_lock = RTE_SPINLOCK_INITIALIZER;
    static int memoized_result = -1;
    rte_spinlock_lock(&_ht_func_lock);
    if (memoized_result == -1) {
        char line[2048];
        unsigned len, i, count;
        FILE *f = fopen("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", "r");
        assert(NULL != f);
        assert(NULL != fgets(line, 2048, f));
        fclose(f);
        len = strnlen(line, 2048);
        count = 1;
        for (i = 0; i < len; i++)
            if (line[i] == ',')
                count ++;
        assert(count >= 1);
        memoized_result = count;
    }
    rte_spinlock_unlock(&_ht_func_lock);
    return memoized_result;
}

static int ps_get_num_cpus(void) {
    return (int) sysconf(_SC_NPROCESSORS_ONLN) / ps_num_hyperthreading_siblings();
}

static int ps_bind_cpu(int cpu) {
    struct bitmask *bmask;
    size_t ncpus = ps_get_num_cpus();

    bmask = numa_bitmask_alloc(ncpus);
    assert(bmask != NULL);
    assert(cpu >= 0 && cpu < ncpus);
    numa_bitmask_clearall(bmask);
    numa_bitmask_setbit(bmask, cpu);
    numa_sched_setaffinity(0, bmask);
    numa_bitmask_free(bmask);

    /* skip NUMA stuff for UMA systems */
    if (numa_available() == -1 || numa_max_node() == 0)
        return 0;

    bmask = numa_bitmask_alloc(numa_num_configured_nodes());
    assert(bmask != NULL);
    numa_bitmask_clearall(bmask);
    numa_bitmask_setbit(bmask, numa_node_of_cpu(cpu));
    numa_set_membind(bmask);
    numa_bitmask_free(bmask);
    return 0;
}

static bool ps_in_samenode(int cpu, int ifindex)
{
    if (numa_available() == -1 || numa_max_node() == 0)
        return true;

    assert(ifindex >= 0);
    assert(ifindex < PS_MAX_DEVICES);

    /* CPU 0,2,4,6,... -> Node 0,
     * CPU 1,3,5,7,... -> Node 1. */
    int cpu_node = numa_node_of_cpu(cpu);
    assert(cpu_node != -1);

    int if_node = devices[ifindex].pci_dev->numa_node;
    assert(if_node < numa_num_configured_nodes());

    return cpu_node == if_node;
}

static uint64_t ps_get_usec(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    return now.tv_sec * 1000000L + now.tv_nsec / 1000L;
}

static int ether_aton(const char *buf, size_t len, struct ether_addr *addr)
{
    char piece[3];
    int j = 0, k = 0;
    for (int i = 0; i < len; i ++) {
        if (buf[i] == ':') {
            if (j == 0 && i > 0)
                continue;
            else
                return -EINVAL;
        }
        piece[j++] = buf[i];
        if (j == 2) {
            piece[j] = '\0';
            char *endptr;
            addr->addr_bytes[k] = (int) strtol(piece, &endptr, 16);
            if (errno < 0)
                return errno;
            if (endptr == piece)
                return -EINVAL;
            k++;
            if (k == ETHER_ADDR_LEN) break;
            j = 0;
        }
    }
    if (k < ETHER_ADDR_LEN) return -EINVAL;
    return 0;
}

void stop_all(void)
{
    int num_cpus = ps_get_num_cpus();
    for (int c = 0; c < num_cpus; c++) {
        if (contexts[c] != NULL) {
            rte_atomic16_set(&contexts[c]->working, 0);
        }
    }
}

void handle_signal(int signal)
{
    stop_all();
}

void update_stats(struct rte_timer *tim, void *arg)
{
    struct pspgen_context *ctx = (struct pspgen_context *) arg;
    uint64_t cur_usec = ps_get_usec();
    int64_t usec_diff = cur_usec - ctx->last_usec;

    for (int i = 0; i < ctx->num_attached_ports; i++) {
        int port_idx = ctx->attached_ports[i];
        ctx->total_tx_packets += ctx->tx_packets[port_idx];
        ctx->total_tx_batches += ctx->tx_batches[port_idx];
        ctx->total_tx_bytes   += ctx->tx_bytes[port_idx];
        ctx->total_rx_packets += ctx->rx_packets[port_idx];
        ctx->total_rx_batches += ctx->rx_batches[port_idx];
        ctx->total_rx_bytes   += ctx->rx_bytes[port_idx];
    }

    char linebuf[512];
    int p = 0;
    uint64_t tx_pps = (ctx->total_tx_packets - ctx->last_total_tx_packets) / (usec_diff / 1e6f);
    uint64_t tx_bps = ((ctx->total_tx_bytes - ctx->last_total_tx_bytes) * 8) / (usec_diff / 1e6f);
    p = sprintf(linebuf, "CPU %d: %'10ld pps, %6.3f Gbps (%5.1f pkts/batch)",
                ctx->my_cpu, tx_pps, (tx_bps + (tx_pps * ETH_EXTRA_BYTES) * 8) / 1e9f,
                (float) (ctx->total_tx_packets - ctx->last_total_tx_packets)
                        / (ctx->total_tx_batches - ctx->last_total_tx_batches));

    for (int i = 0; i < ctx->num_attached_ports; i++) {
        int port_idx = ctx->attached_ports[i];
        const char *driver = devices[port_idx].driver_name;

        tx_pps = ctx->tx_packets[port_idx];
        tx_bps = ctx->tx_bytes[port_idx] * 8;
        p += sprintf(linebuf + p, "  %s.%d: %'10ld pps,%6.3f Gbps",
                     driver, port_idx, tx_pps, (tx_bps + (tx_pps * ETH_EXTRA_BYTES) * 8) / 1e9f);
    }
    printf("%s\n", linebuf);

    ctx->elapsed_sec ++;
    if (ctx->time_limit > 0 && ctx->elapsed_sec >= ctx->time_limit)
        stop_all();

    for (int i = 0; i < ctx->num_attached_ports; i++) {
        int port_idx = ctx->attached_ports[i];
        ctx->tx_packets[port_idx] = 0;
        ctx->tx_batches[port_idx] = 0;
        ctx->tx_bytes[port_idx] = 0;
        ctx->rx_packets[port_idx] = 0;
        ctx->rx_batches[port_idx] = 0;
        ctx->rx_bytes[port_idx] = 0;
    }
    ctx->last_total_tx_packets = ctx->total_tx_packets;
    ctx->last_total_tx_batches = ctx->total_tx_batches;
    ctx->last_total_tx_bytes   = ctx->total_tx_bytes;
    ctx->last_total_rx_packets = ctx->total_rx_packets;
    ctx->last_total_rx_batches = ctx->total_rx_batches;
    ctx->last_total_rx_bytes   = ctx->total_rx_bytes;
    ctx->last_usec = cur_usec;
}

static inline uint32_t myrand(uint64_t *seed)
{
    *seed = *seed * 1103515245 + 12345;
    return (uint32_t)(*seed >> 32);
}

int io_loop(void *arg)
{
    struct pspgen_context *ctx = contexts[rte_lcore_id()];
    if (ctx == NULL) return 0;
    assert(ctx->my_cpu == rte_lcore_id());
    ps_bind_cpu(ctx->my_cpu);

    struct rte_timer *stat_timer = rte_zmalloc("timer", sizeof(struct rte_timer), RTE_CACHE_LINE_SIZE);
    assert(stat_timer != NULL);
    rte_timer_init(stat_timer);
    rte_timer_reset(stat_timer, rte_get_timer_hz() * 1, PERIODICAL, ctx->my_cpu, update_stats, (void *) ctx);

    rte_atomic16_init(&ctx->working);
    rte_atomic16_set(&ctx->working, 1);
 
    struct port_info port_infos[PS_MAX_DEVICES];
    for (unsigned i = 0; i < num_devices; i++) {
        port_infos[i].port_id = i;
        memcpy(port_infos[i].mac_addr, &my_ethaddrs[i], 6);
    }
    pktproc_init(ctx->my_cpu, (void *) port_infos, num_devices);

    while (rte_atomic16_read(&ctx->working) == 1)
    {
        unsigned total_recv_cnt = 0;
        size_t max_num_pkts = ctx->batch_size * ctx->num_attached_ports;
        struct rte_mbuf *pkts[max_num_pkts];

        for (unsigned i = 0; i < ctx->num_attached_ports; i++) {
            unsigned port_idx = ctx->attached_ports[i];
            unsigned recv_cnt = rte_eth_rx_burst(port_idx, ctx->ring_idx, &pkts[total_recv_cnt], ctx->batch_size);
            for (unsigned j = 0; j < recv_cnt; j++) {
                ctx->rx_bytes[port_idx] += rte_pktmbuf_pkt_len(pkts[j]);
            }
            total_recv_cnt += recv_cnt;
            ctx->rx_packets[port_idx] += recv_cnt;
            ctx->rx_batches[port_idx] += 1;
        } /* end of for(attached_ports) */

        for (unsigned i = 0; i < total_recv_cnt; i += ctx->batch_size) {
            unsigned batch_size = RTE_MIN(ctx->batch_size, total_recv_cnt - i);
            /* Call the rust function. */
            #if 1
            pktproc_process(ctx->my_cpu, (void **) &pkts[i], batch_size);
            #else
            /* Equivalent C version. */
            for (unsigned j = 0; j < batch_size; j++) {
                unsigned p = i + j;
                struct ether_hdr *ethh = rte_pktmbuf_mtod(pkts[p], struct ether_hdr *);
                struct Packet *pkt = (struct Packet *) ((char*) pkts[p] + sizeof(struct rte_mbuf));
                pkt->result = -1;
                if ((ethh->d_addr.addr_bytes[0] & 0x01) == 0) {
                    memcpy(&ethh->d_addr, &ethh->s_addr, 6);
                    memcpy(&ethh->s_addr, &my_ethaddrs[pkts[p]->port], 6);
                    pkt->result = (signed) pkts[p]->port;
                }
            }
            #endif
        }

        /* Split-forward. */
        struct rte_mbuf *tx_batches[PS_MAX_DEVICES][ctx->batch_size * ctx->num_attached_ports];
        unsigned tx_counts[PS_MAX_DEVICES] = {0, };
        for (unsigned j = 0; j < total_recv_cnt; j++) {
            struct Packet *pkt = (struct Packet *) ((char*) pkts[j] + sizeof(struct rte_mbuf));
            if (pkt->result == -1) {
                rte_pktmbuf_free(pkts[j]);
            } else {
                assert(pkt->result >= 0);
                assert(pkt->result < num_devices);
                tx_batches[pkt->result][tx_counts[pkt->result] ++] = pkts[j];
                ctx->tx_packets[pkt->result] ++;
                ctx->tx_bytes[pkt->result] += rte_pktmbuf_data_len(pkts[j]);
            }
        }
        for (unsigned d = 0; d < num_devices_registered; d++) {
            unsigned out_port_idx = devices_registered[d];
            if (tx_counts[out_port_idx] == 0) continue;
            unsigned sent_cnt = rte_eth_tx_burst(out_port_idx, ctx->my_cpu, &tx_batches[out_port_idx][0], tx_counts[out_port_idx]);
            for (unsigned j = sent_cnt; j < tx_counts[out_port_idx]; j++) {
                rte_pktmbuf_free(tx_batches[out_port_idx][j]);
            }
        }

        rte_timer_manage();

    } /* end of while(working) */

    usleep(10000 * (ctx->my_cpu + 1));
    if (ctx->my_cpu == 0) printf("----------\n");
    printf("CPU %d: total %'lu packets, %'lu bytes transmitted\n",
            ctx->my_cpu, ctx->total_tx_packets, ctx->total_tx_bytes);

    return 0;
}

void print_usage(const char *program)
{
    printf("Usage: %s [EAL options] -- [PSPGEN options]\n\n", program);
    printf("To use in packet-generator (pktgen) mode:\n");
    printf("  %s "
           "-i all|dev1 [-i dev2] ... "
           "[-n <num_packets>] "
           "[-s <chunk_size>] "
           "[-p <packet_size>] "
           "[--min-pkt-size <min_packet_size>] "
           "[-f <num_flows>] "
           "[-r <randomize_flows>] "
           "[-v <ip_version>] "
           "[-l <latency_measure>] "
           "[--latency-record-prefix <prefix>] "
           "[-c <loop_count>] "
           "[-t <seconds>] "
           "[-g <offered_throughput>] "
           "[--debug] "
           "[--loglevel <debug|info|...|critical|emergency>] "
           "[--neighbor-conf <neighbor_config_file>]\n",
           program);
    printf("\nTo replay traces (currently only supports pcap):\n");
    printf("  %s -i all|dev1 [-i dev2] ... --trace <file_name> [--repeat] [--debug]\n\n", program);

    printf("  default <num_packets> is 0. (0 = infinite)\n");
    printf("    (note: <num_packets> is a per-cpu value.)\n");
    printf("  default <chunk_size> is 64. packets per batch\n");
    printf("  default <packet_size> is 60. (w/o 4-byte CRC)\n");
    printf("  default <min_packet_size> is same to <packet_size>.\n"
           "    If set, it will generate packets randomly sized\n"
           "    between <min_packet_size> and <packet_size>.\n"
           "    Must follow after <packet_size> option to be effective.\n");
    printf("  default <num_flows> is 0. (0 = infinite)\n");
    printf("  default <randomize_flows> is 1. (0 = off)\n");
    printf("  default <ip_version> is 4. (6 = ipv6)\n");
    printf("  default <latency_measure> is 0. (1 = on)\n");
    printf("  default <prefix> is none (don't record latency histogram into files).\n");
    printf("  default <loop_count> is 1. (only valid for latency mesaurement)\n"); // TODO: re-implement
    printf("  default <seconds> is 0. (0 = infinite)\n");
    printf("  default <offered_throughput> is maximum possible. (Gbps including Ethernet overheads)\n");
    printf("  default <neighbor_config_file> is ./neighbors.conf\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    unsigned loglevel = RTE_LOG_WARNING;
    int ret;
    int num_cpus    = 0;
    int batch_size  = 64;
    uint64_t time_limit = 0;
    uint64_t begin, end;

    setlocale(LC_NUMERIC, "");
    rte_set_log_level(RTE_LOG_WARNING);
    rte_set_application_usage_hook(print_usage);
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters.\n");
    argc -= ret;
    argv += ret;

    /* Initialize system information. */
    num_cpus = ps_get_num_cpus();
    assert(num_cpus >= 1);
    num_devices = rte_eth_dev_count();
    assert(num_devices != -1);
    if (num_devices == 0)
        rte_exit(EXIT_FAILURE, "There is no detected device.\n");
    for (int i = 0; i < num_devices; i++) {
        rte_eth_dev_info_get((uint8_t) i, &devices[i]);
        rte_eth_macaddr_get((uint8_t) i, &my_ethaddrs[i]);
    }

    /* Argument parsing. */
    struct option long_opts[] = {
        {"repeat", no_argument, NULL, 0},
        {"trace", required_argument, NULL, 0},
        {"debug", no_argument, NULL, 0},
        {"loglevel", required_argument, NULL, 0},
        {"latency-record-prefix", required_argument, NULL, 0},
        {"min-pkt-size", required_argument, NULL, 0},
        {"neighbor-conf", required_argument, NULL, 0},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };
    while (true) {
        int optidx = 0;
        int c = getopt_long(argc, argv, "i:n:s:p:f:v:c:t:g:rlh", long_opts, &optidx);
        if (c == -1) break;
        switch (c) {
        case 0:
            if (!strcmp("loglevel", long_opts[optidx].name)) {
                assert(optarg != NULL);
                if (!strcmp("debug", optarg))
                    loglevel = RTE_LOG_DEBUG;
                else if (!strcmp("info", optarg))
                    loglevel = RTE_LOG_INFO;
                else if (!strcmp("notice", optarg))
                    loglevel = RTE_LOG_NOTICE;
                else if (!strcmp("warning", optarg))
                    loglevel = RTE_LOG_WARNING;
                else if (!strcmp("error", optarg))
                    loglevel = RTE_LOG_ERR;
                else if (!strcmp("critical", optarg))
                    loglevel = RTE_LOG_CRIT;
                else if (!strcmp("emergency", optarg))
                    loglevel = RTE_LOG_EMERG;
                else
                    rte_exit(EXIT_FAILURE, "Invalid value for loglevel: %s\n", optarg);
            } else if (!strcmp("debug", long_opts[optidx].name)) {
                debug = true;
            }
            break;
        case 'h':
            print_usage(argv[1]);
            break;
        case 'i': {
            int ifindex = -1;
            int j;
            if (optarg == NULL)
                rte_exit(EXIT_FAILURE, "-i option requires an argument.\n");

            /* Register all devices. */
            if (!strcmp(optarg, "all")) {
                for (j = 0; j < num_devices; j++)
                    devices_registered[j] = j;
                num_devices_registered = num_devices;
                continue;
            }

            /* Or, register one by one. */
            for (j = 0; j < num_devices; j++) {
                char ifname[64];
                // Example of interface name: igb_uio.2
                snprintf(ifname, 64, "%s.%d", devices[j].driver_name, j);
                if (!strcmp(optarg, ifname))
                    ifindex = j;
            }

            if (ifindex == -1)
                rte_exit(EXIT_FAILURE, "device %s does not exist!\n", optarg);

            for (j = 0; j < num_devices_registered; j++)
                if (devices_registered[j] == ifindex)
                    rte_exit(EXIT_FAILURE, "device %s is registered more than once!\n", optarg);

            devices_registered[num_devices_registered] = ifindex;
            num_devices_registered ++;
            } break;
        case 's':
            batch_size = atoi(optarg);
            assert(batch_size >= 1 && batch_size <= 2048);
            break;
        case 't':
            time_limit = atoi(optarg);
            break;
        case '?':
            rte_exit(EXIT_FAILURE, "Unknown option or missing argument: %c\n", optopt);
            break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
    if (num_devices_registered == 0)
        rte_exit(EXIT_FAILURE, "No devices registered!\n");
    rte_set_log_level(loglevel);

    /* Show the configuration. */
    printf("# of CPUs = %d\n", num_cpus);
    printf("batch size = %d\n", batch_size);
    printf("interfaces: ");
    for (int i = 0; i < num_devices_registered; i++) {
        if (i > 0)
            printf(", ");
        printf("%s.%d", devices[devices_registered[i]].driver_name, devices_registered[i]);
    }
    printf("\n");
    printf("----------\n");

    /* Initialize devices and queues. */
    printf("Initializing interfaces...\n");

    unsigned num_rxq_per_port = num_cpus / numa_num_configured_nodes();
    unsigned num_txq_per_port = num_cpus;
    unsigned num_rx_desc = 512;
    unsigned num_tx_desc = 512;

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode    = ETH_MQ_RX_RSS;
    uint8_t hash_key[40];
    for (unsigned k = 0; k < sizeof(hash_key); k++)
        hash_key[k] = (uint8_t) rand();
    port_conf.rx_adv_conf.rss_conf.rss_key = hash_key;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
    port_conf.txmode.mq_mode    = ETH_MQ_TX_NONE;
    port_conf.fdir_conf.mode    = RTE_FDIR_MODE_NONE;
    port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
    port_conf.fdir_conf.status  = RTE_FDIR_NO_REPORT_STATUS;

    struct rte_eth_rxconf rx_conf;
    memset(&rx_conf, 0, sizeof(rx_conf));
    rx_conf.rx_thresh.pthresh = 8;
    rx_conf.rx_thresh.hthresh = 4;
    rx_conf.rx_thresh.wthresh = 4;
    rx_conf.rx_free_thresh = 32;
    rx_conf.rx_drop_en     = 0; /* when enabled, drop packets if no descriptors are available */

    struct rte_eth_txconf tx_conf;
    memset(&tx_conf, 0, sizeof(tx_conf));
    tx_conf.tx_thresh.pthresh = 36;
    tx_conf.tx_thresh.hthresh = 4;
    tx_conf.tx_thresh.wthresh = 0;
    /* The following rs_thresh and flag value enables "simple TX" function. */
    tx_conf.tx_rs_thresh   = 32;
    tx_conf.tx_free_thresh = 0;  /* use PMD default value */
    tx_conf.txq_flags      = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS;

    const uint32_t num_mp_cache = 250;
    const uint32_t num_mbufs = num_rx_desc + num_tx_desc
                               + (num_cpus * num_mp_cache)
                               + batch_size + 1;
    const uint16_t mbuf_size = (RTE_PKTMBUF_HEADROOM + ETHER_MAX_LEN);

    struct rte_mempool* rx_mempools[PS_MAX_DEVICES][PS_MAX_QUEUES];
    struct rte_mempool* tx_mempools[PS_MAX_DEVICES][PS_MAX_QUEUES];
    memset(rx_mempools, 0, sizeof(struct rte_mempool*) * PS_MAX_DEVICES * PS_MAX_QUEUES);
    memset(tx_mempools, 0, sizeof(struct rte_mempool*) * PS_MAX_DEVICES * PS_MAX_QUEUES);

    for (int i = 0; i < num_devices_registered; i++) {
        struct rte_eth_link link_info;
        int port_idx = devices_registered[i];
        int ring_idx;
        int node_idx = devices[port_idx].pci_dev->numa_node;
        assert(0 == rte_eth_dev_configure(port_idx, num_rxq_per_port, num_txq_per_port, &port_conf));

        /* Initialize TX queues. */
        for (ring_idx = 0; ring_idx < num_txq_per_port; ring_idx++) {
            struct rte_mempool *mp = NULL;
            char mempool_name[RTE_MEMPOOL_NAMESIZE];
            snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE,
                     "txmp_n%u_d%u_r%u", node_idx, port_idx, ring_idx);
            mp = rte_pktmbuf_pool_create(mempool_name, num_mbufs, num_mp_cache, sizeof(struct Packet),
                                         mbuf_size, node_idx);
            if (mp == NULL)
                rte_exit(EXIT_FAILURE, "cannot allocate memory pool for txq %u:%u@%u.\n",
                         port_idx, ring_idx, node_idx);
            tx_mempools[port_idx][ring_idx] = mp;

            ret = rte_eth_tx_queue_setup(port_idx, ring_idx, num_tx_desc, node_idx, &tx_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d, qidx=%d\n",
                         ret, port_idx, ring_idx);
        }

        /* Initialize RX queues. */
        /* They are used only when latency measure is enabled,
         * but they must be initialized always. */
        for (int ring_idx = 0; ring_idx < num_rxq_per_port; ring_idx++) {
            struct rte_mempool *mp = NULL;
            char mempool_name[RTE_MEMPOOL_NAMESIZE];
            snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE,
                     "rxmp_n%u_d%u_r%u", node_idx, port_idx, ring_idx);

            mp = rte_pktmbuf_pool_create(mempool_name, num_mbufs, num_mp_cache, sizeof(struct Packet),
                                         mbuf_size, node_idx);
            if (mp == NULL)
                rte_exit(EXIT_FAILURE, "cannot allocate memory pool for rxq %u:%u@%u.\n",
                         port_idx, ring_idx, node_idx);
            ret = rte_eth_rx_queue_setup(port_idx, ring_idx, num_rx_desc,
                                         node_idx, &rx_conf, mp);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d, qidx=%d\n",
                         ret, port_idx, ring_idx);
            rx_mempools[port_idx][ring_idx] = mp;
        }

        assert(0 == rte_eth_dev_start(port_idx));
        rte_eth_promiscuous_enable(port_idx);
        rte_eth_link_get(port_idx, &link_info);
        RTE_LOG(INFO, MAIN, "port %u -- link running at %s %s, %s\n", port_idx,
                (link_info.link_speed == ETH_LINK_SPEED_10000) ? "10G" : "lower than 10G",
                (link_info.link_duplex == ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex",
                (link_info.link_status == 1) ? "UP" : "DOWN");

        struct rte_eth_fc_conf fc_conf;
        memset(&fc_conf, 0, sizeof(fc_conf));
        rte_eth_dev_flow_ctrl_get(port_idx, &fc_conf);
        RTE_LOG(INFO, MAIN, "port %u -- flow control mode: %d, autoneg: %d\n", port_idx,
                fc_conf.mode, fc_conf.autoneg);
    }

    /* Initialize contexts. */
    printf("Initializing thread contexts...\n");

    rte_timer_subsystem_init();
    memset(contexts, 0, sizeof(struct pspgen_context *) * PS_MAX_CPUS);

    int used_cores_per_node[PS_MAX_NODES];
    memset(used_cores_per_node, 0, sizeof(int) * PS_MAX_NODES);

    for (int my_cpu = 0; my_cpu < num_cpus; my_cpu++) {
        int node_id = numa_node_of_cpu(my_cpu);
        struct pspgen_context *ctx = rte_malloc_socket("pspgen_context", sizeof(struct pspgen_context),
                                                       RTE_CACHE_LINE_SIZE, node_id);
        assert(ctx != NULL);
        memset(ctx, 0, sizeof(struct pspgen_context));
        contexts[my_cpu] = ctx;

        ctx->num_cpus = num_cpus;
        ctx->my_node  = node_id;
        ctx->my_cpu   = my_cpu;
        ctx->tsc_hz   = rte_get_tsc_hz();

        ctx->num_txq_per_port = num_txq_per_port;
        ctx->ring_idx   = used_cores_per_node[node_id];
        ctx->num_attached_ports = 0;
        for (int i = 0; i < num_devices_registered; i++) {
            int port_idx = devices_registered[i];
            if (ps_in_samenode(ctx->my_cpu, port_idx)) {
                ctx->attached_ports[ctx->num_attached_ports ++] = port_idx;
                printf("  core %d (node %d) uses port:ring %d:%d\n", my_cpu, node_id, port_idx, ctx->ring_idx);
                ctx->tx_mempools[port_idx] = tx_mempools[port_idx][ctx->ring_idx];
            }
        }

        ctx->time_limit = time_limit;
        ctx->batch_size = batch_size;

        used_cores_per_node[node_id] ++;
    }

    /* Spawn threads and send packets. */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Running...\n");
    printf("----------\n");

    begin = ps_get_usec();
    rte_eal_mp_remote_launch(io_loop, NULL, CALL_MASTER);
    rte_eal_mp_wait_lcore();
    end = ps_get_usec();

    printf("----------\n");
    printf("%.2f seconds elapsed\n", (end - begin) / 1000000.0);
    return 0;
}

/* vim: set ts=8 sts=4 sw=4 et: */
