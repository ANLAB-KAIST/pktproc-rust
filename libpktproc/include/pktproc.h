#ifndef __LIBPKTPROC_H__
#define  __LIBPKTPROC_H__

#include <stdint.h>

#ifdef __cplusplus__
extern "C" {
#endif

struct Packet {
    int32_t result;  // forwarding port idx (>= 0) or drop (-1)
};

extern void pktproc_init(uint64_t thread_id, void *port_infos, uint32_t port_count);
extern void pktproc_process(uint64_t thread_id, void **pkts, uint32_t pkt_count);

#ifdef __cplusplus__
}
#endif

#endif
