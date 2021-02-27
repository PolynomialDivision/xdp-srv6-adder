#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in.h>

#include <linux/bpf.h>

#include <inttypes.h>
#include <stdbool.h>

#define MAX_SEG_LIST 2
#define MAX_CIDR 1

struct cidr {
	uint32_t prefix;
	union {
		struct in6_addr v6;
	} addr;
	union {
		char v6[sizeof("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255/128 ")];
	} buf;
};
