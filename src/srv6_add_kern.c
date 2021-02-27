/* SPDX-License-Identifier: GPL-2.0 */

#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

#define ipv6_optlen(p) (((p)->hdrlen + 1) << 3)
#define ipv6_lentest(p) (((p * 2) + 1) << 3)

#define IPV6_ENCAP 41 // [RFC2473]
#define IPV6_EXT_ROUTING 43

struct ip6_addr_t {
  unsigned long long hi;
  unsigned long long lo;
};

struct ip6_srh_t {
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned char type;
  unsigned char segments_left;
  unsigned char first_segment;
  unsigned char flags;
  unsigned short tag;

  struct ip6_addr_t segments[0];
};

struct bpf_map_def SEC("maps") prefixmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct cidr),
    .max_entries = MAX_CIDR,
};

struct bpf_map_def SEC("maps") segpathmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct cidr),
    .max_entries = MAX_SEG_LIST,
};

struct bpf_map_def SEC("maps") segleftmap = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("srv6-adder")
int xdp_srv6_add(struct xdp_md *ctx) {
  volatile struct ethhdr old_ehdr;
  volatile struct ipv6hdr oldr_ipv6_orig_hdr;
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *ehdr = data;
  if (ehdr + 1 > data_end) // bounds checking
    goto out;
  old_ehdr = *ehdr;

  if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
    goto out;
  }

  // ----- Copy Orig IPv6 Header -------
  struct ipv6hdr *ipv6_orig_header = (void *)(ehdr + 1);
  if (ipv6_orig_header + 1 > data_end)
    goto out;
  oldr_ipv6_orig_hdr = *ipv6_orig_header;
  // ------------------------------------

	// -------- checking --------

	int inprefix=0;
	int j;
	for (j = 0; j <= MAX_CIDR; j++){
		__u32 key = (__u32)j;
		struct cidr *cidr = bpf_map_lookup_elem(&prefixmap, &key);
		if (!cidr)
			goto loop;
		int prefix_limit = 15 - ((128 - cidr->prefix) / 8);
		int i;
		for (i = 0; i < 16; i++)
		{
			__u8 net1 = ipv6_orig_header->daddr.s6_addr[i];
			__u8 net2 = cidr->addr.v6.s6_addr[i];

			if (i >= prefix_limit)
				break;

			if (net1 != net2)
			{
				goto loop;
			}
		}
		if (i >= 16)
			goto loop;

		__u8 net1 = ipv6_orig_header->daddr.s6_addr[i];
		__u8 net2 = cidr->addr.v6.s6_addr[i];
		__u8 mask = ~((1 << ((128 - cidr->prefix) % 8)) - 1);

		net1 &= mask;
		net2 &= mask;

		if (net1 != net2)
		{
			goto loop;
		}

		// if we reach here, some prefix is announced
		inprefix=1;
		break;
loop:
		continue;
	}

	if (!inprefix)
		goto out;


  // ---------------

  int offset = sizeof(struct ipv6hdr) + ipv6_lentest(MAX_SEG_LIST);
  if (bpf_xdp_adjust_head(ctx, -offset)) {
    goto out;
  }

  // ------------ Copy Eth-Addr ---------------
  data_end = (void *)(long)ctx->data_end;
  ehdr = (void *)(long)ctx->data;

  if (ehdr + 1 > data_end)
    goto out;

  *ehdr = old_ehdr;

  // ------------------------------------------

  // -------------- Copy Header Back as encap header -----
  struct ipv6hdr *ip6_srv6_encap = (void *)(ehdr + 1);
  if (ip6_srv6_encap + 1 > data_end)
    goto out;
  *ip6_srv6_encap = oldr_ipv6_orig_hdr;
  ip6_srv6_encap->nexthdr = IPV6_EXT_ROUTING;
  ip6_srv6_encap->daddr.s6_addr[0] = 0x20;
  ip6_srv6_encap->daddr.s6_addr[1] = 0x01;
  int i;
  for (i = 2; i < 15; i++)
    ip6_srv6_encap->daddr.s6_addr[i] = 0x0;
  ip6_srv6_encap->daddr.s6_addr[2] = 0x0;
  ip6_srv6_encap->daddr.s6_addr[15] = 0x02;

  ip6_srv6_encap->payload_len += bpf_ntohs(offset);
  // ------------------------------------------

  // ------ Create Srv6 Header ------------------
  unsigned long long hi = 0x2001000000000000;

  struct ip6_addr_t *seg;
  struct ip6_srh_t *srh;

  __u32 keysegleft = 0;
  int* segleft = bpf_map_lookup_elem(&segleftmap, &keysegleft);
  if (!segleft)
    goto out;

  srh = (struct ip6_srh_t *)(void *)(ip6_srv6_encap + 1);
  if (srh + 1 > data_end)
    goto out;
  srh->nexthdr = 41;
  srh->hdrlen = 2 * MAX_SEG_LIST;
  srh->type = 4;
  srh->segments_left = *segleft;
  srh->first_segment = MAX_SEG_LIST - 1;
  srh->flags = 0;
  srh->tag = 0;

  seg = (struct ip6_addr_t *)((char *)srh + sizeof(*srh));
  // seg = (struct in6_addr *)((char *)srh + sizeof(*srh));

  if (seg + MAX_SEG_LIST > data_end)
    goto out;

#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_SEG_LIST; i++) {
    __u32 key = (__u32)i;
    struct cidr *cidr = bpf_map_lookup_elem(&segpathmap, &key);
    if (!cidr)
      goto out;

	__builtin_memcpy(seg,cidr->addr.v6.s6_addr, 16);

    seg = (struct in6_addr *)((char *)seg + sizeof(*seg));
	
  }
  // ------------------------------------------
out:
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
