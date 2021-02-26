/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

#define IPV6_ENCAP 41           // [RFC2473]
#define IPV6_EXT_ROUTING 43

#define ipv6_optlen(p)  (((p).hdrlen+1) << 3)
#define ipv6_lentest(p)  (((p)+1) << 3)

SEC("srv6-adder")
int xdp_router_func(struct xdp_md *ctx)
{
	volatile struct ethhdr old_ehdr;
	volatile struct ipv6hdr oldr_ipv6_orig_hdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *ehdr = data;
	if (ehdr + 1 > data_end) // bounds checking
		goto out;
	old_ehdr = *ehdr;

	if (bpf_ntohs(ehdr->h_proto) != ETH_P_IPV6) {
		goto out;
	}

	// ----- Copy Orig IPv6 Header -------
	struct ipv6hdr* ipv6_orig_header = (void *)(ehdr + 1);
	if (ipv6_orig_header + 1 > data_end)
		goto out;
	oldr_ipv6_orig_hdr = *ipv6_orig_header;
	// ------------------------------------

	// ------ Create Routing Header ---------

	// ToDo:

	// ------------------------------------
	
	int offset = 64; //sizeof(struct ipv6hdr) +  ipv6_lentest(2);
	if (bpf_xdp_adjust_head(ctx, -offset))
	{
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

	ip6_srv6_encap->payload_len += bpf_ntohs(64);
	//ip6_srv6_encap->payload_len = bpf_ntohs(128); // ToDo: Check this!
	// ------------------------------------------

	// ------ Create Srv6 Header ------------------
	unsigned long long hi = 0xfd00000000000000;
	struct ip6_addr_t *seg;
	struct ip6_srh_t *srh;
	//char srh_buf[72]; // room for 4 segments

	srh = (struct ip6_srh_t *)(void *)(ip6_srv6_encap + 1);
	if (srh + 1 > data_end)
		goto out;
	srh->nexthdr = 41;
	srh->hdrlen = 2;
	srh->type = 4;
	srh->segments_left = 0;
	srh->first_segment = 0;
	srh->flags = 0;
	srh->tag = 0;

	seg = (struct ip6_addr_t *)((char *)srh + sizeof(*srh));

	if (seg + 1 > data_end)
		goto out;

	#pragma clang loop unroll(full)
	for (unsigned long long lo = 0; lo < 1; lo++) {
		seg->lo = bpf_cpu_to_be64(4 - lo);
		seg->hi = bpf_cpu_to_be64(hi);
		seg = (struct ip6_addr_t *)((char *)seg + sizeof(*seg));
	}

	
	struct ipv6hdr* iptest = (void *)(seg + 1);
	if (iptest + 1 > data_end)
		goto out;
	//iptest->payload_len = bpf_ntohs(64);
	//*iptest = oldr_ipv6_orig_hdr;

	// ------------------------------------------
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
