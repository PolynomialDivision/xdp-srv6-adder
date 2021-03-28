/* SPDX-License-Identifier: GPL-2.0 */

/* based on ubpf */

#include <arpa/inet.h>

#include "common.h"
#include "uxdp.h"

static struct cidr *cidr_parse6(const char *s) {
  /* copied from owipcalc.c */

  char *p = NULL, *r;
  struct cidr *addr = malloc(sizeof(struct cidr));

  if (!addr || (strlen(s) >= sizeof(addr->buf.v6)))
    goto err;

  snprintf(addr->buf.v6, sizeof(addr->buf.v6), "%s", s);

  if ((p = strchr(addr->buf.v6, '/')) != NULL) {
    *p++ = 0;

    addr->prefix = strtoul(p, &r, 10);

    if ((p == r) || (*r != 0) || (addr->prefix > 128))
      goto err;
  } else {
    addr->prefix = 128;
  }

  if (p == addr->buf.v6 + 1)
    memset(&addr->addr.v6, 0, sizeof(addr->addr.v6));
  else if (inet_pton(AF_INET6, addr->buf.v6, &addr->addr.v6) != 1)
    goto err;

  return addr;

err:
  if (addr)
    free(addr);

  return NULL;
}

static void update_prefix_map(char *net, int key, struct cidr *prefix, char *segpathstring, int segleft) {
  printf("Updating Prefix Map\n");

  struct xdp_map xdp_map = {
      .prog = "xdp_srv6_add",
      .map = "prefixmap",
      .map_want =
          {
              .key_size = sizeof(__u32),
              .value_size = sizeof(struct cidr),
              .max_entries = MAX_CIDR,
          },
      .net = net,
  };

  printf("Parsing Segpath!\n");
  int i;
  i = 0;
  char *seg = strtok(segpathstring, ",");
  while (seg != NULL && i < MAX_SEG_LIST) {
    memcpy(prefix->segpath[MAX_SEG_LIST-1-i].s6_addr,cidr_parse6(seg)->addr.v6.s6_addr,16); // we reverse route so it is iproute2 behavior
    seg = strtok(NULL, ",");
    i++;
  }
  prefix->numsegs = i;
  printf("Numsegs: %d\n",prefix->numsegs);

  printf("Segpath Parsing Finished!\n");

  prefix->segleft = segleft;

  printf("Updating on device: %s\n", net);
  if (!xdp_map.net) {
    fprintf(stderr, "invalid arguments\n");
    return;
  }

  if (map_lookup(&xdp_map)) {
    fprintf(stderr, "failed to xdp_map map\n");
    return;
  }

  if (bpf_map_update_elem(xdp_map.map_fd, &key, prefix, 0) < 0) {
    fprintf(stderr, "WARN: Failed to update bpf map file: err(%d):%s\n", errno,
            strerror(errno));
    return;
  }
}

int main(int argc, char **argv) {
  struct cidr *prefix = NULL;
  char *net = NULL;
  char *segpath = NULL;

  int ch;
  int key = -1;
  int segleft = 0;
  while ((ch = getopt(argc, argv, "d:f:p:k:s:l:")) != -1) {
    switch (ch) {
    case 'd':
      net = optarg;
      break;
    case 'p':
      // parse prefix
      prefix = cidr_parse6(optarg);
      break;
    case 'k':
      key = atoi(optarg);
      break;
    case 's':
      // parse segmentpath
      segpath = optarg;
      break;
    case 'l':
      // parse segment left
      segleft = atoi(optarg);
      printf("Segleft: %d\n", segleft);
      break;
    default:
      fprintf(stderr, "Invalid argument\n");
      exit(-1);
    }
  }

  if(!segpath)
  {
    return 1;
  }
  if(!net)
  {
    return 1;
  }

  update_prefix_map(net, key, prefix, segpath, segleft);

  return 0;
}
