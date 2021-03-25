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

static void update_prefix_map(char *net, int key, struct cidr *prefix) {
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

static void update_segpath_map(char *net, char *segpathstring, int segleft) {
  printf("Updating Segpath\n");

  char *seg;
  struct cidr seglist[MAX_SEG_LIST];

  struct xdp_map xdp_map = {
      .prog = "xdp_srv6_add",
      .map = "segpathmap",
      .map_want =
          {
              .key_size = sizeof(__u32),
              .value_size = sizeof(struct cidr),
              .max_entries = MAX_SEG_LIST,
          },
      .net = net,
  };

  printf("Updating on device: %s\n", net);

  int i;
  i = 0;
  seg = strtok(segpathstring, ",");
  while (seg != NULL && i < MAX_SEG_LIST) {
    seglist[MAX_SEG_LIST-1-i] = *cidr_parse6(seg); // we reverse route so it is iproute2 behavior
    seg = strtok(NULL, ",");
    i++;
  }

  if (!xdp_map.net) {
    fprintf(stderr, "invalid arguments\n");
    return;
  }

  if (map_lookup(&xdp_map)) {
    fprintf(stderr, "failed to xdp_map map\n");
    return;
  }

  for (int j = 0; j < MAX_SEG_LIST; j++) {
    if (bpf_map_update_elem(xdp_map.map_fd, &j, &seglist[j], 0) < 0) {
      fprintf(stderr, "WARN: Failed to update bpf map file: err(%d):%s\n",
              errno, strerror(errno));
      return;
    }
  }

  struct xdp_map xdp_map_segleft = {
      .prog = "xdp_srv6_add_inline",
      .map = "segleftmap",
      .map_want =
          {
              .key_size = sizeof(__u32),
              .value_size = sizeof(__u32),
              .max_entries = 1,
          },
      .net = net,
  };

  if (!xdp_map_segleft.net) {
    fprintf(stderr, "invalid arguments\n");
    return;
  }

  if (map_lookup(&xdp_map_segleft)) {
    fprintf(stderr, "failed to xdp_map map\n");
    return;
  }

  int segleftkey = 0;
  if (bpf_map_update_elem(xdp_map_segleft.map_fd, &segleftkey, &segleft, 0) <
      0) {
    fprintf(stderr, "WARN: Failed to update bpf map file: err(%d):%s\n", errno,
            strerror(errno));
    return;
  }
}

int main(int argc, char **argv) {
  struct cidr *prefix = NULL;
  char *net;
  char *segpath;

  int ch;
  int key = -1;
  bool do_update_prefix_map = false;
  bool do_update_segpath_map = false;
  int segleft = 0;
  while ((ch = getopt(argc, argv, "d:f:p:k:s:l:")) != -1) {
    switch (ch) {
    case 'd':
      net = optarg;
      break;
    case 'p':
      // parse prefix
      prefix = cidr_parse6(optarg);
      do_update_prefix_map = true;
      break;
    case 'k':
      key = atoi(optarg);
      break;
    case 's':
      // parse segmentpath
      segpath = optarg;
      do_update_segpath_map = true;
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

  if (do_update_prefix_map)
    update_prefix_map(net, key, prefix);

  if (do_update_segpath_map)
    update_segpath_map(net, segpath, segleft);

  return 0;
}
