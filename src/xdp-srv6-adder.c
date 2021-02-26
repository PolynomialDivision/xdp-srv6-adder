/* SPDX-License-Identifier: GPL-2.0 */

#include <arpa/inet.h>

#include "common.h"
#include "uxdp.h"

static bool cidr_print6(struct cidr *a) {
  char *p;

  if (!a)
    return NULL;

  if (!(p = (char *)inet_ntop(AF_INET6, &a->addr.v6, a->buf.v6,
                              sizeof(a->buf.v6))))
    return false;

  printf("%s", p);

  if (a->prefix < 128)
    printf("/%u", a->prefix);

  return true;
}

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

int main(int argc, char **argv) {
  struct cidr *prefix = NULL;

  struct xdp_map xdp_map = {
      .prog = "xdp_srv6_add",
      .map = "prefix_map",
      .map_want =
          {
              .key_size = sizeof(__u32),
              .value_size = sizeof(struct cidr),
              .max_entries = 3,
          },
  };
  int ch;
  int key;
  while ((ch = getopt(argc, argv, "d:f:p:k:")) != -1) {
    switch (ch) {
    case 'd':
      xdp_map.net = optarg;
      break;
    case 'p':
      // parse prefix
      prefix = cidr_parse6(optarg);
      break;
    case 'k':
      // parse prefix
      key = atoi(optarg);
      break;
    default:
      fprintf(stderr, "Invalid argument\n");
      exit(-1);
    }
  }
  if (!xdp_map.net) {
    fprintf(stderr, "invalid arguments\n");
    return -1;
  }

  if (map_lookup(&xdp_map)) {
    fprintf(stderr, "failed to xdp_map map\n");
    return -1;
  }

  printf("Updating Map with: ");
  cidr_print6(prefix);

  //int key = 0;
  if (bpf_map_update_elem(xdp_map.map_fd, &key, prefix, 0) < 0) {
    fprintf(stderr, "WARN: Failed to update bpf map file: err(%d):%s\n", errno,
            strerror(errno));
    return -1;
  }

  return 0;
}
