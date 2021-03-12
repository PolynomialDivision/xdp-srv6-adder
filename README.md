## XDP-SRv6-Adder

This package contains a userspace program and the corresponding kernel xdp program to do all XDP encapsulations for clients. This program is based on [ubpf](https://github.com/blogic/ubpf) and uses most of the userspace xdp code.

I have written everything again in inline because I had issues with the IPQ40xx SOC using outer encapsulation.

### Usage

Load xdp to the client interface

    xdpload -d br-lan -f /usr/xdp/srv6_add_kern.o -p srv6-adder-inline

Feed it with segment path

    xdp-srv6-adder -d br-lan -s 2000::1,2000::2,... -l [last segment]


Specify Prefixes the segment path should be applied to (you can specify up to CIDR_MAX prefixes):

    xdp-srv6-adder -d br-lan -p 2003::/64 -k 0