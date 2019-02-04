package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
*/
import "C"

const source string = `
#define KBUILD_MODNAME "xdp_reporter"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


typedef struct {
	u32 sIP;
	u32 dIP;
	u16 len;
	u8 proto;
} v4Session_t;

typedef struct {
	u32 sIP[4];
	u32 dIP[4];
	u16 len;
	u8 proto;
} v6Session_t;

BPF_PERF_OUTPUT(v4Report);
BPF_PERF_OUTPUT(v6Report);

static inline void parse_ipv4(v4Session_t *session, void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
		return;

	session->sIP = iph->saddr;
	session->dIP = iph->daddr;
	session->proto = iph->protocol;
	session->len = iph->tot_len;

	return;
}

static inline void parse_ipv6(v6Session_t *session, void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
		return;

	memcpy(&(session->sIP), &(ip6h->saddr), sizeof(struct in6_addr));
	memcpy(&(session->dIP), &(ip6h->daddr), sizeof(struct in6_addr));
	session->proto = ip6h->nexthdr;
	session->len = ip6h->payload_len;
	return;
}

int xdp_reporter(struct xdp_md *ctx) {

	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth = data;

    uint16_t h_proto;
    uint64_t nh_off = 0;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

	if (h_proto == htons(ETH_P_IP)) {
		v4Session_t session = {};
		parse_ipv4(&session, data, nh_off, data_end);
		v4Report.perf_submit(ctx, &session, sizeof(session));
    } else if (h_proto == htons(ETH_P_IPV6)) {
		v6Session_t session = {};
	    parse_ipv6(&session, data, nh_off, data_end);
		v6Report.perf_submit(ctx, &session, sizeof(session));
	}

	return XDP_PASS;
}
`

type v4Report struct {
	sIP      net.IP
	dIP      net.IP
	len      []byte
	protocol uint8
}

type v6Report struct {
	sIP      net.IP
	dIP      net.IP
	len      []byte
	protocol uint8
}

func main() {
	var device string

	if len(os.Args) != 2 {
		fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
		fmt.Printf("e.g.: %v eth0\n", os.Args[0])
		os.Exit(1)
	}

	device = os.Args[1]

	module := bpf.NewModule(source, []string{"-w"})
	defer module.Close()

	fn, err := module.Load("xdp_reporter", C.BPF_PROG_TYPE_XDP, 0, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	v4ReportTable := bpf.NewTable(module.TableId("v4Report"), module)
	v6ReportTable := bpf.NewTable(module.TableId("v6Report"), module)

	v4Chan := make(chan []byte)
	v6Chan := make(chan []byte)

	v4ReportMap, err := bpf.InitPerfMap(v4ReportTable, v4Chan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init v4 report map: %s\n", err)
		os.Exit(1)
	}

	v6ReportMap, err := bpf.InitPerfMap(v6ReportTable, v6Chan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init v6 report map: %s\n", err)
		os.Exit(1)
	}

	go func() {
		var session v4Report
		for {
			data := <-v4Chan
			session.sIP = data[:4]
			session.dIP = data[4:8]
			session.len = data[8:10]
			session.protocol = data[10]
			fmt.Printf("%s > %s %v %d\n", session.sIP, session.dIP, session.protocol, session.len)

		}
	}()

	go func() {
		var session v6Report
		for {
			data := <-v6Chan
			session.sIP = data[:16]
			session.dIP = data[16:32]
			session.len = data[32:34]
			session.protocol = data[34]
			fmt.Printf("%s > %s %v %d\n", session.sIP, session.dIP, session.protocol, session.len)
		}
	}()

	v6ReportMap.Start()
	v4ReportMap.Start()
	<-sig
	v4ReportMap.Stop()
	v6ReportMap.Stop()
}
