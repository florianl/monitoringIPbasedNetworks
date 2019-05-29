// Copyright 2019 Florian Lehner <dev@der-flo.net>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
*/
import "C"

const source string = `
#define KBUILD_MODNAME "tracepoint_reporter"
#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tracepoint.h>

#define MAC_HEADER_SIZE 14;

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

int tracepoint_reporter(struct tracepoint__net__net_dev_start_xmit *ctx) {

	struct sk_buff* skb = NULL;
	skb = ctx->skbaddr;
	char *head;
	u16 mac;

	bpf_probe_read((void*)&head, sizeof(skb->head), (void*)&skb->head);
	bpf_probe_read((void*)&mac, sizeof(skb->mac_header), (void*)&skb->mac_header);
	
	if (ctx->protocol == ETH_P_IP) {
		v4Session_t session = {};
		struct iphdr *iph = head + mac + MAC_HEADER_SIZE;

		bpf_probe_read((void*)&session.sIP, sizeof(iph->saddr), (void*)&iph->saddr);
		bpf_probe_read((void*)&session.dIP, sizeof(iph->daddr), (void*)&iph->daddr);
		bpf_probe_read((void*)&session.proto, sizeof(iph->protocol), (void*)&iph->protocol);
		bpf_probe_read((void*)&session.len, sizeof(iph->tot_len), (void*)&iph->tot_len);

		v4Report.perf_submit(ctx, &session, sizeof(session));
    } else if (ctx->protocol == ETH_P_IPV6) {
		v6Session_t session = {};
    	struct ipv6hdr *ip6h = head + mac + MAC_HEADER_SIZE;

		bpf_probe_read((void*)&session.sIP, sizeof(struct in6_addr), (void*)&ip6h->saddr);
		bpf_probe_read((void*)&session.dIP, sizeof(struct in6_addr), (void*)&ip6h->daddr);
		bpf_probe_read((void*)&session.proto, sizeof(ip6h->nexthdr), (void*)&ip6h->nexthdr);
		bpf_probe_read((void*)&session.len, sizeof(ip6h->payload_len), (void*)&ip6h->payload_len);

		v6Report.perf_submit(ctx, &session, sizeof(session));
	}

	return 0;
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
	// Translate the C code to eBPF instructions
	module := bpf.NewModule(source, []string{"-w"})
	defer module.Close()

	tracepoint, err := module.LoadTracepoint("tracepoint_reporter")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load tracepoint: %v\n", err)
		os.Exit(1)
	}

	// Attach the program to the tracepoint
	err = module.AttachTracepoint("net:net_dev_start_xmit", tracepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach tracepoint: %v\n", err)
		os.Exit(1)
	}

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
