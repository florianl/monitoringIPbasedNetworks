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

	"github.com/florianl/go-tc"
	bpf "github.com/iovisor/gobpf/bcc"
	"golang.org/x/sys/unix"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
#define KBUILD_MODNAME "tc_eBPF"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
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

int tc_eBPF(struct __sk_buff *skb) {
	void* data_end = (void*)(long)skb->data_end;
	void* data = (void*)(long)skb->data;

	struct ethhdr *eth = data;

	uint64_t nh_off = 0;

    nh_off = sizeof(*eth);


	if (skb->protocol == htons(ETH_P_IP)) {
		v4Session_t session = {};
		bpf_trace_printk("IPv4\n");

		parse_ipv4(&session, skb->data, nh_off, skb->data_end);

		v4Report.perf_submit(skb, &session, sizeof(session));

    } else if (skb->protocol == htons(ETH_P_IPV6)) {
		v6Session_t session = {};
		bpf_trace_printk("IPv6\n");
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
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
		fmt.Printf("e.g.: %v eth0\n", os.Args[0])
		os.Exit(1)
	}

	module := bpf.NewModule(source, []string{"-w"})
	defer module.Close()

	fn, err := module.Load("tc_eBPF", unix.BPF_PROG_TYPE_SCHED_CLS, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load ebpf prog: %v\n", err)
		return
	}

	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	device, err := net.InterfaceByName(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get interface ID: %v\n", err)
		return
	}

	qdisc := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(device.Index),
			Handle:  tc.BuildHandle(0xFFFF, 0x0000),
			Parent:  0xFFFFFFF1,
			Info:    0,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}

	if err := rtnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", os.Args[1], err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer rtnl.Qdisc().Delete(&qdisc)

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(device.Index),
			Handle:  0,
			Parent:  tc.Ingress,
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",

			BPF: &tc.BPF{
				FD:    uint32(fn),
				Name:  "tc_prog",
				Flags: 0x1,
			},
		},
	}
	if err := rtnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}

	filter.Parent = tc.Egress
	if err := rtnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
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
