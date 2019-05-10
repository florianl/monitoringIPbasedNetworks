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
	"context"
	"fmt"
	"net"
	"time"

	ct "github.com/florianl/go-conntrack"
)

func main() {
	// Opens the socket for the communication with the subsystem
	nfct, err := ct.Open(&ct.Config{ReadTimeout: 10 * time.Millisecond})
	if err != nil {
		fmt.Println("Could not open socket:", err)
		return
	}
	defer nfct.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hook := func(c ct.Conn) int {
		var err error
		var proto uint8
		var srcIP, dstIP net.IP

		srcIP, err = c.OrigSrcIP()
		if err != nil {
			return 0
		}
		dstIP, err = c.OrigDstIP()
		if err != nil {
			return 0
		}
		proto, err = c.Uint8(ct.AttrOrigL4Proto)
		if err != nil {
			return 0
		}
		fmt.Printf("%s > %s %d\n", srcIP, dstIP, proto)

		// returning something else other than 0, will stop the hook to be called
		return 0
	}

	if err := nfct.Register(ctx, ct.Ct, ct.NetlinkCtNew|ct.NetlinkCtUpdate|ct.NetlinkCtDestroy, hook); err != nil {
		fmt.Println("Could not register hook:", err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
