package main

import (
	"context"
	"fmt"

	nflog "github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	// Send all incoming traffic to nflog group 100
	// # sudo iptables -I INPUT -j NFLOG --nflog-group 100

	//Set configuration parameters
	config := nflog.Config{
		Group:    100,
		Copymode: nflog.NfUlnlCopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		fmt.Println("Could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var ip4 layers.IPv4
	var ip6 layers.IPv6
	decoded := []gopacket.LayerType{}
	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	parserIPv6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6)
	parserIPv4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4)

	fn := func(m nflog.Msg) int {
		data := (m[nflog.AttrPayload]).([]byte)
		version := data[0] >> 4
		if version == 6 {
			packet := gopacket.NewPacket(data, layers.LayerTypeIPv6, decodeOptions)
			parserIPv6.DecodeLayers(packet.Data(), &decoded)
		} else if version == 4 {
			packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, decodeOptions)
			parserIPv4.DecodeLayers(packet.Data(), &decoded)
		} else {
			fmt.Println("Could not decode IP packet")
			return 0
		}
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Printf("%s > %s %v %d\n", ip6.SrcIP, ip6.DstIP, ip6.NextHeader, ip6.Length)
			case layers.LayerTypeIPv4:
				fmt.Printf("%s > %s %v %d\n", ip4.SrcIP, ip4.DstIP, ip4.Protocol, ip4.Length)
			}
		}
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
