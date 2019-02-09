package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var handle *pcap.Handle
	var err error

	var device string

	if len(os.Args) != 2 {
		fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
		fmt.Printf("e.g.: %v eth0\n", os.Args[0])
		os.Exit(1)
	}

	device = os.Args[1]

	// Prepare decoders for expected layers
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6)
	decoded := []gopacket.LayerType{}
	// Attach the capture to the given interface
	handle, err = pcap.OpenLive(device, 512, true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s for capturing: %v\n", device, err)
		os.Exit(1)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packetData := range packetSource.Packets() {
		// Try to decode each received packet and extract its information
		parser.DecodeLayers(packetData.Data(), &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Printf("%s > %s %v %d\n", ip6.SrcIP, ip6.DstIP, ip6.NextHeader, ip6.Length)
			case layers.LayerTypeIPv4:
				fmt.Printf("%s > %s %v %d\n", ip4.SrcIP, ip4.DstIP, ip4.Protocol, ip4.Length)
			}
		}
	}
}
