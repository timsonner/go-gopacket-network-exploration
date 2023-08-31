package main

import (
   "fmt"
   "log"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "github.com/google/gopacket/layers"
)

func main() {
   // Open device for capturing packets
   handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
   if err != nil {
	  log.Fatal(err)
   }
   defer handle.Close()

   // Capture packets
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
	  // Decode each packet

	  ipLayer := packet.Layer(layers.LayerTypeIPv4)
	  if ipLayer != nil {
		  fmt.Println("[+] IPv4 layer detected.")
		  ip, _ := ipLayer.(*layers.IPv4)
  
		  // IP layer variables:
		  // Version (Either 4 or 6)
		  // IHL (IP Header Length in 32-bit words)
		  // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),

		  // Checksum, SrcIP, DstIP
		  fmt.Println("--------------------------------------------------------------------------------")
		  fmt.Println("Source IP:", ip.SrcIP)
		  fmt.Println("Destination IP:", ip.DstIP)
	  } else {
		fmt.Println("[+] Ethernet layer detected.")
		fmt.Println("--------------------------------------------------------------------------------")

	  }

	  ethLayer := packet.Layer(layers.LayerTypeEthernet)
	  if ethLayer != nil {
		 ethPacket, _ := ethLayer.(*layers.Ethernet)
		 fmt.Println("Source MAC:", ethPacket.SrcMAC)
		 fmt.Println("Destination MAC:", ethPacket.DstMAC)
		 fmt.Println("--------------------------------------------------------------------------------")

	  }
	  // Add decoding for other layers if required
   }
}
