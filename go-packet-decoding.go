package main

import (
   "fmt"
   "log"
   "os"
   "bufio"
   "strings"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "github.com/google/gopacket/layers"
)

func main() {
	// Open manufacturer OUI file


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
		  fmt.Println("--------------------------------------------------------------------------------")
		  ip, _ := ipLayer.(*layers.IPv4)
		// Examples of data available
		  fmt.Println("IP Header length in 32-bit word:", ip.IHL)
		  fmt.Println("IP TOS:", ip.TOS)
		  fmt.Println("IP Length:", ip.Length)
		  fmt.Println("IP Id:", ip.Id)
		  fmt.Println("IP Flags:", ip.Flags)
		  fmt.Println("IP FragOffset:", ip.FragOffset)
		  fmt.Println("IP TTL:", ip.TTL)
		  fmt.Println("IP Protocol:", ip.Protocol)
		  fmt.Println("IP Checksum:", ip.Checksum)
		// Ip Addresses
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
	  // Add decoding for other layers here...
   }
}
