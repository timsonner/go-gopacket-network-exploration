package main

   import (
      "fmt"
      "log"
	  "github.com/google/gopacket"
      "github.com/google/gopacket/pcap"
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
         fmt.Println(packet)
      }
   }
