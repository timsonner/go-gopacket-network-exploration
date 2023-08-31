package main

import (
   "log"
   "github.com/google/gopacket/pcap"
)

func main() {
   // Open device for packet injection
   handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
   if err != nil {
	  log.Fatal(err)
   }
   defer handle.Close()

   // Create a raw packet to inject
   rawBytes := []byte{0x01, 0x02, 0x03, 0x04} // Example raw packet

   // Inject the packet
   err = handle.WritePacketData(rawBytes)
   if err != nil {
	  log.Fatal(err)
   }
}
