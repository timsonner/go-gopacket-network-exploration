package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"
)

func FindManufacturer(macAddress string) {
	// Extract the first 3 octets and capitalize them
	parts := strings.Split(macAddress, ":")
	if len(parts) < 3 {
		fmt.Println("Invalid MAC address")
		return
	}
	capitalizedPrefix := strings.ToUpper(strings.Join(parts[:3], ":"))

	filePath := "/usr/share/wireshark/manuf"
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, capitalizedPrefix) {
			manufacturer := strings.Fields(line)[2:]
			if len(manufacturer) > 0 {
				fmt.Println("MAC Address OUI:", strings.Join(manufacturer, " "))
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}

switch capitalizedPrefix {
case "33:33:00":
	fmt.Println("**IPv6 Multicast**")
case "01:00:5E":
	fmt.Println("**IPv4 Multicast**")
case "FF:FF:FF":
	fmt.Println("**Ethernet Broadcast**")
case "01:00:0C":
	fmt.Println("**Cisco Multicast Address used by STP to send BPDUs**")
case "01:80:C2":
	fmt.Println("**Cisco Multicast Address used by STP to send BPDUs**")	
case "CF:00:00":
	fmt.Println("**Multicast Reserved by IANA for Point-to-Point Protocol (PPP) or when vendors don't need an IEEE-assigned OUI**")
default:
	fmt.Printf("No manufacturer found for MAC address %s\n", macAddress)
}
}

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
			// fmt.Println("IP Header length in 32-bit word:", ip.IHL)
			// fmt.Println("IP TOS:", ip.TOS)
			// fmt.Println("IP Length:", ip.Length)
			// fmt.Println("IP Id:", ip.Id)
			// fmt.Println("IP Flags:", ip.Flags)
			// fmt.Println("IP FragOffset:", ip.FragOffset)
			// fmt.Println("IP TTL:", ip.TTL)
			// fmt.Println("IP Protocol:", ip.Protocol)
			// fmt.Println("IP Checksum:", ip.Checksum)
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
			FindManufacturer(ethPacket.SrcMAC.String())
			fmt.Println("Destination MAC:", ethPacket.DstMAC)
			FindManufacturer(ethPacket.DstMAC.String())
			fmt.Println("--------------------------------------------------------------------------------")

		}
		// Add decoding for other layers here...
	}
}
