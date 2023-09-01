package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	macAddress := "a0:36:bc:ad:0b:1b" // Replace with the MAC address you want to compare

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
				fmt.Printf("MAC address %s is manufactured by %s\n", macAddress, strings.Join(manufacturer, " "))
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
	fmt.Printf("No manufacturer found for MAC address %s\n", macAddress)
}
