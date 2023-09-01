package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	macAddress := "A0:36:BC" // Replace with the MAC address you want to compare

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
		if strings.HasPrefix(line, macAddress) {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) > 1 {
				fmt.Printf("MAC address %s is manufactured by %s\n", macAddress, parts[1])
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
	}
	fmt.Printf("No manufacturer found for MAC address %s\n", macAddress)
}
