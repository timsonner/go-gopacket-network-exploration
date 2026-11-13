# go-gopacket-network-exploration

Small standalone Go programs that use [gopacket](https://github.com/google/gopacket) and libpcap to capture packets, decode IPv4 and Ethernet headers, write one raw buffer, scan a local IPv4 subnet with ARP, and look up a MAC vendor prefix. Each `.go` file is its own `package main`. The module path in `go.mod` is `foo`.

There is no shared CLI. Interface names, the example MAC address, and the packet bytes are constants in the source.

## Prerequisites

- Go 1.20 or later, as declared in `go.mod`.
- A C compiler. The pcap programs import `github.com/google/gopacket/pcap`, which is cgo and includes `pcap.h`.
- libpcap headers. On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

- Permission to open a live capture on an interface named `eth0`. `go-packet-capture.go`, `go-packet-decoding.go`, `go-packet-injection.go`, and `go-arp-request.go` pass that name to `pcap.OpenLive` or `net.InterfaceByName`. The name is not a flag.
- For `go-find-mac-manufacturer.go` and the vendor lookup inside `go-packet-decoding.go`: a Wireshark manuf file at `/usr/share/wireshark/manuf`. Both programs open that path and nothing else.

`go-arp-request.go` also requires `eth0` to have an IPv4 address. It skips an address whose first octet is `127`, and it returns an error when the mask does not start with `255.255` (the scan refuses a network it treats as too large).

## Install, build, run, test

Download modules:

```bash
go mod download
```

Build one file at a time. `go build .` does not work in this directory, because every file declares `main`.

```bash
go build -o go-find-mac-manufacturer go-find-mac-manufacturer.go
go build -o go-packet-capture go-packet-capture.go
go build -o go-packet-decoding go-packet-decoding.go
go build -o go-packet-injection go-packet-injection.go
go build -o go-arp-request go-arp-request.go
```

Run one file at a time:

```bash
go run go-find-mac-manufacturer.go
go run go-packet-capture.go
go run go-packet-decoding.go
go run go-packet-injection.go
go run go-arp-request.go
```

The three capture and injection programs call `log.Fatal` if `pcap.OpenLive` fails. The ARP program logs the error and exits. The manufacturer program prints the open error and exits 0.

There are no `*_test.go` files. `go test ./...` fails at compile time with `main redeclared`, for the same reason `go build .` fails.

Built binaries match the `*.exe` patterns ignored by `.gitignore` only for Windows-style names. The `-o` names above are local build outputs.

## Usage

### MAC manufacturer lookup

`go-find-mac-manufacturer.go` looks up the constant MAC `a0:36:bc:ad:0b:1b`. It uppercases the first three octets (`A0:36:BC`), scans `/usr/share/wireshark/manuf` for a line with that prefix, and prints the fields after the second column as the manufacturer. If the prefix is shorter than three colon-separated parts it prints `Invalid MAC address`. If the file has no match it prints `No manufacturer found for MAC address`.

Change the `macAddress` constant to look up a different address.

### Packet capture

`go-packet-capture.go` opens `eth0` with a snapshot length of 1600, promiscuous mode on, and `pcap.BlockForever`. It prints every packet from that handle until the process is stopped.

### Packet decoding

`go-packet-decoding.go` opens `eth0` with the same snapshot length, promiscuous mode, and timeout as the capture program. For each packet:

- When an IPv4 layer is present, it prints `Source IP` and `Destination IP`.
- Otherwise it prints `[+] Ethernet layer detected.`
- When an Ethernet layer is present, it prints the source and destination MAC addresses and calls `FindManufacturer` on each.

`FindManufacturer` uses the same manuf file and three-octet prefix as the standalone lookup. If that file cannot be opened, it prints the error and returns before the extra prefix checks. If the file opens and the prefix is not listed, it prints one of these labels for the prefixes below, or `No manufacturer found for MAC address`:

| Prefix | Printed label |
| --- | --- |
| `33:33:00` | `**IPv6 Multicast**` |
| `01:00:5E` | `**IPv4 Multicast**` |
| `FF:FF:FF` | `**Ethernet Broadcast**` |
| `01:00:0C` | `**Cisco Multicast Address used by STP to send BPDUs**` |
| `01:80:C2` | `**Cisco Multicast Address used by STP to send BPDUs**` |
| `CF:00:00` | `**Multicast Reserved by IANA for Point-to-Point Protocol (PPP) or when vendors don't need an IEEE-assigned OUI**` |

### Packet injection

`go-packet-injection.go` opens `eth0` with the same live-capture settings as the capture program and writes one buffer, `[]byte{0x01, 0x02, 0x03, 0x04}`, with `WritePacketData`. It then closes the handle and exits.

### ARP scan

`go-arp-request.go` reads the first IPv4 address on `eth0`, opens that interface with snapshot length 65536, promiscuous mode on, and `pcap.BlockForever`, and then loops:

1. A reader prints ARP replies whose source hardware address is not this interface, as `IP <addr> is at <mac>`.
2. A writer sends an ARP request for every host address in the local subnet (network and broadcast addresses are not included). Ethernet destination is the broadcast MAC `ff:ff:ff:ff:ff:ff`.
3. The writer sleeps 10 seconds and sends the sweep again.

Stop the process to end the loop. On a mask that does not start with `255.255`, a missing IPv4 address, or an address in `127.0.0.0/8`, it returns an error and does not send packets.

## Layout

```
.
├── go.mod
├── go.sum
├── go-arp-request.go
├── go-find-mac-manufacturer.go
├── go-packet-capture.go
├── go-packet-decoding.go
├── go-packet-injection.go
├── .gitattributes
└── .gitignore
```

Direct module requirements are `github.com/google/gopacket v1.1.19`. Other modules in `go.sum` are indirect.

## License

This repository has no license file.
