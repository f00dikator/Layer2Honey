package main

import (
	"container/list"
	"encoding/binary"
	"github.com/spf13/viper"
	"os"
	"strconv"
	"time"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"regexp"
	//"sync"
)

// TODO put interface, myIP, myMAC, and GatewayMac into a config file
var MacList = list.New()
var InterfaceToMac = make(map[string]string)
var MacToInterface = make(map[string]string)
var IPToMac = make(map[string][]byte)
var HabitualOffenders = make(map[string]string)

type conf struct {
	Interface string
	gatewaymac string
	interfacemac string
	interfaceip string
}
var config conf

func populate_config (c *conf, config_file_name string) {
	viper.SetConfigFile(config_file_name)
	viper.SetConfigType("yaml")
	viper.Set("Verbose", true)
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error. Could not read in the config file %v: %v \n", config_file_name, err))
	}

	c.Interface = viper.GetString("l2.interface")
	if c.Interface == "" {
		fmt.Printf("No interface defined. Setting to default of en0\n")
		c.Interface = "en0"
	}
	c.gatewaymac = viper.GetString("l2.gatewaymac")
	if c.gatewaymac == "" {
		fmt.Printf("No gateway mac defined. Exiting")
		os.Exit(0)
	}
	c.interfacemac = viper.GetString("l2.interfacemac")
	if c.interfacemac == "" {
		fmt.Printf("No interface mac defined. Exiting.")
		os.Exit(0)
	}
	c.interfaceip = viper.GetString("l2.interfaceip")
	if c.interfaceip == "" {
		fmt.Printf("No interface IP defined. Exiting")
		os.Exit(0)
	}
}



func LemmeSlideIntoYourCache (SniffInterface string) {
	var addr *net.IPNet

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("\nFailed to retrieve net Interfaces\n")
		panic(err)
	}
	writeHandle, err := pcap.OpenLive(SniffInterface, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("\nError opening write handle\n")
		os.Exit(0)
	}

	// kick off an active scan of IP/Mask on a separate thread
	go func() {
		// sleep for 5 seconds to allow sniffer to kick off
		time.Sleep(5 * time.Second)
		i := 1
		for i > 0 {
			for _, iface := range ifaces {
				macAddr := iface.HardwareAddr.String()
				interfaceName := iface.Name

				if IsValidMac(macAddr) && i == 1 {
					InterfaceToMac[interfaceName] = macAddr
					MacToInterface[macAddr] = interfaceName
				}
				if addrs, err := iface.Addrs(); err == nil {
					if len(addrs) > 0 {
						for _, ip := range addrs {
							if IsValidIPNet(fmt.Sprintf("%v", ip)) {
								if ipnet, ok := ip.(*net.IPNet); ok {
									if ip4 := ipnet.IP.To4(); ip4 != nil {
										addr = &net.IPNet{
											IP:   ip4,
											Mask: ipnet.Mask[len(ipnet.Mask)-4:],
										}
									}
								}
								err = writeARP(writeHandle, &iface, addr)
								if err != nil {
									fmt.Printf("\nSError scanning IP range %v. Error was %v\n", ip, err)
								}
								// send our unsolicited arp response out to all hosts
								err = writeArpResponse(writeHandle, &iface, addr)
								if err != nil {
									fmt.Printf("Error sending arp responses to IP range %v. Error was %v\n", ip, err)
								}
							}
						}
					}
				}
			}
			// apparently windows 2008 and later only persist an arp for 15-45 seconds
			// keep working, keep working. I got mid, loud kush, good purpin'
			time.Sleep(30 * time.Second)
			i += 1
		}
	}()
}


func CheckArpCode (buf []byte) (int, string) {
	ret := 0
	buf_len := len(buf)
	opcodeOffset := 20

	// Make sure we have our runway
	// (dst - 6 bytes) (src - 6 bytes)
	// (ARP 0x0806) - 2 bytes
	// (hardware - 2 bytes 0x0001) (protocol - 2 bytes 0x0800)
	// (hardware sz - 1 byte 0x06) (protocol sz - 1 byte 0x04)
	// (opcode - 2 bytes)
	// sender MAC 6 bytes
	// sender IP 4 bytes
	if buf_len < (opcodeOffset + 2) {
		return 0, "Not enough buffer to process an opcode"
	} else {
		ret = ret + (256 * int(buf[opcodeOffset])) + int(buf[opcodeOffset+1])
		// do we have 10 more bytes of buffer space?
		if buf_len >= (opcodeOffset + 12) && buf[18] == 0x06 && buf[19] == 0x04 {
			tmpmac := []byte{buf[opcodeOffset+2], buf[opcodeOffset+3], buf[opcodeOffset+4],
				buf[opcodeOffset+5], buf[opcodeOffset+6], buf[opcodeOffset+7]}
			tmpip := fmt.Sprintf("%v.%v.%v.%v", buf[opcodeOffset+8], buf[opcodeOffset+9], buf[opcodeOffset+10], buf[opcodeOffset+11])
			IPToMac[tmpip] = tmpmac
		}
		return ret, ""
	}

}

func SynchMacList (macAddr string) {
	for i := MacList.Front(); i != nil; i = i.Next() {
		existingMac := fmt.Sprintf("%v", i.Value)
		if existingMac == macAddr {
			return
		}
	}

	fmt.Printf("New Mac Detected %v\n", macAddr)
	MacList.PushFront(macAddr)

}



// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest, //layers.ARPReply
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}



func writeArpResponse(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},		// this needs to be the discovered mac
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		strIP := fmt.Sprintf("%v.%v.%v.%v", ip[0], ip[1], ip[2], ip[3])
		if len(IPToMac[strIP]) > 0 {
			arp.DstHwAddress = IPToMac[strIP]
			gopacket.SerializeLayers(buf, opts, &eth, &arp)
			if err := handle.WritePacketData(buf.Bytes()); err != nil {
				fmt.Printf("\nError calling WritePacketData()\n")
				return err
			}
		}
	}
	return nil
}



func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}


func IsValidIPNet (IpInfo string) bool {
	IpRegex, _ := regexp.Compile(`^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$`)
	result := IpRegex.FindStringSubmatch(IpInfo)
	if len(result) > 0 {
		mask, err := strconv.Atoi(result[2])
		if err != nil {
			fmt.Printf("\nError converting mask %v to an integer. Error: %v\n", result[2], err)
			return false
		}
		if (mask >= 22) {
			return true
		} else {
			return false
		}
	} else {
		return false
	}

}



func IsValidMac (mac string) bool {
	MacRegex, _ := regexp.Compile(`([a-fA-F0-9]{2}:){5}[a-fA-F0-9]`)
	result := MacRegex.FindStringSubmatch(mac)
	if len(result) > 0 {
		return true
	}

	return false
}



