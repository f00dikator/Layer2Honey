// John Lampe Dec. 2019
// blatantly horked tons of code from https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"time"
)


func main() {
	var configPath string

	now := time.Now()
	scriptStartTime := now.Unix()

	flag.StringVar(&configPath, "config", "config.yml", "Full Path to the YAML configuration file")
	flag.Parse()
	populate_config(&config, configPath)

	// first off...we need to insert ourselves into the arp cache of all broadcast-domain hosts
	LemmeSlideIntoYourCache(config.Interface)

	handle, err := pcap.OpenLive(config.Interface, 1500, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Failed to open %v. Set the listening interface with the '-i' param. Exiting\n", config.Interface)
		os.Exit(0)
	}


	var filter = fmt.Sprintf("arp or dst %v", config.interfaceip)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Printf("%s\n", "Failed to set BPF Filter %v. Exiting\n", filter)
		os.Exit(0)
	}


	// sniff for new hosts
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dstMac := fmt.Sprintf("%v", packet.LinkLayer().LinkFlow().Dst())
		srcMac := fmt.Sprintf("%v", packet.LinkLayer().LinkFlow().Src())
		SynchMacList(srcMac)
		if packet.NetworkLayer() == nil  && srcMac != config.gatewaymac {
			// handle just our ARP traffic first
			now = time.Now()
			currentTime := now.Unix()
			if (currentTime - scriptStartTime) > 60 &&
				len(MacToInterface[dstMac]) > 0 {
					arpCode, err := CheckArpCode(packet.Data())
					if len(err) > 0 {
						fmt.Printf("Error retrieving opcode of arp packet. Error: %v", err)
					}
					// arp opcode 0x0002 is an Arp Reply. We have a thread sending Arp requests...ignore those responses...
					if arpCode != 2  && len(HabitualOffenders[srcMac]) <= 0 &&
						(srcMac != "ff:ff:ff:ff:ff:ff") && (dstMac != "ff:ff:ff:ff:ff:ff") {
						fmt.Printf("Captured an Arp Probe to our mac %v from %v Opcode %v\n", dstMac, srcMac, arpCode)
						HabitualOffenders[srcMac] = srcMac
						}

			}
 		}


		// Now, let's see what we have (if anything) at layer 4
		if packet.TransportLayer() != nil {
			dstPort := packet.TransportLayer().TransportFlow().Dst()
			srcPort := packet.TransportLayer().TransportFlow().Src()
			if srcMac != config.gatewaymac {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					ipTxt := fmt.Sprintf("%v", ip.SrcIP)
					dstIP := fmt.Sprintf("%v", ip.DstIP)
					// avoid broadcast traffic. Ensure that packet has a dstIP of us
					if dstIP == config.interfaceip && len(HabitualOffenders[ipTxt]) <= 0 {
						// see if we have already flagged on this mofo
						if fmt.Sprintf("%v", srcPort) != "443" {
							fmt.Printf("Captured a probe at layer 3/4 %v:%v -> %v:%v\n\n", ip.SrcIP, srcPort, ip.DstIP, dstPort)
							HabitualOffenders[ipTxt] = ipTxt
						}
					}
				} else {
					// icmp and shit
					dstIP := fmt.Sprintf("%v", packet.TransportLayer().TransportFlow().Dst())
					ipTxt := fmt.Sprintf("%v", packet.TransportLayer().TransportFlow().Src())
					if dstIP == config.interfaceip && len(HabitualOffenders[ipTxt]) <= 0 {
						fmt.Printf("Captured a Transport-Layer probe from %v", ipTxt)
						HabitualOffenders[ipTxt] = ipTxt
					}
				}
			}
			// check layer 3 generic shit (like icmp)
		} else if (packet.NetworkLayer() != nil) && srcMac != config.gatewaymac {
			ipTxt := fmt.Sprintf("%v",packet.NetworkLayer().NetworkFlow().Src())
			dstIP := fmt.Sprintf("%v",packet.NetworkLayer().NetworkFlow().Dst())
			if dstIP == config.interfaceip && len(HabitualOffenders[ipTxt]) <= 0 {
				fmt.Printf("Unspecified layer 3 traffic from %v to %v\n", ipTxt, dstIP)
				HabitualOffenders[ipTxt] = ipTxt
			}
		}
	}
}




