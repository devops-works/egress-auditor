package nflog

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/inputs"
	"github.com/devops-works/egress-auditor/pkg/procdetail"
	nfl "github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NFLog catches connections from NFLOG iptables target
type NFLog struct {
	Config        nfl.Config
	group         int
	allowLoopback bool
	quiet         bool
	// Output outputs.Output
}

const (
	layerIPv4 = 0x0800
	layerIPv6 = 0x86DD
)

// Description returns a description for the module, including the available
// options
func (nfh *NFLog) Description() string {
	return `
	nflog iptables hook
	Gets packet from iptables NFLOG target.
	Add iptable rules like so:

		sudo iptables -I OUTPUT -m state --state NEW -p tcp -j NFLOG --nflog-group 100
		sudo iptables -I OUTPUT -m state --state NEW -p udp -j NFLOG --nflog-group 100

	Options:
		- "nflog:group:<ID>": listens for packet send to nflog entry identified by this group ID
		- "nflog:allow-loopback:<false|true>": whether to check on loopback traffic or not
		- "nflog:quiet:<false|true>": suppress per-connection messages on stderr

	Example:
		egress-auditor -i nflog -I nflog:group:100 ...
	`
}

// Process starts handling connections capture
func (nfh *NFLog) Process(ctx context.Context, c chan<- entry.Connection) {
	nfh.Config = nfl.Config{
		Group:    uint16(nfh.group),
		Copymode: nfl.CopyPacket,
	}

	nf, err := nfl.Open(&nfh.Config)
	if err != nil {
		// Pass logger in context, log & return ?
		fmt.Fprintf(os.Stderr, "error opening nflog: %v\n", err)
		return
	}

	defer nf.Close()

	fn := func(a nfl.Attribute) int {
		var (
			layerType    gopacket.LayerType
			p            gopacket.Packet
			srcIP, dstIP net.IP
			ipv          uint8
		)

		if a.HwProtocol == nil || a.Payload == nil {
			return 0
		}

		switch *a.HwProtocol {
		case layerIPv4:
			layerType = layers.LayerTypeIPv4
		case layerIPv6:
			layerType = layers.LayerTypeIPv6
		default:
			return 0
		}

		p = gopacket.NewPacket(*a.Payload, layerType, gopacket.Default)

		ipLayer := p.Layer(layerType)
		// helper to extract IPs from the IP layer
		extractIPs := func() bool {
			switch ipLayer.LayerType() {
			case layers.LayerTypeIPv4:
				ip, _ := ipLayer.(*layers.IPv4)
				srcIP = ip.SrcIP
				dstIP = ip.DstIP
				ipv = 4
			case layers.LayerTypeIPv6:
				ip, _ := ipLayer.(*layers.IPv6)
				srcIP = ip.SrcIP
				dstIP = ip.DstIP
				ipv = 6
			default:
				return false
			}
			return true
		}

		if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if !extractIPs() {
				return 0
			}
			if tcp.SYN && (!dstIP.IsLoopback() || nfh.allowLoopback) {
				proc, err := procdetail.GetOwnerOfConnection("tcp", srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort))
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to get process: %v\n", err)
				} else if !nfh.quiet {
					fmt.Fprintf(os.Stderr, "new tcp connection %s:%s -> %s:%s by %s\n", srcIP, tcp.SrcPort, dstIP, tcp.DstPort, proc.Name)
				}
				c <- entry.Connection{
					Hook:     "nflog",
					Protocol: "tcp",
					DestIP:   dstIP.String(),
					DestPort: uint16(tcp.DstPort),
					Proc:     proc,
					IPv:      ipv,
				}
			}
			return 0
		}

		if udpLayer := p.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if !extractIPs() {
				return 0
			}
			if !dstIP.IsLoopback() || nfh.allowLoopback {
				proc, err := procdetail.GetOwnerOfConnection("udp", srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort))
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to get process: %v\n", err)
				} else if !nfh.quiet {
					fmt.Fprintf(os.Stderr, "new udp connection %s:%s -> %s:%s by %s\n", srcIP, udp.SrcPort, dstIP, udp.DstPort, proc.Name)
				}
				c <- entry.Connection{
					Hook:     "nflog",
					Protocol: "udp",
					DestIP:   dstIP.String(),
					DestPort: uint16(udp.DstPort),
					Proc:     proc,
					IPv:      ipv,
				}
			}
			return 0
		}
		return 0
	}

	if err := nf.Register(ctx, fn); err != nil {
		fmt.Fprintf(os.Stderr, "error registering nflog: %v\n", err)
		panic(err)
		// TODO:exit gorouting and catch in a rungroup in main, then cancel ctx there
	}

	<-ctx.Done()
}

// Cleanup any stuff that needs to be sorted out before exiting
func (nfh *NFLog) Cleanup() {
}

// SetOption let caller set specific module suboptions
func (nfh *NFLog) SetOption(k, v string) error {
	switch k {
	case "group":
		g, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		nfh.group = g
		fmt.Fprintf(os.Stderr, "setting nflog group to %d\n", nfh.group)
	case "allow-loopback":
		a, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		nfh.allowLoopback = a
		fmt.Fprintf(os.Stderr, "setting allowing-loopback to %t\n", nfh.allowLoopback)
	case "quiet":
		q, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		nfh.quiet = q
	}
	return nil
}

func init() {
	// register in inputs
	inputs.Add("nflog", &NFLog{})
}
