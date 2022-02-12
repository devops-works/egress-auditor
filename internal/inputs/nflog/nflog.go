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
	nfl "github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NFLog catches connections from NFLOG iptables target
type NFLog struct {
	Config nfl.Config
	group  int
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

	Options:
		- "nflog:group:<ID>": listens for packet send to nflog entry identified by this group ID
	`
}

// Process starts handling connections capture
func (nfh *NFLog) Process(ctx context.Context, c chan<- entry.Connection) {
	nfh.Config = nfl.Config{
		Group:    uint16(nfh.group),
		Copymode: nfl.NfUlnlCopyPacket,
	}

	nf, err := nfl.Open(&nfh.Config)
	if err != nil {
		// Pass logger in context, log & return ?
		fmt.Fprintf(os.Stderr, "error opening nflog: %v\n", err)
		return
	}

	defer nf.Close()

	fn := func(m nfl.Msg) int {
		var (
			layerType    gopacket.LayerType
			p            gopacket.Packet
			srcIP, dstIP net.IP
			ipv          uint8
		)

		proto, ok := m[nfl.AttrHwProtocol].(uint16)
		if !ok {
			// skip packet
			return 0
		}

		switch proto {
		case layerIPv4:
			layerType = layers.LayerTypeIPv4
		case layerIPv6:
			layerType = layers.LayerTypeIPv6
		default:
			return 0
		}

		p = gopacket.NewPacket(m[nfl.AttrPayload].([]byte), layerType, gopacket.Default)

		ipLayer := p.Layer(layerType)
		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

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
				fmt.Println("default")
				return 0
			}

			if tcp.SYN && !dstIP.IsLoopback() {
				proc, err := procdetail.GetOwnerOfConnection(srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort))
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to get process: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "new TCP connection %s:%s -> %s:%s by %s\n", srcIP, tcp.SrcPort, dstIP, tcp.DstPort, proc.Name)
				}
				c <- entry.Connection{
					Hook:     "nflog",
					DestIP:   dstIP.String(),
					DestPort: uint16(tcp.DstPort),
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
	}

	return nil
}

func init() {
	// register in inputs
	inputs.Add("nflog", &NFLog{})
}
