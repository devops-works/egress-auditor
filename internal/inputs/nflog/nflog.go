package nflog

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/inputs"
	"github.com/devops-works/egress-auditor/pkg/procdetail"
	nfl "github.com/florianl/go-nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NFLog struct {
	Config nfl.Config
	group  int
	// Output outputs.Output
}

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
		// Just print out the id and payload of the nfqueue packet
		// fmt.Printf("got packet\n")
		// fmt.Printf("%+v\n", m[nfl.AttrPayload].([]byte))
		p := gopacket.NewPacket(m[nfl.AttrPayload].([]byte), layers.LayerTypeIPv4, gopacket.Default)

		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			ipLayer := p.Layer(layers.LayerTypeIPv4)
			tcp, _ := tcpLayer.(*layers.TCP)
			ip, _ := ipLayer.(*layers.IPv4)
			if tcp.SYN && !ip.DstIP.IsLoopback() {
				proc, err := procdetail.GetOwnerOfConnection(ip.SrcIP, uint16(tcp.SrcPort), ip.DstIP, uint16(tcp.DstPort))
				if err != nil {
					fmt.Fprintf(os.Stderr, "unable to getting process: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "new TCP connection %s:%s -> %s:%s by %s\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, proc.Name)
				}
				c <- entry.Connection{
					Hook:     "nflog",
					DestIP:   ip.DstIP.String(),
					DestPort: uint16(tcp.DstPort),
					Proc:     proc,
				}
			}
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

func (nfh *NFLog) Cleanup() {
	// fmt.Printf("%+v\n", nfh)
	// nfh.NfLog.Close()
}

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
	inputs.Add("nflog", &NFLog{})
}
