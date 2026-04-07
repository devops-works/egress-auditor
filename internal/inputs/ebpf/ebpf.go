// Package ebpf implements an input that captures egress connections via
// eBPF kprobes on tcp_*_connect / udp[v6]_sendmsg. Compared to the nflog
// input, the PID is captured directly in kernel context (no /proc race),
// and no iptables rules are required.
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -cc clang -cflags "-O2 -g -Wall" -target bpfel,bpfeb bpf bpf/egress.c -- -I/usr/include

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/inputs"
	"github.com/devops-works/egress-auditor/pkg/procdetail"
)

// bpfEvent mirrors `struct event` in bpf/egress.c. The byte layout must
// stay in sync with the C struct (no padding because all fields are
// naturally aligned).
type bpfEvent struct {
	Pid       uint32
	Saddr     [4]byte
	Daddr     [4]byte
	Saddr6    [16]byte
	Daddr6    [16]byte
	Sport     uint16
	Dport     uint16
	IPVersion uint8
	Protocol  uint8
	Comm      [16]byte
}

// Input captures egress connections using eBPF kprobes.
type Input struct {
	quiet         bool
	allowLoopback bool

	ignoreNets      []*net.IPNet
	ignorePorts     map[uint16]struct{}
	ignoreComms     map[string]struct{} // exact matches (fast path)
	ignoreCommGlobs []string            // glob patterns (path.Match syntax)

	objs  bpfObjects
	links []link.Link

	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

const dedupWindow = time.Second

// Description returns documentation shown by `egress-auditor -l`.
func (e *Input) Description() string {
	return `
	ebpf kprobe hook
	Captures egress connections by attaching eBPF kprobes to:
	  tcp_v4_connect, tcp_v6_connect, udp_sendmsg, udpv6_sendmsg.

	Process owner (pid) is read directly from kernel context — no race with
	/proc, and no iptables/nftables rules are needed. Requires CAP_BPF (or
	root) and CAP_PERFMON on modern kernels.

	Options:
		- "ebpf:quiet:<false|true>": suppress per-connection messages on stderr
		- "ebpf:allow-loopback:<false|true>": include loopback traffic
		- "ebpf:ignore-cidr:<CIDR>": drop events whose dest IP is in this network
		    (may be specified multiple times, IPv4 or IPv6)
		- "ebpf:ignore-port:<port>": drop events with this dest port
		    (may be specified multiple times)
		- "ebpf:ignore-comm:<name>": drop events from this process name
		    (matched against the resolved /proc name; may be specified multiple
		    times; supports glob wildcards * ? [...] e.g. "chrome*", "*-worker")

	Example:
		sudo egress-auditor -i ebpf -o logfmt \
		    -I ebpf:ignore-cidr:10.0.0.0/8 \
		    -I ebpf:ignore-cidr:192.168.0.0/16 \
		    -I ebpf:ignore-port:53 \
		    -I ebpf:ignore-comm:chronyd
	`
}

// SetOption configures the input.
func (e *Input) SetOption(k, v string) error {
	switch k {
	case "quiet":
		q, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		e.quiet = q
	case "allow-loopback":
		a, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		e.allowLoopback = a
	case "ignore-cidr":
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", v, err)
		}
		e.ignoreNets = append(e.ignoreNets, n)
	case "ignore-port":
		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port %q: %w", v, err)
		}
		if e.ignorePorts == nil {
			e.ignorePorts = make(map[uint16]struct{})
		}
		e.ignorePorts[uint16(port)] = struct{}{}
	case "ignore-comm":
		if v == "" {
			return fmt.Errorf("ignore-comm requires a non-empty value")
		}
		if strings.ContainsAny(v, "*?[") {
			// Validate the pattern by running a dummy match.
			if _, err := path.Match(v, ""); err != nil {
				return fmt.Errorf("invalid ignore-comm pattern %q: %w", v, err)
			}
			e.ignoreCommGlobs = append(e.ignoreCommGlobs, v)
		} else {
			if e.ignoreComms == nil {
				e.ignoreComms = make(map[string]struct{})
			}
			e.ignoreComms[v] = struct{}{}
		}
	default:
		return fmt.Errorf("option %q unknown for ebpf input", k)
	}
	return nil
}

// isNetFiltered returns true if the destination IP/port should be dropped.
// This is checked early, before any process resolution.
func (e *Input) isNetFiltered(destIP net.IP, dport uint16) bool {
	for _, n := range e.ignoreNets {
		if n.Contains(destIP) {
			return true
		}
	}
	if _, skip := e.ignorePorts[dport]; skip {
		return true
	}
	return false
}

// isProcFiltered returns true if the resolved process name matches an
// ignore-comm rule. We match against proc.Name (from /proc) rather than the
// eBPF-captured thread comm, because multi-threaded daemons set per-thread
// names via prctl(PR_SET_NAME) — the kernel comm at hook time can differ
// from the user-visible process name (e.g. unbound worker threads).
func (e *Input) isProcFiltered(procName string) bool {
	if _, skip := e.ignoreComms[procName]; skip {
		return true
	}
	for _, pat := range e.ignoreCommGlobs {
		if ok, _ := path.Match(pat, procName); ok {
			return true
		}
	}
	return false
}

// Process loads the eBPF objects, attaches the kprobes, and forwards
// events on c until ctx is cancelled.
func (e *Input) Process(ctx context.Context, c chan<- entry.Connection) {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "[ebpf] failed to remove memlock: %v\n", err)
		return
	}

	if err := loadBpfObjects(&e.objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "[ebpf] failed to load eBPF objects: %v\n", err)
		return
	}

	type probeSpec struct {
		symbol string
		prog   *ebpf.Program
		ret    bool
	}
	probes := []probeSpec{
		{"tcp_v4_connect", e.objs.KprobeTcpV4Connect, false},
		{"tcp_v4_connect", e.objs.KretprobeTcpV4Connect, true},
		{"tcp_v6_connect", e.objs.KprobeTcpV6Connect, false},
		{"tcp_v6_connect", e.objs.KretprobeTcpV6Connect, true},
		{"udp_sendmsg", e.objs.KprobeUdpSendmsg, false},
		{"udpv6_sendmsg", e.objs.KprobeUdpv6Sendmsg, false},
	}
	for _, p := range probes {
		var (
			l   link.Link
			err error
		)
		if p.ret {
			l, err = link.Kretprobe(p.symbol, p.prog, nil)
		} else {
			l, err = link.Kprobe(p.symbol, p.prog, nil)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ebpf] failed to attach %s (ret=%v): %v\n", p.symbol, p.ret, err)
			return
		}
		e.links = append(e.links, l)
	}

	rd, err := perf.NewReader(e.objs.Events, os.Getpagesize()*64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ebpf] failed to create perf reader: %v\n", err)
		return
	}

	// Closing the reader unblocks rd.Read() so the loop below exits cleanly.
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	e.dedup = make(map[string]time.Time)

	var evt bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "[ebpf] perf read error: %v\n", err)
			continue
		}
		if record.LostSamples != 0 {
			fmt.Fprintf(os.Stderr, "[ebpf] lost %d samples\n", record.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			fmt.Fprintf(os.Stderr, "[ebpf] failed to decode event: %v\n", err)
			continue
		}

		destIP := destToIP(&evt)
		if destIP == nil {
			continue
		}
		if destIP.IsLoopback() && !e.allowLoopback {
			continue
		}
		if e.isNetFiltered(destIP, evt.Dport) {
			continue
		}

		// UDP can fire many times per "flow"; dedup on (pid, daddr, dport).
		if evt.Protocol == 17 {
			key := fmt.Sprintf("%d|%s|%d", evt.Pid, destIP.String(), evt.Dport)
			if e.shouldSkipDup(key) {
				continue
			}
		}

		proto := "tcp"
		if evt.Protocol == 17 {
			proto = "udp"
		}

		proc, err := procdetail.New(int32(evt.Pid))
		if err != nil || proc == nil {
			proc = fallbackProc(int32(evt.Pid), evt.Comm[:])
		}

		if e.isProcFiltered(proc.Name) {
			continue
		}

		if !e.quiet {
			fmt.Fprintf(os.Stderr, "new %s connection -> %s:%d by %s\n",
				proto, destIP, evt.Dport, proc.Name)
		}

		c <- entry.Connection{
			Hook:     "ebpf",
			Protocol: proto,
			DestIP:   destIP.String(),
			DestPort: evt.Dport,
			Proc:     proc,
			IPv:      evt.IPVersion,
		}
	}
}

func (e *Input) shouldSkipDup(key string) bool {
	now := time.Now()
	e.dedupMu.Lock()
	defer e.dedupMu.Unlock()
	if last, ok := e.dedup[key]; ok && now.Sub(last) < dedupWindow {
		e.dedup[key] = now
		return true
	}
	e.dedup[key] = now
	// Opportunistic GC.
	if len(e.dedup) > 1024 {
		for k, t := range e.dedup {
			if now.Sub(t) > dedupWindow {
				delete(e.dedup, k)
			}
		}
	}
	return false
}

// Cleanup detaches probes and releases the eBPF objects.
func (e *Input) Cleanup() {
	for _, l := range e.links {
		l.Close()
	}
	e.objs.Close()
}

func destToIP(evt *bpfEvent) net.IP {
	if evt.IPVersion == 6 {
		ip := make(net.IP, 16)
		copy(ip, evt.Daddr6[:])
		return ip
	}
	ip := make(net.IP, 4)
	copy(ip, evt.Daddr[:])
	return ip
}

func fallbackProc(pid int32, comm []byte) *procdetail.ProcessDetail {
	name := nullTerm(comm)
	if name == "" {
		name = "unknown"
	}
	return &procdetail.ProcessDetail{
		Pid:     pid,
		Name:    name,
		CmdLine: name,
		User:    "unknown",
		Parent: &procdetail.ProcessDetail{
			Name:    "unknown",
			CmdLine: "unknown",
			User:    "unknown",
		},
	}
}

func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func init() {
	inputs.Add("ebpf", &Input{})
}
