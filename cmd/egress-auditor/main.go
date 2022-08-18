package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/inputs"
	_ "github.com/devops-works/egress-auditor/internal/inputs/all"
	"github.com/devops-works/egress-auditor/internal/outputs"
	_ "github.com/devops-works/egress-auditor/internal/outputs/all"

	// nflog "github.com/florianl/go-nflog"

	flags "github.com/jessevdk/go-flags"
)

// type strslice []string

// func (s *strslice) String() string {
// 	return strings.Join(*s, ",")
// }

// func (s *strslice) Set(v string) error {
// 	*s = append(*s, v)
// 	return nil
// }

var (
	// Version of current binary
	Version string
	// BuildDate of current binary
	BuildDate string
)

func main() {
	var (
		opts struct {
			Inputs        []string     `short:"i" long:"input" description:"Input to use" required:"true"`
			Outputs       []string     `short:"o" long:"output" description:"Output to use" required:"true"`
			HookOptsFn    func(string) `short:"I" long:"inopt" description:"Input option in the form <inputname>:<key>:<value>"`
			HandlerOptsFn func(string) `short:"O" long:"outopt" description:"Output option in the form <outputname>:<key>:<value>"`
			ListFn        func()       `short:"l" long:"list" description:"list available inputs and outputs"`
			RenameProc    string       `short:"R" long:"rename" description:"rename egress-auditor process to this name and wipe arguments in ps output"`
			Version       func()       `short:"V" long:"version" description:"displays versions"`
			// Count         int          `short:"C" long:"count" description:"How many packets to capture before exiting"`
		}
		in  []inputs.Input
		out []outputs.Output
	)

	ino := map[string]map[string]string{}
	outo := map[string]map[string]string{}

	opts.HookOptsFn = func(o string) {
		err := parseSubOption(ino, o)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing input options: %v", err)
		}
	}
	opts.HandlerOptsFn = func(o string) {
		err := parseSubOption(outo, o)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing output options: %v", err)
		}
	}

	opts.ListFn = func() {
		fmt.Fprintf(os.Stderr, "\nAvailable inputs:\n\n")
		for k, h := range inputs.Inputs {
			fmt.Fprintf(os.Stderr, "* %s\n%s\n", k, h.Description())
		}
		fmt.Fprintf(os.Stderr, "\nAvailable outputs:\n\n")

		for k, h := range outputs.Outputs {
			fmt.Fprintf(os.Stderr, "* %s\n%s\n", k, h.Description())
		}
		os.Exit(1)
	}

	opts.Version = func() {
		fmt.Fprintf(os.Stderr, "egress-auditor version %s (built %s)\n", Version, BuildDate)
		os.Exit(0)
	}

	flags.Parse(&opts)

	for _, h := range opts.Inputs {
		if s, ok := inputs.Inputs[h]; ok {
			// Set configured options for input
			for k, v := range ino[h] {
				err := s.SetOption(k, v)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error configuring input %s: %v\n", h, err)
					os.Exit(1)
				}
			}
			in = append(in, s)
			continue
		}
		fmt.Fprintf(os.Stderr, "hook %s not implemented", h)
	}

	if len(in) == 0 {
		fmt.Fprintf(os.Stderr, "no input registered; at least one is needed\n")
		os.Exit(1)
	}

	for _, h := range opts.Outputs {
		if s, ok := outputs.Outputs[h]; ok {
			// Set configured options for output
			for k, v := range outo[h] {
				err := s.SetOption(k, v)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error configuring output %s: %v\n", h, err)
					os.Exit(1)
				}
			}
			out = append(out, s)
			continue
		}
		fmt.Fprintf(os.Stderr, "output %s not implemented\n", h)
	}

	if len(out) == 0 {
		fmt.Fprintf(os.Stderr, "no output registered; at least one is needed\n")
		os.Exit(1)
	}

	if opts.RenameProc != "" {
		if len(opts.RenameProc) > len(os.Args[0]) {
			fmt.Fprintf(os.Stderr, "unable to rename process to %q: new name must be shorter or have the same size as %q\n", opts.RenameProc, os.Args[0])
			os.Exit(1)
		}
		setProcessName(opts.RenameProc)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entriesChan := make(chan entry.Connection, 20)

	// Register inputs
	for i := range in {
		// err :=
		go in[i].Process(ctx, entriesChan)
		defer in[i].Cleanup()
	}

	// Register outputs
	for o := range out {
		go out[o].Process(ctx, entriesChan)
		defer out[o].Cleanup()
	}

	// Wait for ctrl-c
	fmt.Println("egress-auditor is running... press ctrl-c to stop")
	c := make(chan os.Signal, 10)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	cancel()
}

func parseSubOption(m map[string]map[string]string, o string) error {
	parts := strings.SplitN(o, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("wrong number of parts (%d) parts in option %q", len(parts), o)
	}
	if m[parts[0]] == nil {
		m[parts[0]] = make(map[string]string)
	}
	m[parts[0]][parts[1]] = parts[2]
	return nil
}

func setProcessName(name string) {
	for pos := range os.Args {
		argStr := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[pos]))
		arg := (*[1 << 30]byte)(unsafe.Pointer(argStr.Data))[:argStr.Len]

		n := 0
		// only replace namefor arg[0]
		if pos == 0 {
			n = copy(arg, name)
		}
		if n < len(arg) {
			for i := n; i < len(arg); i++ {
				arg[i] = 0
			}
		}
	}
}
