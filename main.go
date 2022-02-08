package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

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

func main() {
	var (
		opts struct {
			Inputs        []string     `short:"i" long:"input" description:"Input to use" required:"true"`
			Outputs       []string     `short:"o" long:"output" description:"Output to use" required:"true"`
			HookOptsFn    func(string) `short:"I" long:"inopt" description:"Input option in the form <hookname>:<key>:<value>"`
			HandlerOptsFn func(string) `short:"O" long:"outopt" description:"Output option in the form <handlername>:<key>:<value>"`
			ListFn        func()       `short:"l" long:"list" description:"list available inputs and outputs"`
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

	// _, err :=
	flags.Parse(&opts)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "error: %v", err)
	// }

	// for k, v := range ino {
	// 	fmt.Println(k, v)
	// }
	// for k, v := range hao {
	// 	fmt.Println(k, v)
	// }

	for _, h := range opts.Inputs {
		if s, ok := inputs.Inputs[h]; ok {
			// Set configured options for input
			for k, v := range ino[h] {
				s.SetOption(k, v)
			}
			in = append(in, s)
			continue
		}
		fmt.Fprintf(os.Stderr, "hook %s not implemented", h)
	}

	if len(in) == 0 {
		fmt.Fprintf(os.Stderr, "no hook registered; at least one is needed\n")
		os.Exit(1)
	}

	for _, h := range opts.Outputs {
		if s, ok := outputs.Outputs[h]; ok {
			// Set configured options for output
			for k, v := range outo[h] {
				s.SetOption(k, v)
			}
			out = append(out, s)
			continue
		}
		fmt.Fprintf(os.Stderr, "handler %s not implemented", h)
	}

	if len(out) == 0 {
		fmt.Fprintf(os.Stderr, "no handler registered; at least one is needed\n")
		os.Exit(1)
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
		// defer out[o].Cleanup()
	}

	// Wait for ctrl-c
	fmt.Println("egress-auditor is running... press ctrl-c to stop")
	c := make(chan os.Signal, 10)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	cancel()

	fmt.Println()
	for _, s := range out[0].Generate() {
		fmt.Println(string(s))
	}
	os.Exit(1)
}

func parseSubOption(m map[string]map[string]string, o string) error {
	parts := strings.Split(o, ":")
	if len(parts) != 3 {
		return fmt.Errorf("wrong parts in options %v", parts)
	}
	if m[parts[0]] == nil {
		m[parts[0]] = make(map[string]string)
	}
	m[parts[0]][parts[1]] = parts[2]
	return nil
}
