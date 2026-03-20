package logfmt

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/outputs"
)

// Output writes connections to stdout in logfmt format
type Output struct {
	mu   sync.Mutex
	w    io.Writer
	file *os.File
	path string
}

// Description returns a description for the module, including the available
// options
func (o *Output) Description() string {
	return `
	logfmt handler
	Prints connections in logfmt format (one line per connection).
	Output goes to stdout by default, or to a file if specified.
	When writing to a file, SIGHUP causes the file to be reopened (for logrotate compatibility).

	Options:
		- "logfmt:file:<path>": write output to file instead of stdout

	Example:
		egress-auditor -i nflog -I nflog:group:100 -o logfmt
		egress-auditor -i nflog -I nflog:group:100 -o logfmt -O logfmt:file:/var/log/egress.log
	`
}

// Process starts handling connections captured by upstream inputs
func (o *Output) Process(ctx context.Context, c <-chan entry.Connection) {
	if o.w == nil {
		o.w = os.Stdout
	}

	var sighup chan os.Signal
	if o.path != "" {
		sighup = make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		defer signal.Stop(sighup)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			if err := o.reopen(); err != nil {
				fmt.Fprintf(os.Stderr, "[logfmt] error reopening file: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[logfmt] file reopened after SIGHUP\n")
			}
		case ent := <-c:
			o.print(ent)
		}
	}
}

func quoteIfNeeded(s string) string {
	if strings.ContainsAny(s, " \t\"\\") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func (o *Output) print(e entry.Connection) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintf(o.w, "ts=%s hook=%s protocol=%s dest_ip=%s dest_port=%d ip_version=%d proc_name=%s proc_pid=%d proc_user=%s proc_cmdline=%s parent_name=%s parent_pid=%d parent_user=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		e.Hook,
		e.Protocol,
		e.DestIP,
		e.DestPort,
		e.IPv,
		quoteIfNeeded(e.Proc.Name),
		e.Proc.Pid,
		quoteIfNeeded(e.Proc.User),
		quoteIfNeeded(e.Proc.CmdLine),
		quoteIfNeeded(e.Proc.Parent.Name),
		e.Proc.Parent.Pid,
		quoteIfNeeded(e.Proc.Parent.User),
	)
}

func (o *Output) reopen() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.path == "" {
		return nil
	}
	if o.file != nil {
		o.file.Close()
	}
	f, err := os.OpenFile(o.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	o.file = f
	o.w = f
	return nil
}

// Cleanup any stuff that needs to be sorted out before exiting
func (o *Output) Cleanup() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.file != nil {
		o.file.Close()
	}
}

// SetOption let caller set specific module suboptions
func (o *Output) SetOption(k, v string) error {
	switch k {
	case "file":
		o.path = v
		f, err := os.OpenFile(v, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("unable to open file %q: %w", v, err)
		}
		o.file = f
		o.w = f
		fmt.Fprintf(os.Stderr, "setting logfmt output to %s\n", v)
	default:
		return fmt.Errorf("option %q unknown for logfmt output", k)
	}

	return nil
}

func init() {
	outputs.Add("logfmt", &Output{})
}
