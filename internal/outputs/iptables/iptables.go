package iptables

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"strconv"
	"sync"

	"github.com/devops-works/egress-auditor/internal/entry"
	"github.com/devops-works/egress-auditor/internal/outputs"
)

// IPTHandler writes iptables rules matching connections seen by upstream
// inputs
type IPTHandler struct {
	sync.Mutex
	tpl       *template.Template
	entries   map[string]entry.Connection
	verbosity int
}

func (e *IPTHandler) prepare() error {
	var err error

	e.entries = make(map[string]entry.Connection)

	templates := []string{
		`ip{{ if eq .IPv 6 }}6{{ end }}tables -I OUTPUT -d {{ .DestIP }} -p tcp -m tcp --dport {{ .DestPort }} -j ACCEPT -m comment --comment "{{ .Proc.Name }}"`,
		`# [{{ .Hook }}] Line generated for {{ .Proc.Name }} running as {{ .Proc.User }}"
ip{{ if eq .IPv 6 }}6{{ end }}tables -I OUTPUT -d {{ .DestIP }} -p tcp -m tcp --dport {{ .DestPort }} -j ACCEPT -m comment --comment "{{ .Proc.Name }}"`,
		`# [{{ .Hook }}] Line generated for {{ .Proc.Name }} running as {{ .Proc.User }} with command "{{ .Proc.CmdLine }}"
# [{{ .Hook }}] Parent of this process was {{ .Proc.Parent.Name }} running as {{ .Proc.Parent.User }}
ip{{ if eq .IPv 6 }}6{{ end }}tables -I OUTPUT -d {{ .DestIP }} -p tcp -m tcp --dport {{ .DestPort }} -j ACCEPT -m comment --comment "{{ .Proc.Name }}"`,
	}

	e.tpl, err = template.New("rule").Parse(templates[e.verbosity])
	if err != nil {
		return err
	}
	return nil
}

// Description returns a description for the module, including the available
// options
func (e *IPTHandler) Description() string {
	return `
	iptables handler
	Generates iptables rules to accomodated packet seen via hooks

	Options:
		- "iptables:verbosity:<LVL>": sets verbosity for generated rules (0, 1 or 2)
		     0: no comments, only the iptable command
		     1: comments including process name and process user that triggered the connection
		     2: like above but with parent process information
	`
}

// Process starts handling connections captured by upstream inputs
func (e *IPTHandler) Process(ctx context.Context, c <-chan entry.Connection) {
	err := e.prepare()
	if err != nil {
		panic(err)
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("terminating capture")
			return
		case ent := <-c:
			key := fmt.Sprintf("%s:%d", ent.DestIP, ent.DestPort)
			if _, ok := e.entries[key]; !ok {
				e.Lock()
				e.entries[key] = ent
				e.Unlock()
			}
		}
	}
}

// generate iptable rules
func (e *IPTHandler) generate() [][]byte {
	e.Lock()
	defer e.Unlock()

	rules := [][]byte{}

	for _, v := range e.entries {
		var buf bytes.Buffer
		err := e.tpl.Execute(&buf, v)
		if err != nil {
			// same rationale as above (see New)
			panic(err)
		}
		rules = append(rules, buf.Bytes())
	}

	return rules
}

// Cleanup any stuff that needs to be sorted out before exiting
func (e *IPTHandler) Cleanup() {
	for _, s := range e.generate() {
		fmt.Println(string(s))
	}
}

// SetOption let caller set specific module suboptions
func (e *IPTHandler) SetOption(k, v string) error {
	switch k {
	case "verbose":
		g, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		if g > 2 || g < 0 {
			return fmt.Errorf("wrong verbosity %d; verbosity must be between 0 and 2 included", g)
		}
		e.verbosity = g
	default:
		return fmt.Errorf("option %q unknow for iptables output", k)
	}

	return nil
}

func init() {
	// register in outputs
	outputs.Add("iptables", &IPTHandler{})
}
