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

type IPTHandler struct {
	sync.Mutex
	tpl       *template.Template
	entries   map[string]entry.Connection
	templates []*template.Template
	verbosity int
}

func (e *IPTHandler) prepare() error {
	var err error

	e.entries = make(map[string]entry.Connection)

	templates := []string{
		`iptables -I OUTPUT -d {{ .DestIP }} -p tcp -m tcp --dport {{ .DestPort }} -j ACCEPT -m comment --comment "{{ .Proc.Name }}"`,
		`# [{{ .Hook }}] Line generated for {{ .Proc.Name }} running as {{ .Proc.User }}"
iptables -I OUTPUT -d {{ .DestIP }} -p tcp -m tcp --dport {{ .DestPort }} -j ACCEPT -m comment --comment "{{ .Proc.Name }}"`,
		`# [{{ .Hook }}] Line generated for {{ .Proc.Name }} running as {{ .Proc.User }} with command "{{ .Proc.CmdLine }}"
# [{{ .Hook }}] Parent of this process was {{ .Proc.Parent.Name }} running as {{ .Proc.Parent.User }}
iptables -I OUTPUT -d {{ .DestIP }} -p tcp -m tcp --dport {{ .DestPort }} -j ACCEPT -m comment --comment "{{ .Proc.Name }}"`,
	}

	e.tpl, err = template.New("rule").Parse(templates[e.verbosity])
	if err != nil {
		return err
	}
	return nil
}

func (nfh *IPTHandler) Description() string {
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
			fmt.Println("checking entry", key)
			if _, ok := e.entries[key]; !ok {
				e.Lock()
				e.entries[key] = ent
				e.Unlock()
				fmt.Println("added entry", key)
			}
		}
	}
}

func (e *IPTHandler) Generate() [][]byte {
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

func (e *IPTHandler) Apply() error {
	return nil
}

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
	}

	return nil
}

func init() {
	outputs.Add("iptables", &IPTHandler{})
}
