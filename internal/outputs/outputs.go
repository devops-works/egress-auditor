package outputs

import (
	"context"

	"github.com/devops-works/egress-auditor/internal/entry"
)

// Handler interface must be implement for specific rule handlers.
//
// A handler must be able to generate a dump of rules or apply rules
type Output interface {
	Description() string
	// Add(hook, dstip string, dstport uint16, proc *procdetail.ProcessDetail)
	Process(context.Context, <-chan entry.Connection)
	Cleanup()
	// Apply() error
	SetOption(string, string) error
}

var Outputs = map[string]Output{}

func Add(name string, h Output) {
	Outputs[name] = h
}
