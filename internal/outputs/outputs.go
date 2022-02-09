package outputs

import (
	"context"

	"github.com/devops-works/egress-auditor/internal/entry"
)

// Output interface must be implemented to make use of connections captured par
// inputs.
//
// An output must be able to generate a dump of rules or apply rules
type Output interface {
	// Description returns a description for the module, including the
	// available options
	Description() string
	// Process starts handling connections captured by upstream inputs
	Process(context.Context, <-chan entry.Connection)
	// Cleanup any stuff that needs to be sorted out before exiting main
	Cleanup()
	// SetOption let caller set specific module suboptions
	SetOption(string, string) error
}

// Outputs holds the list of available outputs
var Outputs = map[string]Output{}

// Add lets an ouput register itself at startup
func Add(name string, h Output) {
	Outputs[name] = h
}
