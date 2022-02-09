package inputs

import (
	"context"

	"github.com/devops-works/egress-auditor/internal/entry"
)

// Input interface must be implemented by plugins that capture egress connections
type Input interface {
	Description() string
	Process(context.Context, chan<- entry.Connection)
	Cleanup()
	SetOption(string, string) error
}

// Inputs has a list of available inputs
var Inputs = map[string]Input{}

// Add let an input register itself
func Add(name string, h Input) {
	Inputs[name] = h
}
