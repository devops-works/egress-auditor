package inputs

import (
	"context"

	"github.com/devops-works/egress-auditor/internal/entry"
)

type Input interface {
	Description() string
	Process(context.Context, chan<- entry.Connection)
	Cleanup()
	SetOption(string, string) error
}

var Inputs = map[string]Input{}

func Add(name string, h Input) {
	Inputs[name] = h
}
