package entry

import "github.com/devops-works/egress-auditor/pkg/procdetail"

// Connection info passed between inputs and outputs
type Connection struct {
	Hook     string
	DestIP   string
	DestPort uint16
	Proc     *procdetail.ProcessDetail
}
