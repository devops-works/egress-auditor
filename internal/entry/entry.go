package entry

import "github.com/devops-works/egress-auditor/pkg/procdetail"

type Connection struct {
	Hook     string
	DestIP   string
	DestPort uint16
	Proc     *procdetail.ProcessDetail
}
