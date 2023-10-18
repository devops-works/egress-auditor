package entry

import "github.com/devops-works/egress-auditor/pkg/procdetail"

// Connection info passed between inputs and outputs
type Connection struct {
	Hook     string                    `json:"-"`
	DestIP   string                    `json:"dest_ip"`
	DestPort uint16                    `json:"dest_port"`
	Proc     *procdetail.ProcessDetail `json:"process"`
	IPv      uint8                     `json:"ip_version"`
}
