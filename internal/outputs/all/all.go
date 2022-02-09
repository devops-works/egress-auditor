package all

import (
	//Blank imports for handlers to register themselves
	_ "github.com/devops-works/egress-auditor/internal/outputs/iptables"
	_ "github.com/devops-works/egress-auditor/internal/outputs/loki"
	// _ "github.com/devops-works/egress-auditor/internal/handlers/iptables"
)
