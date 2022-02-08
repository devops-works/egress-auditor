package procdetail

import (
	"fmt"
	"net"

	"github.com/cakturk/go-netstat/netstat"
	"github.com/shirou/gopsutil/process"
)

type ProcessDetail struct {
	Pid     int32
	Name    string
	CmdLine string
	User    string
	Parent  *ProcessDetail
}

func GetOwnerOfConnection(sip net.IP, spp uint16, dip net.IP, dpp uint16) (*ProcessDetail, error) {
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.LocalAddr.IP.Equal(sip) && s.RemoteAddr.IP.Equal(dip) &&
			s.LocalAddr.Port == spp && s.RemoteAddr.Port == dpp
	})
	if err != nil {
		return nil, err
	}

	switch len(tabs) {
	case 0:
		return nil, nil
	case 1:
		// continue processing
		break
	default:
		return nil, fmt.Errorf("multiple process matched")
	}

	e := tabs[0]

	// In some circumstances, process finishes really fast and can not be found in /proc
	// This is an issue in NFLOG mode
	if e.Process == nil {
		return &ProcessDetail{
			Name:    "unknown",
			CmdLine: "unknown",
			User:    "unknown",
			Parent: &ProcessDetail{
				Name:    "unknown",
				CmdLine: "unknown",
				User:    "unknown",
				Parent:  nil,
			},
		}, nil
	}

	procentry, err := New(int32(e.Process.Pid))
	if err != nil {
		return nil, err
	}

	return procentry, nil
}

// func getDetail(pid int, checkparent bool) (*Process, error) {

// }

func New(pid int32) (*ProcessDetail, error) {
	p := &ProcessDetail{}

	err := p.getDetailsFor(pid)
	if err != nil {
		return nil, err
	}

	err = p.Parent.getDetailsFor(p.Parent.Pid)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *ProcessDetail) getDetailsFor(pid int32) error {
	proc, err := process.NewProcess(pid)
	if err != nil {
		return err
	}

	p.Pid = proc.Pid
	p.Parent = &ProcessDetail{
		Name:    "unknown",
		CmdLine: "unknown",
		User:    "unknown",
		Parent:  nil,
	}

	p.Parent.Pid, err = proc.Ppid()
	if err != nil {
		return err
	}
	p.Name, err = proc.Name()
	if err != nil {
		return err
	}

	p.CmdLine, err = proc.Cmdline()
	if err != nil {
		return err
	}

	p.User, err = proc.Username()
	if err != nil {
		return err
	}

	return nil
}
