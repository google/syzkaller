package qemu

import (
	"encoding/json"
	"fmt"
	"net"
)

type qmpVersion struct {
	Package string
	QEMU    struct {
		Major int
		Micro int
		Minor int
	}
}

type qmpBanner struct {
	QMP struct {
		Version qmpVersion
	}
}

type qmpCommand struct {
	Execute   string      `json:"execute"`
	Arguments interface{} `json:"arguments,omitempty"`
}

type hmpCommand struct {
	Command string `json:"command-line"`
	CPU     int    `json:"cpu-index"`
}

type qmpResponse struct {
	Error struct {
		Class string
		Desc  string
	}
	Return interface{}
}

func (inst *instance) qmp_check_connection() error {
	if inst.mon != nil {
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%v", inst.monport)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	monDec := json.NewDecoder(conn)
	monEnc := json.NewEncoder(conn)

	var banner qmpBanner
	if err := monDec.Decode(&banner); err != nil {
		return err
	}

	inst.monEnc = monEnc
	inst.monDec = monDec
	if _, err := inst.do_qmp(&qmpCommand{Execute: "qmp_capabilities"}); err != nil {
		inst.monEnc = nil
		inst.monDec = nil
		return err
	}
	inst.mon = conn

	return nil
}

func (inst *instance) qmp_recv() (*qmpResponse, error) {
	qmp := new(qmpResponse)
	err := inst.monDec.Decode(qmp)

	return qmp, err
}

func (inst *instance) do_qmp(cmd *qmpCommand) (*qmpResponse, error) {
	if err := inst.monEnc.Encode(cmd); err != nil {
		return nil, err
	}
	return inst.qmp_recv()
}

func (inst *instance) qmp(cmd *qmpCommand) (interface{}, error) {
	if err := inst.qmp_check_connection(); err != nil {
		return nil, err
	}
	resp, err := inst.do_qmp(cmd)
	if err != nil {
		return resp.Return, err
	}
	if resp.Error.Desc != "" {
		return resp.Return, fmt.Errorf("Error %v", resp.Error)
	}
	if resp.Return == nil {
		return nil, fmt.Errorf(`No "return" nor "error" in [%v]`, resp)
	}
	return resp.Return, nil
}

func (inst *instance) hmp(cmd string, cpu int) (string, error) {
	req := &qmpCommand{
		Execute: "human-monitor-command",
		Arguments: &hmpCommand{
			Command: cmd,
			CPU:     cpu,
		},
	}
	resp, err := inst.qmp(req)
	if err != nil {
		return "", err
	}
	return resp.(string), nil
}
