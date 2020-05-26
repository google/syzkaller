package qemu

import (
	"fmt"
	"net"
	"encoding/json"
	"errors"
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
	Error string       `json:"error,omitempty"`
	Return interface{} `json:"return,omitempty"`
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

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var banner qmpBanner
	err = dec.Decode(&banner)

	cmd := qmpCommand{Execute: "qmp_capabilities"}
	err = enc.Encode(cmd)

	var resp qmpResponse
	err = dec.Decode(&resp)
	if err != nil {
		return err
	}
	inst.mon = conn
	return nil
}

func (inst *instance) qmp_recv() (*qmpResponse, error) {
	qmp := new(qmpResponse)
	dec := json.NewDecoder(inst.mon)
	err := dec.Decode(qmp)

	return qmp, err
}

func (inst *instance) qmp(cmd *qmpCommand) (*qmpResponse, error) {
	if err := inst.qmp_check_connection(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(cmd)
	if err != nil {
		return nil, err
	}
	fmt.Printf("qmp %s\n", data)
	inst.mon.Write(data)
	return inst.qmp_recv()
}

func (inst *instance) hmp(cmd string, cpu int) (string, error) {
	req := &qmpCommand{
		Execute: "human-monitor-command",
		Arguments: &hmpCommand{
			Command: cmd,
			CPU: cpu,
		},
	}
	resp, err := inst.qmp(req)
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	if resp.Return != nil {
		return resp.Return.(string), nil
	}
	return "", errors.New(fmt.Sprintf(`No "return" nor "error" in [%v]`, resp))
}
