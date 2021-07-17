// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
)

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

type qmpEvent struct {
	Event     string
	Data      map[string]interface{}
	Timestamp struct {
		Seconds      int64
		Microseconds int64
	}
}

func (inst *instance) qmpConnCheck() error {
	if inst.mon != nil {
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%v", inst.monport)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(conn)
	monEnc := json.NewEncoder(conn)

	inst.mon = conn
	inst.scanner = scanner

	inst.qmpRecv()

	inst.monEnc = monEnc
	if _, err := inst.doQmp(&qmpCommand{Execute: "qmp_capabilities"}); err != nil {
		inst.monEnc = nil
		inst.mon = nil
		inst.scanner = nil
		return err
	}

	return nil
}

func (inst *instance) qmpRecv() (*qmpResponse, error) {
	qmp := new(qmpResponse)
	var err error

	for inst.scanner.Scan() {
		var qe qmpEvent
		b := inst.scanner.Bytes()
		err = json.Unmarshal(b, &qe)
		if err != nil {
			continue
		}
		if qe.Event == "" {
			err = json.Unmarshal(b, qmp)
			if err != nil {
				continue
			} else {
				break
			}
		}
	}

	return qmp, err
}

func (inst *instance) doQmp(cmd *qmpCommand) (*qmpResponse, error) {
	if err := inst.monEnc.Encode(cmd); err != nil {
		return nil, err
	}
	return inst.qmpRecv()
}

func (inst *instance) qmp(cmd *qmpCommand) (interface{}, error) {
	if err := inst.qmpConnCheck(); err != nil {
		return nil, err
	}
	resp, err := inst.doQmp(cmd)
	if err != nil {
		return nil, err
	}
	if resp.Error.Desc != "" {
		return resp.Return, fmt.Errorf("error %v", resp.Error)
	}
	if resp.Return == nil {
		return nil, fmt.Errorf(`no "return" nor "error" in [%v]`, resp)
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
