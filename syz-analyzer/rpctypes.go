package syz_analyzer

import "github.com/google/syzkaller/pkg/ipc"

type ProgramArgs struct {
	Pool, VM int
	TaskID   int64
	Info     *ipc.ProgInfo
	Hanged   bool
	Error    []byte
}

type ProgramResults struct {
	Prog []byte
	ID   int64
}
