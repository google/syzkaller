package syz_analyze

type ProgramArgs struct {
	Pool, VM   int
	ExecTaskID int64
	Hanged     bool
	Error      []byte
}

type ProgramResults struct {
	Prog []byte
	ID   int64
}
