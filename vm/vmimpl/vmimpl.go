// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vmimpl provides an abstract test machine (VM, physical machine, etc)
// interface for the rest of the system. For convenience test machines are subsequently
// collectively called VMs.
// The package also provides various utility functions for VM implementations.
package vmimpl

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
)

// Pool represents a set of test machines (VMs, physical devices, etc) of particular type.
type Pool interface {
	// Count returns total number of VMs in the pool.
	Count() int

	// Create creates and boots a new VM instance.
	Create(ctx context.Context, workdir string, index int) (Instance, error)
}

// Instance represents a single VM.
type Instance interface {
	// Copy copies a hostSrc file into VM and returns file name in VM.
	Copy(hostSrc string) (string, error)

	// Forward sets up forwarding from within VM to the given tcp
	// port on the host and returns the address to use in VM.
	Forward(port int) (string, error)

	// Run runs cmd inside of the VM (think of ssh cmd).
	// outc receives combined cmd and kernel console output.
	// errc receives either command Wait return error or vmimpl.ErrTimeout.
	// Command terminates with context. Use context.WithTimeout to terminate it earlier.
	Run(ctx context.Context, command string) (outc <-chan Chunk, errc <-chan error, err error)

	// Diagnose retrieves additional debugging info from the VM
	// (e.g. by sending some sys-rq's or SIGABORT'ing a Go program).
	//
	// Optionally returns (some or all) of the info directly. If wait == true,
	// the caller must wait for the VM to output info directly to its log.
	//
	// rep describes the reason why Diagnose was called.
	Diagnose(rep *report.Report) (diagnosis []byte, wait bool)

	// Close stops and destroys the VM.
	io.Closer
}

// Infoer is an optional interface that can be implemented by Instance.
type Infoer interface {
	// MachineInfo returns additional info about the VM, e.g. VMM version/arguments.
	Info() ([]byte, error)
}

// Env contains global constant parameters for a pool of VMs.
type Env struct {
	// Unique name
	// Can be used for VM name collision resolution if several pools share global name space.
	Name      string
	OS        string // target OS
	Arch      string // target arch
	Workdir   string
	Image     string
	SSHKey    string
	SSHUser   string
	Timeouts  targets.Timeouts
	Snapshot  bool
	Debug     bool
	Config    []byte // json-serialized VM-type-specific config
	KernelSrc string
}

// BootError is returned by Pool.Create when VM does not boot.
// It should not be used for VMM intfrastructure errors, i.e. for problems not related
// to the tested kernel itself.
type BootError struct {
	Title  string
	Output []byte
}

func MakeBootError(err error, output []byte) error {
	if len(output) == 0 {
		// In reports, it may be helpful to distinguish the case when the boot output
		// was collected, but turned out to be empty.
		output = []byte("<empty boot output>")
	}
	var verboseError *osutil.VerboseError
	if errors.As(err, &verboseError) {
		return BootError{verboseError.Error(), append(verboseError.Output, output...)}
	}
	return BootError{err.Error(), output}
}

func (err BootError) Error() string {
	return fmt.Sprintf("%v\n%s", err.Title, err.Output)
}

func (err BootError) BootError() (string, []byte) {
	return err.Title, err.Output
}

// By default, all Pool.Create() errors are related to infrastructure problems.
// InfraError is to be used when we want to also attach output to the title.
type InfraError struct {
	Title  string
	Output []byte
}

func (err InfraError) Error() string {
	return fmt.Sprintf("%v\n%s", err.Title, err.Output)
}

func (err InfraError) InfraError() (string, []byte) {
	return err.Title, err.Output
}

// Register registers a new VM type within the package.
func Register(typ string, desc Type) {
	Types[typ] = desc
}

type Type struct {
	Ctor ctorFunc
	// It's possible to create out-of-thin-air instances of this type.
	// Out-of-thin-air instances are used by syz-ci for image testing, patch testing, bisection, etc.
	Overcommit bool
	// Instances of this type can be preempted and lost connection as the result.
	// For preempted instances executor prints "SYZ-EXECUTOR: PREEMPTED" and then
	// the host understands that the lost connection was expected and is not a bug.
	Preemptible bool
}

type ctorFunc func(env *Env) (Pool, error)

var (
	// Close to interrupt all pending operations in all VMs.
	Shutdown   = make(chan struct{})
	ErrTimeout = errors.New("timeout")

	Types = make(map[string]Type)
)

type CmdCloser struct {
	*exec.Cmd
}

func (cc CmdCloser) Close() error {
	cc.Process.Kill()
	return cc.Wait()
}

var WaitForOutputTimeout = 10 * time.Second

type MultiplexConfig struct {
	Console     io.Closer
	Close       <-chan bool
	Debug       bool
	Scale       time.Duration
	IgnoreError func(err error) bool
}

func Multiplex(ctx context.Context, cmd *exec.Cmd, merger *OutputMerger, config MultiplexConfig) (
	<-chan Chunk, <-chan error, error) {
	if config.Scale <= 0 {
		panic("slowdown must be set")
	}
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			signal(ErrTimeout)
		case <-config.Close:
			if config.Debug {
				log.Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			// EOF is not always in perfect sync with exit, so we should wait a bit.
			if cmdErr := waitAndKill(ctx, cmd); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			} else if config.IgnoreError != nil && config.IgnoreError(err) {
				err = ErrTimeout
			}
			// Once the command has failed, we might want to let the full console
			// output accumulate before we abort the console connection too.
			if err != nil {
				time.Sleep(WaitForOutputTimeout * config.Scale)
			}
			if config.Console != nil {
				// Only wait for the merger if we're able to control the console stream.
				config.Console.Close()
				merger.Wait()
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		if config.Console != nil {
			config.Console.Close()
			merger.Wait()
		}
		cmd.Wait()
	}()
	return merger.Output, errc, nil
}

func waitAndKill(ctx context.Context, cmd *exec.Cmd) error {
	err := make(chan error)
	go func() {
		err <- cmd.Wait()
	}()
	// The processes sometimes first close their output streams
	// and only then exit, with some time in between.
	// There might be better ways to enforce another ordering,
	// but for now let's just use a timeout.
	const waitTimeout = 5 * time.Second
	ctxDone := false
	select {
	case <-ctx.Done():
	case <-time.After(waitTimeout):
	case err := <-err:
		return err
	}
	cmd.Process.Kill()
	if ctxDone {
		// Wait till process exits, but return another error.
		<-err
		return ctx.Err()
	}
	return <-err
}

func RandomPort() int {
	n, err := rand.Int(rand.Reader, big.NewInt(64<<10-1<<10))
	if err != nil {
		panic(err)
	}
	return int(n.Int64()) + 1<<10
}

func UnusedTCPPort() int {
	for {
		port := RandomPort()
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", port))
		if err == nil {
			ln.Close()
			return port
		}

		// Continue searching for a port only if we fail with EADDRINUSE or don't have permissions to use this port.
		// Although we exclude ports <1024 in RandomPort(), it's still possible that we can face a restricted port.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "listen" {
			var syscallErr *os.SyscallError
			if errors.As(opErr.Err, &syscallErr) {
				if errors.Is(syscallErr.Err, syscall.EADDRINUSE) || errors.Is(syscallErr.Err, syscall.EACCES) {
					continue
				}
			}
		}
		log.Fatalf("error allocating port localhost:%d: %v", port, err)
	}
}

// Escapes double quotes(and nested double quote escapes). Ignores any other escapes.
// Reference: https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html
func EscapeDoubleQuotes(inp string) string {
	var ret strings.Builder
	for pos := 0; pos < len(inp); pos++ {
		// If inp[pos] is not a double quote or a backslash, just use
		// as is.
		if inp[pos] != '"' && inp[pos] != '\\' {
			ret.WriteByte(inp[pos])
			continue
		}
		// If it is a double quote, escape.
		if inp[pos] == '"' {
			ret.WriteString("\\\"")
			continue
		}
		// If we detect a backslash, reescape only if what it's already escaping
		// is a double-quotes.
		temp := ""
		j := pos
		for ; j < len(inp); j++ {
			if inp[j] == '\\' {
				temp += string(inp[j])
				continue
			}
			// If the escape corresponds to a double quotes, re-escape.
			// Else, just use as is.
			if inp[j] == '"' {
				temp = temp + temp + "\\\""
			} else {
				temp += string(inp[j])
			}
			break
		}
		ret.WriteString(temp)
		pos = j
	}
	return ret.String()
}
