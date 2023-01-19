// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package vmimpl provides an abstract test machine (VM, physical machine, etc)
// interface for the rest of the system. For convenience test machines are subsequently
// collectively called VMs.
// The package also provides various utility functions for VM implementations.
package vmimpl

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os/exec"
	"strings"
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
	Create(workdir string, index int) (Instance, error)
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
	// Command is terminated after timeout. Send on the stop chan can be used to terminate it earlier.
	Run(timeout time.Duration, stop <-chan bool, command string) (outc <-chan []byte, errc <-chan error, err error)

	// Diagnose retrieves additional debugging info from the VM
	// (e.g. by sending some sys-rq's or SIGABORT'ing a Go program).
	//
	// Optionally returns (some or all) of the info directly. If wait == true,
	// the caller must wait for the VM to output info directly to its log.
	//
	// rep describes the reason why Diagnose was called.
	Diagnose(rep *report.Report) (diagnosis []byte, wait bool)

	// Close stops and destroys the VM.
	Close()
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
	Debug     bool
	Config    []byte // json-serialized VM-type-specific config
	KernelSrc string
}

// BootError is returned by Pool.Create when VM does not boot.
type BootError struct {
	Title  string
	Output []byte
}

func MakeBootError(err error, output []byte) error {
	switch err1 := err.(type) {
	case *osutil.VerboseError:
		return BootError{err1.Title, append(err1.Output, output...)}
	default:
		return BootError{err.Error(), output}
	}
}

func (err BootError) Error() string {
	return fmt.Sprintf("%v\n%s", err.Title, err.Output)
}

func (err BootError) BootError() (string, []byte) {
	return err.Title, err.Output
}

// Register registers a new VM type within the package.
func Register(typ string, ctor ctorFunc, allowsOvercommit bool) {
	Types[typ] = Type{
		Ctor:       ctor,
		Overcommit: allowsOvercommit,
	}
}

type Type struct {
	Ctor       ctorFunc
	Overcommit bool
}

type ctorFunc func(env *Env) (Pool, error)

var (
	// Close to interrupt all pending operations in all VMs.
	Shutdown   = make(chan struct{})
	ErrTimeout = errors.New("timeout")

	Types = make(map[string]Type)
)

func Multiplex(cmd *exec.Cmd, merger *OutputMerger, console io.Closer, timeout time.Duration,
	stop, closed <-chan bool, debug bool) (<-chan []byte, <-chan error, error) {
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}
	go func() {
		select {
		case <-time.After(timeout):
			signal(ErrTimeout)
		case <-stop:
			signal(ErrTimeout)
		case <-closed:
			if debug {
				log.Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			cmd.Process.Kill()
			console.Close()
			merger.Wait()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		console.Close()
		merger.Wait()
		cmd.Wait()
	}()
	return merger.Output, errc, nil
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
