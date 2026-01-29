// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

type testPool struct {
}

func (pool *testPool) Count() int {
	return 1
}

func (pool *testPool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	return &testInstance{
		outc: make(chan []byte, 10),
		errc: make(chan error, 1),
	}, nil
}

func (pool *testPool) Close() error {
	return nil
}

type testInstance struct {
	outc           chan []byte
	errc           chan error
	diagnoseBug    bool
	diagnoseNoWait bool
}

func (inst *testInstance) Copy(hostSrc string) (string, error) {
	return "", nil
}

func (inst *testInstance) Forward(port int) (string, error) {
	return "", nil
}

func (inst *testInstance) Run(ctx context.Context, command string) (
	outc <-chan []byte, errc <-chan error, err error) {
	return inst.outc, inst.errc, nil
}

func (inst *testInstance) Diagnose(rep *report.Report) ([]byte, bool) {
	var diag []byte
	if inst.diagnoseBug {
		diag = []byte("BUG: DIAGNOSE\n")
	} else {
		diag = []byte("DIAGNOSE\n")
	}

	if inst.diagnoseNoWait {
		return diag, false
	}

	inst.outc <- diag
	return nil, true
}

func (inst *testInstance) Close() error {
	return nil
}

func init() {
	vmimpl.WaitForOutputTimeout = 3 * time.Second
	ctor := func(env *vmimpl.Env) (vmimpl.Pool, error) {
		return &testPool{}, nil
	}
	vmimpl.Register("test", vmimpl.Type{
		Ctor:        ctor,
		Preemptible: true,
	})
}

func withTestRunOptionsDefaults() func(*RunOptions) {
	return func(opts *RunOptions) {
		opts.beforeContext = maxErrorLength + 100
		opts.tickerPeriod = 1 * time.Second
	}
}

type Test struct {
	Name           string
	Exit           ExitCondition
	DiagnoseBug    bool // Diagnose produces output that is detected as kernel crash.
	DiagnoseNoWait bool // Diagnose returns output directly rather than to console.
	Body           func(outc chan []byte, errc chan error)
	BodyExecuting  func(outc chan []byte, errc chan error, inject chan<- bool)
	Report         *report.Report
}

var tests = []*Test{
	{
		Name: "program-exits-normally",
		Exit: ExitNormal,
		Body: func(outc chan []byte, errc chan error) {
			time.Sleep(time.Second)
			errc <- nil
		},
	},
	{
		Name: "program-exits-when-it-should-not",
		Body: func(outc chan []byte, errc chan error) {
			time.Sleep(time.Second)
			errc <- nil
		},
		Report: &report.Report{
			Title: lostConnectionCrash,
			Type:  crash.LostConnection,
		},
	},
	{
		Name:        "#875-diagnose-bugs",
		Exit:        ExitNormal,
		DiagnoseBug: true,
		Body: func(outc chan []byte, errc chan error) {
			errc <- nil
		},
	},
	{
		Name: "#875-diagnose-bugs-2",
		Body: func(outc chan []byte, errc chan error) {
			errc <- nil
		},
		Report: &report.Report{
			Title: lostConnectionCrash,
			Output: []byte(
				"DIAGNOSE\n",
			),
			Type: crash.LostConnection,
		},
	},
	{
		Name: "diagnose-no-wait",
		Body: func(outc chan []byte, errc chan error) {
			errc <- nil
		},
		DiagnoseNoWait: true,
		Report: &report.Report{
			Title: lostConnectionCrash,
			Output: []byte(
				"\n" +
					"VM DIAGNOSIS:\n" +
					"DIAGNOSE\n",
			),
			Type: crash.LostConnection,
		},
	},
	{
		Name: "diagnose-bug-no-wait",
		Body: func(outc chan []byte, errc chan error) {
			outc <- []byte("BUG: bad\n")
			time.Sleep(time.Second)
			outc <- []byte("other output\n")
		},
		DiagnoseNoWait: true,
		Report: &report.Report{
			Title: "BUG: bad",
			Report: []byte(
				"BUG: bad\n" +
					"other output\n",
			),
			Output: []byte(
				"BUG: bad\n" +
					"other output\n" +
					"\n" +
					"VM DIAGNOSIS:\n" +
					"DIAGNOSE\n",
			),
		},
	},
	{
		Name: "kernel-crashes",
		Body: func(outc chan []byte, errc chan error) {
			outc <- []byte("BUG: bad\n")
			time.Sleep(time.Second)
			outc <- []byte("other output\n")
		},
		Report: &report.Report{
			Title: "BUG: bad",
			Report: []byte(
				"BUG: bad\n" +
					"DIAGNOSE\n" +
					"other output\n",
			),
		},
	},
	{
		Name: "fuzzer-is-preempted",
		Body: func(outc chan []byte, errc chan error) {
			outc <- []byte("BUG: bad\n")
			outc <- []byte(executorPreemptedStr + "\n")
		},
	},
	{
		Name: "program-exits-but-kernel-crashes-afterwards",
		Exit: ExitNormal,
		Body: func(outc chan []byte, errc chan error) {
			errc <- nil
			time.Sleep(time.Second)
			outc <- []byte("BUG: bad\n")
		},
		Report: &report.Report{
			Title: "BUG: bad",
			Report: []byte(
				"BUG: bad\n" +
					"DIAGNOSE\n",
			),
		},
	},
	{
		Name: "timeout",
		Exit: ExitTimeout,
		Body: func(outc chan []byte, errc chan error) {
			errc <- vmimpl.ErrTimeout
		},
	},
	{
		Name: "bad-timeout",
		Body: func(outc chan []byte, errc chan error) {
			errc <- vmimpl.ErrTimeout
		},
		Report: &report.Report{
			Title: timeoutCrash,
		},
	},
	{
		Name: "program-crashes",
		Body: func(outc chan []byte, errc chan error) {
			errc <- fmt.Errorf("error")
		},
		Report: &report.Report{
			Title: lostConnectionCrash,
			Type:  crash.LostConnection,
		},
	},
	{
		Name: "program-crashes-expected",
		Exit: ExitError,
		Body: func(outc chan []byte, errc chan error) {
			errc <- fmt.Errorf("error")
		},
	},
	{
		Name: "no-output-1",
		Body: func(outc chan []byte, errc chan error) {
		},
		Report: &report.Report{
			Title: noOutputCrash,
		},
	},
	{
		Name: "no-output-2",
		Body: func(outc chan []byte, errc chan error) {
			for i := 0; i < 5; i++ {
				time.Sleep(time.Second)
				outc <- []byte("something\n")
			}
		},
		Report: &report.Report{
			Title: noOutputCrash,
		},
	},
	{
		Name: "no-no-output",
		Exit: ExitNormal,
		Body: func(outc chan []byte, errc chan error) {
			for i := 0; i < 5; i++ {
				time.Sleep(time.Second)
				outc <- []byte(executedProgramsStart + "\n")
			}
			errc <- nil
		},
	},
	{
		Name: "outc-closed",
		Exit: ExitTimeout,
		Body: func(outc chan []byte, errc chan error) {
			close(outc)
			time.Sleep(time.Second)
			errc <- vmimpl.ErrTimeout
		},
	},
	{
		Name: "lots-of-output",
		Exit: ExitTimeout,
		Body: func(outc chan []byte, errc chan error) {
			for i := 0; i < 100; i++ {
				outc <- []byte("something\n")
			}
			time.Sleep(time.Second)
			errc <- vmimpl.ErrTimeout
		},
	},
	{
		Name: "split-line",
		Exit: ExitNormal,
		Body: func(outc chan []byte, errc chan error) {
			// "ODEBUG:" lines should be ignored, however the curPos logic
			// used to trim the lines so that we could see just "BUG:" later
			// and detect it as crash.
			buf := new(bytes.Buffer)
			for i := 0; i < 50; i++ {
				buf.WriteString("[ 2886.597572] ODEBUG: Out of memory. ODEBUG disabled\n")
				buf.Write(bytes.Repeat([]byte{'-'}, i))
				buf.WriteByte('\n')
			}
			output := buf.Bytes()
			for i := range output {
				outc <- output[i : i+1]
			}
			errc <- nil
		},
	},
	{
		Name: "inject-executing",
		Exit: ExitNormal,
		BodyExecuting: func(outc chan []byte, errc chan error, inject chan<- bool) {
			for i := 0; i < 6; i++ {
				time.Sleep(time.Second)
				inject <- true
			}
			errc <- nil
		},
	},
}

func TestMonitorExecution(t *testing.T) {
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			testMonitorExecution(t, test)
		})
	}
}

func makeLinuxAMD64Futex(t *testing.T) (*Instance, *report.Reporter) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetArch:   targets.AMD64,
			TargetVMArch: targets.AMD64,
			Timeouts: targets.Timeouts{
				Scale:    1,
				Slowdown: 1,
				NoOutput: 5 * time.Second,
			},
			SysTarget: targets.Get(targets.Linux, targets.AMD64),
		},
		Workdir: t.TempDir(),
		Type:    "test",
	}
	pool, err := Create(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := pool.Create(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inst.Close() })
	return inst, reporter
}

func testMonitorExecution(t *testing.T, test *Test) {
	inst, reporter := makeLinuxAMD64Futex(t)
	testInst := inst.impl.(*testInstance)
	testInst.diagnoseBug = test.DiagnoseBug
	testInst.diagnoseNoWait = test.DiagnoseNoWait
	done := make(chan bool)
	finishCalled := 0
	var inject chan bool
	injectExecuting := func(opts *RunOptions) {}
	if test.BodyExecuting != nil {
		inject = make(chan bool, 10)
		injectExecuting = WithInjectExecuting(inject)
	} else {
		test.BodyExecuting = func(outc chan []byte, errc chan error, inject chan<- bool) {
			test.Body(outc, errc)
		}
	}
	go func() {
		test.BodyExecuting(testInst.outc, testInst.errc, inject)
		done <- true
	}()
	_, reps, err := inst.Run(context.Background(), reporter, "",
		withTestRunOptionsDefaults(),
		WithExitCondition(test.Exit),
		WithEarlyFinishCb(func() { finishCalled++ }),
		injectExecuting,
	)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if finishCalled != 1 {
		t.Fatalf("finish callback is called %v times", finishCalled)
	}
	if test.Report != nil && len(reps) == 0 {
		t.Fatalf("got no report")
	}
	if test.Report == nil && len(reps) != 0 {
		t.Fatalf("got unexpected report: %v", reps[0].Title)
	}
	if test.Report == nil {
		return
	}
	rep := reps[0]
	if test.Report.Title != rep.Title {
		t.Fatalf("want title %q, got title %q", test.Report.Title, rep.Title)
	}
	if !bytes.Equal(test.Report.Report, rep.Report) {
		t.Fatalf("want report:\n%s\n\ngot report:\n%s", test.Report.Report, rep.Report)
	}
	if test.Report.Output != nil && !bytes.Equal(test.Report.Output, rep.Output) {
		t.Fatalf("want output:\n%s\n\ngot output:\n%s", test.Report.Output, rep.Output)
	}
	if test.Report.Type != rep.Type {
		t.Fatalf("want type %q, got type %q", test.Report.Type, rep.Type)
	}
}

func TestVMType(t *testing.T) {
	testCases := []struct {
		in   string
		want string
	}{
		{targets.GVisor, targets.GVisor},
		{"proxyapp:android", "proxyapp"},
	}

	for _, tc := range testCases {
		if got := vmType(tc.in); got != tc.want {
			t.Errorf("vmType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
