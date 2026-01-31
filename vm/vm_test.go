// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
)

type testPool struct {
}

func (pool *testPool) Count() int {
	return 1
}

func (pool *testPool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	return &testInstance{
		outc: make(chan vmimpl.Chunk, 10),
		errc: make(chan error, 1),
	}, nil
}

func (pool *testPool) Close() error {
	return nil
}

type testInstance struct {
	outc           chan vmimpl.Chunk
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
	outc <-chan vmimpl.Chunk, errc <-chan error, err error) {
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

	inst.outc <- vmimpl.Chunk{Data: diag}
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
	Body           func(outc chan vmimpl.Chunk, errc chan error)
	BodyExecuting  func(outc chan vmimpl.Chunk, errc chan error, inject chan<- bool)
	Report         *report.Report
}

var tests = []*Test{
	{
		Name: "program-exits-normally",
		Exit: ExitNormal,
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			time.Sleep(time.Second)
			errc <- nil
		},
	},
	{
		Name: "program-exits-when-it-should-not",
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			errc <- nil
		},
	},
	{
		Name: "#875-diagnose-bugs-2",
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			outc <- vmimpl.Chunk{Data: []byte("BUG: bad\n")}
			time.Sleep(time.Second)
			outc <- vmimpl.Chunk{Data: []byte("other output\n")}
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			outc <- vmimpl.Chunk{Data: []byte("BUG: bad\n")}
			time.Sleep(time.Second)
			outc <- vmimpl.Chunk{Data: []byte("other output\n")}
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			outc <- vmimpl.Chunk{Data: []byte("BUG: bad\n")}
			outc <- vmimpl.Chunk{Data: []byte(executorPreemptedStr + "\n")}
		},
	},
	{
		Name: "program-exits-but-kernel-crashes-afterwards",
		Exit: ExitNormal,
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			errc <- nil
			time.Sleep(time.Second)
			outc <- vmimpl.Chunk{Data: []byte("BUG: bad\n")}
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			errc <- vmimpl.ErrTimeout
		},
	},
	{
		Name: "bad-timeout",
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			errc <- vmimpl.ErrTimeout
		},
		Report: &report.Report{
			Title: timeoutCrash,
		},
	},
	{
		Name: "program-crashes",
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
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
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			errc <- fmt.Errorf("error")
		},
	},
	{
		Name: "no-output-1",
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
		},
		Report: &report.Report{
			Title: noOutputCrash,
		},
	},
	{
		Name: "no-output-2",
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			for i := 0; i < 5; i++ {
				time.Sleep(time.Second)
				outc <- vmimpl.Chunk{Data: []byte("something\n")}
			}
		},
		Report: &report.Report{
			Title: noOutputCrash,
		},
	},
	{
		Name: "no-no-output",
		Exit: ExitNormal,
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			for i := 0; i < 5; i++ {
				time.Sleep(time.Second)
				outc <- vmimpl.Chunk{Data: []byte(executedProgramsStart + "\n")}
			}
			errc <- nil
		},
	},
	{
		Name: "outc-closed",
		Exit: ExitTimeout,
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			close(outc)
			time.Sleep(time.Second)
			errc <- vmimpl.ErrTimeout
		},
	},
	{
		Name: "lots-of-output",
		Exit: ExitTimeout,
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
			for i := 0; i < 100; i++ {
				outc <- vmimpl.Chunk{Data: []byte("something\n")}
			}
			time.Sleep(time.Second)
			errc <- vmimpl.ErrTimeout
		},
	},
	{
		Name: "split-line",
		Exit: ExitNormal,
		Body: func(outc chan vmimpl.Chunk, errc chan error) {
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
				outc <- vmimpl.Chunk{Data: output[i : i+1]}
			}
			errc <- nil
		},
	},
	{
		Name: "inject-executing",
		Exit: ExitNormal,
		BodyExecuting: func(outc chan vmimpl.Chunk, errc chan error, inject chan<- bool) {
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
		test.BodyExecuting = func(outc chan vmimpl.Chunk, errc chan error, inject chan<- bool) {
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

func TestExtractMultipleErrors(t *testing.T) {
	inst, reporter := makeLinuxAMD64Futex(t)
	mon := &monitor{
		RunOptions: &RunOptions{},
		inst:       inst,
		reporter:   reporter,
		output:     []byte(validKASANReport + strings.Repeat(someLine, 10) + validKASANReport),
	}
	reps := mon.extractErrors("unknown error")
	assert.Len(t, reps, 2, "expected to see 2 reports, got %v", len(reps))
	assert.Equal(t, reps[0].Title, reps[1].Title)
	assert.False(t, reps[0].Corrupted)
	assert.False(t, reps[1].Corrupted)
}

const someLine = "[   96.999999] some message \n"
const validKASANReport = `
[   96.262735] BUG: KASAN: double-free or invalid-free in selinux_tun_dev_free_security+0x15/0x20
[   96.271481] 
[   96.273098] CPU: 0 PID: 11514 Comm: syz-executor5 Not tainted 4.12.0-rc7+ #2
[   96.280268] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   96.289602] Call Trace:
[   96.292180]  dump_stack+0x194/0x257
[   96.295796]  ? arch_local_irq_restore+0x53/0x53
[   96.300454]  ? load_image_and_restore+0x10f/0x10f
[   96.305299]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.310565]  print_address_description+0x7f/0x260
[   96.315393]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.320656]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.325919]  kasan_report_double_free+0x55/0x80
[   96.330577]  kasan_slab_free+0xa0/0xc0
[   96.334450]  kfree+0xd3/0x260
[   96.337545]  selinux_tun_dev_free_security+0x15/0x20
[   96.342636]  security_tun_dev_free_security+0x48/0x80
[   96.347822]  __tun_chr_ioctl+0x2cc1/0x3d60
[   96.352054]  ? tun_chr_close+0x60/0x60
[   96.355925]  ? lock_downgrade+0x990/0x990
[   96.360059]  ? lock_release+0xa40/0xa40
[   96.364025]  ? __lock_is_held+0xb6/0x140
[   96.368213]  ? check_same_owner+0x320/0x320
[   96.372530]  ? tun_chr_compat_ioctl+0x30/0x30
[   96.377005]  tun_chr_ioctl+0x2a/0x40
[   96.380701]  ? tun_chr_ioctl+0x2a/0x40
[   96.385099]  do_vfs_ioctl+0x1b1/0x15c0
[   96.388981]  ? ioctl_preallocate+0x2d0/0x2d0
[   96.393378]  ? selinux_capable+0x40/0x40
[   96.397430]  ? SyS_futex+0x2b0/0x3a0
[   96.401147]  ? security_file_ioctl+0x89/0xb0
[   96.405547]  SyS_ioctl+0x8f/0xc0
[   96.408912]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.413651] RIP: 0033:0x4512c9
[   96.416824] RSP: 002b:00007fc65827bc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
[   96.424603] RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
[   96.431863] RDX: 000000002053c000 RSI: 00000000400454ca RDI: 0000000000000005
[   96.439133] RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
[   96.446389] R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004baa97
[   96.453647] R13: 00000000ffffffff R14: 0000000020124ff3 R15: 0000000000000000
[   96.460931] 
[   96.462552] Allocated by task 11514:
[   96.466258]  save_stack_trace+0x16/0x20
[   96.470212]  save_stack+0x43/0xd0
[   96.473649]  kasan_kmalloc+0xaa/0xd0
[   96.477347]  kmem_cache_alloc_trace+0x101/0x6f0
[   96.481995]  selinux_tun_dev_alloc_security+0x49/0x170
[   96.487250]  security_tun_dev_alloc_security+0x6d/0xa0
[   96.492508]  __tun_chr_ioctl+0x16bc/0x3d60
[   96.496722]  tun_chr_ioctl+0x2a/0x40
[   96.500417]  do_vfs_ioctl+0x1b1/0x15c0
[   96.504282]  SyS_ioctl+0x8f/0xc0
[   96.507630]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.512367] 
[   96.513973] Freed by task 11514:
[   96.517323]  save_stack_trace+0x16/0x20
[   96.521276]  save_stack+0x43/0xd0
[   96.524709]  kasan_slab_free+0x6e/0xc0
[   96.528577]  kfree+0xd3/0x260
[   96.531666]  selinux_tun_dev_free_security+0x15/0x20
[   96.536747]  security_tun_dev_free_security+0x48/0x80
[   96.541918]  tun_free_netdev+0x13b/0x1b0
[   96.545959]  register_netdevice+0x8d0/0xee0
[   96.550260]  __tun_chr_ioctl+0x1bae/0x3d60
[   96.554475]  tun_chr_ioctl+0x2a/0x40
[   96.558169]  do_vfs_ioctl+0x1b1/0x15c0
[   96.562035]  SyS_ioctl+0x8f/0xc0
[   96.565385]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.570116] 
[   96.571724] The buggy address belongs to the object at ffff8801d5961a40
[   96.571724]  which belongs to the cache kmalloc-32 of size 32
[   96.584186] The buggy address is located 0 bytes inside of
[   96.584186]  32-byte region [ffff8801d5961a40, ffff8801d5961a60)
[   96.595775] The buggy address belongs to the page:
[   96.600686] page:ffffea00066b8d38 count:1 mapcount:0 mapping:ffff8801d5961000 index:0xffff8801d5961fc1
[   96.610118] flags: 0x200000000000100(slab)
[   96.614335] raw: 0200000000000100 ffff8801d5961000 ffff8801d5961fc1 000000010000003f
[   96.622292] raw: ffffea0006723300 ffffea00066738b8 ffff8801dbc00100
[   96.628675] page dumped because: kasan: bad access detected
[   96.634373] 
[   96.635978] Memory state around the buggy address:
[   96.640884]  ffff8801d5961900: 00 00 01 fc fc fc fc fc 00 00 00 fc fc fc fc fc
[   96.648222]  ffff8801d5961980: 00 00 00 00 fc fc fc fc fb fb fb fb fc fc fc fc
[   96.655567] >ffff8801d5961a00: 00 00 00 fc fc fc fc fc fb fb fb fb fc fc fc fc
[   96.663255]                                            ^
[   96.668685]  ffff8801d5961a80: fb fb fb fb fc fc fc fc 00 00 00 fc fc fc fc fc
[   96.676022]  ffff8801d5961b00: 04 fc fc fc fc fc fc fc fb fb fb fb fc fc fc fc
[   96.683357] ==================================================================
[   96.690692] Disabling lock debugging due to kernel taint
[   96.696117] Kernel panic - not syncing: panic_on_warn set ...
[   96.696117] 
[   96.703470] CPU: 0 PID: 11514 Comm: syz-executor5 Tainted: G    B           4.12.0-rc7+ #2
[   96.711847] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   96.721354] Call Trace:
[   96.723926]  dump_stack+0x194/0x257
[   96.727539]  ? arch_local_irq_restore+0x53/0x53
[   96.732366]  ? kasan_end_report+0x32/0x50
[   96.736497]  ? lock_downgrade+0x990/0x990
[   96.740631]  panic+0x1e4/0x3fb
[   96.743807]  ? percpu_up_read_preempt_enable.constprop.38+0xae/0xae
[   96.750194]  ? add_taint+0x40/0x50
[   96.753723]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.758976]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.764233]  kasan_end_report+0x50/0x50
[   96.768192]  kasan_report_double_free+0x72/0x80
[   96.772843]  kasan_slab_free+0xa0/0xc0
[   96.776711]  kfree+0xd3/0x260
[   96.779802]  selinux_tun_dev_free_security+0x15/0x20
[   96.784886]  security_tun_dev_free_security+0x48/0x80
[   96.790061]  __tun_chr_ioctl+0x2cc1/0x3d60
[   96.794285]  ? tun_chr_close+0x60/0x60
[   96.798152]  ? lock_downgrade+0x990/0x990
[   96.802803]  ? lock_release+0xa40/0xa40
[   96.806763]  ? __lock_is_held+0xb6/0x140
[   96.810829]  ? check_same_owner+0x320/0x320
[   96.815137]  ? tun_chr_compat_ioctl+0x30/0x30
[   96.819611]  tun_chr_ioctl+0x2a/0x40
[   96.823306]  ? tun_chr_ioctl+0x2a/0x40
[   96.827181]  do_vfs_ioctl+0x1b1/0x15c0
[   96.831057]  ? ioctl_preallocate+0x2d0/0x2d0
[   96.835450]  ? selinux_capable+0x40/0x40
[   96.839494]  ? SyS_futex+0x2b0/0x3a0
[   96.843200]  ? security_file_ioctl+0x89/0xb0
[   96.847590]  SyS_ioctl+0x8f/0xc0
[   96.850941]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.855676] RIP: 0033:0x4512c9
[   96.859020] RSP: 002b:00007fc65827bc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
[   96.866708] RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
[   96.873956] RDX: 000000002053c000 RSI: 00000000400454ca RDI: 0000000000000005
[   96.881208] RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
[   96.888461] R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004baa97
[   96.895708] R13: 00000000ffffffff R14: 0000000020124ff3 R15: 0000000000000000
[   96.903943] Dumping ftrace buffer:
[   96.907460]    (ftrace buffer empty)
[   96.911148] Kernel Offset: disabled
`
