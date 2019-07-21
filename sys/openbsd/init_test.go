package openbsd_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/openbsd/gen"
)

func TestSanitizeCall(t *testing.T) {
	target, err := prog.GetTarget("openbsd", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		input  string
		output string
	}{
		{
			`chflagsat(0x0, 0x0, 0x60004, 0x0)`,
			`chflagsat(0x0, 0x0, 0x0, 0x0)`,
		},
		{
			`fchflags(0x0, 0x60004)`,
			`fchflags(0x0, 0x0)`,
		},
		{
			// major=22, minor=232
			`mknodat(0x0, 0x0, 0x0, 0x16e8)`,
			`mknodat(0x0, 0x0, 0x0, 0x202)`,
		},
		{
			// major=22, minor=232
			`mknod(0x0, 0x0, 0x16e8)`,
			`mknod(0x0, 0x0, 0x202)`,
		},
		{
			// major=22, minor=0
			`mknod(0x0, 0x0, 0x1600)`,
			`mknod(0x0, 0x0, 0x1600)`,
		},
		{
			// major=4, minor=0
			`mknod(0x0, 0x0, 0x400)`,
			`mknod(0x0, 0x0, 0x400)`,
		},
		{
			// major=4, minor=1
			`mknod(0x0, 0x0, 0x401)`,
			`mknod(0x0, 0x0, 0x202)`,
		},
		{
			// major=4, minor=2
			`mknod(0x0, 0x0, 0x402)`,
			`mknod(0x0, 0x0, 0x202)`,
		},
		{
			// MCL_CURRENT | MCL_FUTURE
			`mlockall(0x3)`,
			`mlockall(0x1)`,
		},
		{
			// RLIMIT_DATA
			`setrlimit(0x2, &(0x7f0000cc0ff0)={0x0, 0x80000000})`,
			`setrlimit(0x2, &(0x7f0000cc0ff0)={0x60000000, 0x80000000})`,
		},
		{
			// RLIMIT_DATA
			`setrlimit(0x10000000000002, &(0x7f0000cc0ff0)={0x0, 0x80000000})`,
			`setrlimit(0x10000000000002, &(0x7f0000cc0ff0)={0x60000000, 0x80000000})`,
		},
		{
			// RLIMIT_STACK
			`setrlimit(0x3, &(0x7f0000cc0ff0)={0x1000000000, 0x1000000000})`,
			`setrlimit(0x3, &(0x7f0000cc0ff0)={0x100000, 0x100000})`,
		},
		{
			// RLIMIT_CPU
			`setrlimit(0x0, &(0x7f0000cc0ff0)={0x1, 0x1})`,
			`setrlimit(0x0, &(0x7f0000cc0ff0)={0x1, 0x1})`,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.input), prog.Strict)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.TrimSpace(string(p.Serialize()))
			want := strings.TrimSpace(test.output)
			if got != want {
				t.Fatalf("input:\n%v\ngot:\n%v\nwant:\n%s", test.input, got, want)
			}
		})
	}
}
