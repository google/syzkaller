package openbsd_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/openbsd/gen"
)

func TestSanitizeMknodCall(t *testing.T) {
	target, err := prog.GetTarget("openbsd", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		input  string
		output string
	}{
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
