// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
	"testing"
)

func InitTargetTest(t *testing.T, os, arch string) *Target {
	t.Parallel()
	target, err := GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

type DeserializeTest struct {
	In        string
	Out       string // if not set, equals to In
	Err       string
	StrictErr string // if not set, equals to Err
}

func TestDeserializeHelper(t *testing.T, OS, arch string, transform func(*Target, *Prog), tests []DeserializeTest) {
	target := InitTargetTest(t, OS, arch)
	buf := make([]byte, ExecBufferSize)
	for testidx, test := range tests {
		t.Run(fmt.Sprint(testidx), func(t *testing.T) {
			if test.StrictErr == "" {
				test.StrictErr = test.Err
			}
			if test.Err != "" && test.Out != "" {
				t.Errorf("both Err and Out are set")
			}
			if test.In == test.Out {
				t.Errorf("In and Out are equal, remove Out in such case\n%v", test.In)
			}
			if test.Out == "" {
				test.Out = test.In
			}
			for _, mode := range []DeserializeMode{NonStrict, Strict} {
				p, err := target.Deserialize([]byte(test.In), mode)
				wantErr := test.Err
				if mode == Strict {
					wantErr = test.StrictErr
				}
				if err != nil {
					if wantErr == "" {
						t.Fatalf("deserialization failed with\n%s\ndata:\n%s\n",
							err, test.In)
					}
					if !strings.Contains(err.Error(), wantErr) {
						t.Fatalf("deserialization failed with\n%s\nwhich doesn't match\n%s\ndata:\n%s",
							err, wantErr, test.In)
					}
				} else {
					if wantErr != "" {
						t.Fatalf("deserialization should have failed with:\n%s\ndata:\n%s\n",
							wantErr, test.In)
					}
					if transform != nil {
						transform(target, p)
					}
					output := strings.TrimSpace(string(p.Serialize()))
					want := strings.TrimSpace(test.Out)
					if want != output {
						t.Fatalf("wrong serialized data:\n%s\nexpect:\n%s\n", output, want)
					}
					p.SerializeForExec(buf)
				}
			}
		})
	}
}
