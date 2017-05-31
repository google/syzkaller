// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"testing"
)

func TestUnknown(t *testing.T) {
	data := `{"foo": "bar"}`
	_, _, err := parse([]byte(data))
	if err == nil || err.Error() != "unknown field 'foo' in config" {
		t.Fatalf("unknown field is not detected (%v)", err)
	}
}

func TestReflectUnknown(t *testing.T) {
	data := `{"http": "localhost:56741","ParsedIgnores": [], "Odroid_Hub_Bus": "bus"}`
	_, _, err := parse([]byte(data))
	if err == nil || err.Error() != "unknown field 'ParsedIgnores' in config" {
		t.Fatalf("unknown field is not detected (%v)", err)
	}
}
