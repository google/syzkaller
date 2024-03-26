// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var sampleCoverJSON = []byte(`{"file_path":"main.c","func_name":"main",` +
	`"sl":1,"sc":0,"el":1,"ec":-1,"hit_count":1,"inline":false,"pc":12345}`)

func TestWriteCIJSONLine(t *testing.T) {
	expectedJSON :=
		`{"version":1,` +
			`"timestamp":"2014-04-14 00:00:00.000",` +
			`"fuzzing_minutes":360,` +
			`"arch":"x86",` +
			`"build_id":"sample_buildid",` +
			`"manager":"sample_manager",` +
			`"kernel_repo":"sample_repo_path",` +
			`"kernel_branch":"",` +
			`"kernel_commit":"",` +
			`"file_path":"main.c",` +
			`"func_name":"main",` +
			`"sl":1,"sc":0,"el":1,"ec":-1,` +
			`"hit_count":1,` +
			`"inline":false,` +
			`"pc":12345}
`

	covInfo := CoverageInfo{}
	assert.NoError(t, json.Unmarshal(sampleCoverJSON, &covInfo))

	buf := new(bytes.Buffer)
	assert.NoError(t, WriteCIJSONLine(buf, covInfo, CIDetails{
		Version:        1,
		Timestamp:      "2014-04-14 00:00:00.000",
		FuzzingMinutes: 360,
		Arch:           "x86",
		BuildID:        "sample_buildid",
		Manager:        "sample_manager",
		KernelRepo:     "sample_repo_path",
	}))
	assert.Equal(t, expectedJSON, buf.String())
}
