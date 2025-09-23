// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

type SecContextGenerator struct {	
	Sandbox         string
	SandboxArg      int64
	SecContexts     []string
}

func (secContextGenerator *SecContextGenerator) getSecLabel() string {
	var secContext string = ""
	if len(secContextGenerator.SecContexts) != 0 {
		secContext = secContextGenerator.SecContexts[0]
	}
	return secContext
}