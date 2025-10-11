// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

type SecContextGenerator struct {	
	Sandbox         string
	SandboxArg      int64
	AttachSecLabels bool
}

func (secContextGenerator *SecContextGenerator) getSecLabel() string {
	var secContext string = ""
	if secContextGenerator.AttachSecLabels {
		secContext = "user_u:user_r:user_t:s0"
		if secContextGenerator.Sandbox == "android" {
			if secContextGenerator.SandboxArg == 0 {
				secContext = "u:r:untrusted_app:s0:c512,c768"
			} else {
				secContext = ""
			}
		}
	}
	return secContext
}