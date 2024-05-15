// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// SetupFeatures enables and does any one-time setup for the requested features on the host.
// Note: this can be called multiple times and must be idempotent.
func SetupFeatures(target *prog.Target, executor string, mask flatrpc.Feature, flags csource.Features) (
	[]*flatrpc.FeatureInfo, error) {
	if noHostChecks(target) {
		return nil, nil
	}
	var results []*flatrpc.FeatureInfo
	resultC := make(chan *flatrpc.FeatureInfo)
	for feat := range flatrpc.EnumNamesFeature {
		feat := feat
		if mask&feat == 0 {
			continue
		}
		opt := ipc.FlatRPCFeaturesToCSource[feat]
		if opt != "" && flags != nil && !flags["binfmt_misc"].Enabled {
			continue
		}
		results = append(results, nil)
		go setupFeature(executor, feat, resultC)
	}
	// Feature 0 setups common things that are not part of any feature.
	setupFeature(executor, 0, nil)
	for i := range results {
		results[i] = <-resultC
	}
	return results, nil
}

func setupFeature(executor string, feat flatrpc.Feature, resultC chan *flatrpc.FeatureInfo) {
	args := strings.Split(executor, " ")
	executor = args[0]
	args = append(args[1:], "setup", fmt.Sprint(uint64(feat)))
	output, err := osutil.RunCmd(3*time.Minute, "", executor, args...)
	log.Logf(1, "executor %v\n%s", args, bytes.ReplaceAll(output, []byte("SYZFAIL:"), nil))
	outputStr := string(output)
	if err == nil {
		outputStr = ""
	} else if outputStr == "" {
		outputStr = err.Error()
	}
	needSetup := true
	if strings.Contains(outputStr, "feature setup is not needed") {
		needSetup = false
		outputStr = ""
	}
	if resultC != nil {
		resultC <- &flatrpc.FeatureInfo{
			Id:        feat,
			NeedSetup: needSetup,
			Reason:    outputStr,
		}
	}
}

func noHostChecks(target *prog.Target) bool {
	// HostFuzzer targets can't run Go binaries on the targets,
	// so we actually run on the host on another OS. The same for targets.TestOS OS.
	return targets.Get(target.OS, target.Arch).HostFuzzer || target.OS == targets.TestOS
}
