// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
)

type Feature struct {
	Enabled   bool
	NeedSetup bool
	Reason    string
}

type Features map[flatrpc.Feature]Feature

func (features Features) Enabled() flatrpc.Feature {
	var mask flatrpc.Feature
	for feat, info := range features {
		if info.Enabled {
			mask |= feat
		}
	}
	return mask
}

func (features Features) NeedSetup() flatrpc.Feature {
	var mask flatrpc.Feature
	for feat, info := range features {
		if info.Enabled && info.NeedSetup {
			mask |= feat
		}
	}
	return mask
}

type featureResult struct {
	id     flatrpc.Feature
	reason string
}

func (ctx *checkContext) startFeaturesCheck() {
	testProg := ctx.target.DataMmapProg()
	for feat := range flatrpc.EnumNamesFeature {
		if ctx.cfg.Features&feat == 0 {
			ctx.features <- featureResult{feat, "disabled by user"}
			continue
		}
		go func() {
			envFlags, execFlags := ctx.featureToFlags(feat)
			req := &queue.Request{
				Prog:         testProg,
				ReturnOutput: true,
				ReturnError:  true,
				ExecOpts: flatrpc.ExecOpts{
					EnvFlags:   envFlags,
					ExecFlags:  execFlags,
					SandboxArg: ctx.cfg.SandboxArg,
				},
			}
			ctx.executor.Submit(req)
			res := req.Wait(ctx.ctx)
			reason := ctx.featureSucceeded(feat, testProg, res)
			ctx.features <- featureResult{feat, reason}
		}()
	}
}

func (ctx *checkContext) finishFeatures(featureInfos []*flatrpc.FeatureInfo) (Features, error) {
	// Feature checking consists of 2 parts:
	//  - we ask executor to try to setup each feature (results are returned in featureInfos)
	//  - we also try to run a simple program with feature-specific flags
	// Here we combine both results.
	features := make(Features)
	for _, info := range featureInfos {
		features[info.Id] = Feature{
			Reason:    info.Reason,
			NeedSetup: info.NeedSetup,
		}
	}
	outputReplacer := strings.NewReplacer(
		"SYZFAIL:", "",
		"\n", ". ",
	)
	for range flatrpc.EnumNamesFeature {
		res := <-ctx.features
		feat := features[res.id]
		if feat.Reason == "" {
			feat.Reason = res.reason
		}
		if feat.Reason == "" {
			feat.Reason = "enabled"
			feat.Enabled = true
		}
		if pos := strings.Index(feat.Reason, "loop exited with status"); pos != -1 {
			feat.Reason = feat.Reason[:pos]
		}
		// If executor exited the output is prefixed with "executor 4: EOF".
		const executorPrefix = ": EOF\n"
		if pos := strings.Index(feat.Reason, executorPrefix); pos != -1 {
			feat.Reason = feat.Reason[pos+len(executorPrefix):]
		}
		feat.Reason = strings.TrimSpace(outputReplacer.Replace(feat.Reason))
		features[res.id] = feat
	}
	if feat := features[flatrpc.FeatureSandboxNone]; !feat.Enabled {
		return features, fmt.Errorf("execution of simple program fails: %v", feat.Reason)
	}
	if feat := features[flatrpc.FeatureCoverage]; ctx.cfg.Cover && !feat.Enabled {
		return features, fmt.Errorf("coverage is not supported: %v", feat.Reason)
	}
	if feat := features[flatrpc.FeatureMemoryDump]; ctx.cfg.MemoryDump && !feat.Enabled {
		return features, fmt.Errorf("memory dump is not supported: %v", feat.Reason)
	}
	return features, nil
}

// featureToFlags creates ipc flags required to test the feature on a simple program.
// For features that has setup procedure in the executor, we just execute with the default flags.
func (ctx *checkContext) featureToFlags(feat flatrpc.Feature) (flatrpc.ExecEnv, flatrpc.ExecFlag) {
	envFlags := ctx.cfg.Sandbox
	// These don't have a corresponding feature and are always enabled.
	envFlags |= flatrpc.ExecEnvEnableCloseFds | flatrpc.ExecEnvEnableCgroups | flatrpc.ExecEnvEnableNetReset
	execFlags := flatrpc.ExecFlagThreaded
	switch feat {
	case flatrpc.FeatureCoverage:
		envFlags |= flatrpc.ExecEnvSignal
		execFlags |= flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	case flatrpc.FeatureComparisons:
		envFlags |= flatrpc.ExecEnvSignal
		execFlags |= flatrpc.ExecFlagCollectComps
	case flatrpc.FeatureExtraCoverage:
		envFlags |= flatrpc.ExecEnvSignal | flatrpc.ExecEnvExtraCover
		execFlags |= flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	case flatrpc.FeatureDelayKcovMmap:
		envFlags |= flatrpc.ExecEnvSignal | flatrpc.ExecEnvDelayKcovMmap
		execFlags |= flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	case flatrpc.FeatureKcovResetIoctl:
		envFlags |= flatrpc.ExecEnvReadOnlyCoverage
	case flatrpc.FeatureSandboxNone:
		envFlags &= ^ctx.cfg.Sandbox
		envFlags |= flatrpc.ExecEnvSandboxNone
	case flatrpc.FeatureSandboxSetuid:
		envFlags &= ^ctx.cfg.Sandbox
		envFlags |= flatrpc.ExecEnvSandboxSetuid
	case flatrpc.FeatureSandboxNamespace:
		envFlags &= ^ctx.cfg.Sandbox
		envFlags |= flatrpc.ExecEnvSandboxNamespace
	case flatrpc.FeatureSandboxAndroid:
		envFlags &= ^ctx.cfg.Sandbox
		envFlags |= flatrpc.ExecEnvSandboxAndroid
	case flatrpc.FeatureFault:
	case flatrpc.FeatureLeak:
	case flatrpc.FeatureNetInjection:
		envFlags |= flatrpc.ExecEnvEnableTun
	case flatrpc.FeatureNetDevices:
		envFlags |= flatrpc.ExecEnvEnableNetDev
	case flatrpc.FeatureKCSAN:
	case flatrpc.FeatureDevlinkPCI:
		envFlags |= flatrpc.ExecEnvEnableDevlinkPCI
	case flatrpc.FeatureNicVF:
		envFlags |= flatrpc.ExecEnvEnableNicVF
	case flatrpc.FeatureUSBEmulation:
	case flatrpc.FeatureVhciInjection:
		envFlags |= flatrpc.ExecEnvEnableVhciInjection
	case flatrpc.FeatureWifiEmulation:
		envFlags |= flatrpc.ExecEnvEnableWifi
	case flatrpc.FeatureLRWPANEmulation:
	case flatrpc.FeatureBinFmtMisc:
	case flatrpc.FeatureSwap:
	case flatrpc.FeatureMemoryDump:
	default:
		panic(fmt.Sprintf("unknown feature %v", flatrpc.EnumNamesFeature[feat]))
	}
	return envFlags, execFlags
}

// featureSucceeded checks if execution of a simple program with feature-specific flags succeed.
// This generally checks that just all syscalls were executed and succeed,
// for coverage features we also check that we got actual coverage.
func (ctx *checkContext) featureSucceeded(feat flatrpc.Feature, testProg *prog.Prog,
	res *queue.Result) string {
	if res.Status != queue.Success {
		if len(res.Output) != 0 {
			return string(res.Output)
		}
		if res.Err != nil {
			return res.Err.Error()
		}
		return fmt.Sprintf("test program execution failed: status=%v", res.Status)
	}
	if len(res.Info.Calls) != len(testProg.Calls) {
		return fmt.Sprintf("only %v calls are executed out of %v",
			len(res.Info.Calls), len(testProg.Calls))
	}
	for i, call := range res.Info.Calls {
		if call.Error != 0 {
			return fmt.Sprintf("call %v failed with errno %v", i, call.Error)
		}
	}
	call := res.Info.Calls[0]
	switch feat {
	case flatrpc.FeatureCoverage:
		if len(call.Cover) == 0 || len(call.Signal) == 0 {
			return "got no coverage"
		}
	case flatrpc.FeatureComparisons:
		if len(call.Comps) == 0 {
			return "got no coverage"
		}
	}
	return ""
}
