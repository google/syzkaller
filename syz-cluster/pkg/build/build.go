// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package build provides kernel building logic for syz-cluster workflow steps and local tools.
package build

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	pkgbuild "github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

const (
	defaultConfigDir    = "/kernel-configs"
	defaultUserspaceDir = "/disk-images/buildroot_amd64_2024.09" // See the Dockerfile.
	symbolHashesFile    = "symbol_hashes.json"
)

// Params defines the configuration for a kernel build.
type Params struct {
	Req          *api.BuildRequest
	KernelDir    string
	OutputDir    string
	ConfigDir    string
	UserspaceDir string
	Ccache       string
	Tracer       debugtracer.DebugTracer
}

// Result contains the outcome and metadata of a kernel build.
type Result struct {
	Config   []byte
	Compiler string
	Success  bool
	Report   []byte
	Log      []byte
	// Symbols holds the ELF symbol hashes of a successful build (also saved to OutputDir).
	// It's empty if the build failed or the hashes could not be extracted.
	Symbols pkgbuild.SectionHashes
}

// Run builds the kernel image and extracts symbol hashes into OutputDir.
// OutputDir has the following structure:
//
//	|-- image
//	|-- symbol_hashes.json
//	|-- kernel
//	|-- kernel.config
//	`-- obj/vmlinux
func Run(params *Params) (*Result, error) {
	configDir := params.ConfigDir
	if configDir == "" {
		configDir = defaultConfigDir
	}
	userspaceDir := params.UserspaceDir
	if userspaceDir == "" {
		userspaceDir = defaultUserspaceDir
	}
	tracer := params.Tracer
	if tracer == nil {
		tracer = &debugtracer.NullTracer{}
	}
	req := params.Req

	kernelConfig, err := os.ReadFile(filepath.Join(configDir, req.ConfigName))
	if err != nil {
		return nil, fmt.Errorf("failed to read the kernel config: %w", err)
	}
	parsed, err := kconfig.ParseConfigData(kernelConfig, req.ConfigName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kernel config: %w", err)
	}
	for _, cfg := range req.EnableConfigs {
		parsed.Set(cfg, kconfig.Yes)
	}
	// Syzkaller builds bzImage/vmlinux and does not build or load .ko modules.
	// Convert all module (=m) configs to built-in (=y) so tristate dependencies
	// do not downgrade required configs back to =m during make oldconfig.
	parsed.ModToYes()
	kernelConfig = parsed.Serialize()
	if req.Arch != "amd64" {
		// TODO: lift this restriction.
		return nil, fmt.Errorf("only amd64 builds are supported now")
	}
	buildParams := pkgbuild.Params{
		TargetOS:     targets.Linux,
		TargetArch:   req.Arch,
		VMType:       "qemu", // TODO: support others.
		KernelDir:    params.KernelDir,
		OutputDir:    params.OutputDir,
		Compiler:     "clang",
		Linker:       "ld.lld",
		Ccache:       params.Ccache,
		UserspaceDir: userspaceDir,
		Config:       kernelConfig,
		Tracer:       tracer,
	}
	tracer.Logf("started build: %q", req)
	info, err := pkgbuild.Image(buildParams)
	tracer.Logf("compiler: %q", info.CompilerID)
	tracer.Logf("signature: %q", info.Signature)
	// We can fill this regardless of whether it succeeded.
	ret := &Result{
		Compiler: info.CompilerID,
	}
	ret.Config, _ = os.ReadFile(filepath.Join(params.OutputDir, "kernel.config"))
	if err != nil {
		var kernelError *pkgbuild.KernelError
		var verboseError *osutil.VerboseError
		switch {
		case errors.As(err, &kernelError):
			tracer.Logf("kernel error: %q / %s", kernelError.Report, kernelError.Output)
			ret.Report = kernelError.Report
			ret.Log = kernelError.Output
			return ret, nil
		case errors.As(err, &verboseError):
			tracer.Logf("verbose error: %s / %s", verboseError, verboseError.Output)
			ret.Report = []byte(verboseError.Error())
			ret.Log = verboseError.Output
			return ret, nil
		default:
			tracer.Logf("other error: %v", err)
		}
		return nil, fmt.Errorf("image build failed: %w", err)
	}
	ret.Success = true
	tracer.Logf("build finished successfully")

	ret.Symbols, err = saveSymbolHashes(tracer, params.KernelDir, params.OutputDir)
	if err != nil {
		tracer.Logf("failed to save symbol hashes: %s", err)
	}
	return ret, nil
}

// saveSymbolHashes extracts the ELF symbol hashes and saves them to outputDir.
// The extracted hashes are returned even if they could not be saved.
func saveSymbolHashes(tracer debugtracer.DebugTracer, kernelDir, outputDir string) (pkgbuild.SectionHashes, error) {
	hashes, err := pkgbuild.ElfSymbolHashes(filepath.Join(kernelDir, "vmlinux.o"))
	if err != nil {
		return pkgbuild.SectionHashes{}, fmt.Errorf("failed to query symbol hashes: %w", err)
	}
	tracer.Logf("extracted hashes for %d text symbols and %d data symbols",
		len(hashes.Text), len(hashes.Data))
	file, err := os.Create(filepath.Join(outputDir, symbolHashesFile))
	if err != nil {
		return hashes, fmt.Errorf("failed to open %s: %w", symbolHashesFile, err)
	}
	defer file.Close()
	err = json.NewEncoder(file).Encode(hashes)
	if err != nil {
		return hashes, fmt.Errorf("failed to serialize: %w", err)
	}
	return hashes, nil
}

// ReadSymbolHashes loads the ELF symbol hashes saved in buildDir during Run.
func ReadSymbolHashes(buildDir string) (pkgbuild.SectionHashes, error) {
	f, err := os.Open(filepath.Join(buildDir, symbolHashesFile))
	if err != nil {
		return pkgbuild.SectionHashes{}, fmt.Errorf("failed to open %s: %w", symbolHashesFile, err)
	}
	defer f.Close()

	var data pkgbuild.SectionHashes
	err = json.NewDecoder(f).Decode(&data)
	if err != nil {
		return pkgbuild.SectionHashes{}, fmt.Errorf("failed to decode %s: %w", symbolHashesFile, err)
	}
	return data, nil
}
