// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	bsdBuildMemMB      = 8192
	bsdCompilerIDEntry = "compiler.id"
	defaultMaxOutBytes = 2 << 30 // 2 GiB cap per extracted build artifact.
	vmTypeQemu         = "qemu"
)

type bsdVMBuildSpec struct {
	ScratchGB       int64
	OutTarMB        int64
	Config          []byte
	ExpectedOutputs map[string]string
	BuildScript     string
}

type bsdVMDisks struct {
	outputImage string
	bootImage   string
	bootSSHKey  string
}

// bsdInfraError marks a failure as an infrastructure problem (host tooling, QEMU, disks),
// as opposed to a failure of the kernel build itself. syz-ci does not report such errors
// to the dashboard as kernel build failures and bisection does not treat the commit as broken.
func bsdInfraError(format string, args ...any) error {
	err := fmt.Errorf(format, args...)
	infra := &InfraError{Title: err.Error()}
	if bootErr, ok := errors.AsType[vmimpl.BootError](err); ok {
		// BootError.Error() embeds the whole console output; keep the title short
		// and move the output to the dedicated field.
		infra.Title = strings.TrimSuffix(infra.Title, "\n"+string(bootErr.Output))
		infra.Output = bootErr.Output
	}
	return infra
}

// renderBSDScript renders a guest build script template with named fields, so that
// adding or reordering parameters cannot silently produce a broken script.
func renderBSDScript(tmpl *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render %v: %w", tmpl.Name(), err)
	}
	return buf.String(), nil
}

// bsdVMBuild builds a BSD kernel inside an isolated local QEMU VM (regardless of
// params.VMType, so target images for GCE or QEMU fuzzing are built the same way).
func bsdVMBuild(params Params, spec bsdVMBuildSpec) (ImageDetails, error) {
	if runtime.GOOS != targets.Linux {
		return ImageDetails{}, bsdInfraError("VM-based BSD kernel build is only supported on linux hosts (got %v)",
			runtime.GOOS)
	}
	if params.TargetArch != targets.AMD64 {
		return ImageDetails{}, bsdInfraError("building %v on %v supports only amd64 target (got %v)",
			params.TargetOS, runtime.GOOS, params.TargetArch)
	}
	sysTarget := targets.Get(params.TargetOS, params.TargetArch)
	if sysTarget == nil {
		return ImageDetails{}, bsdInfraError("unsupported target %v/%v", params.TargetOS, params.TargetArch)
	}

	params.KernelDir = osutil.Abs(params.KernelDir)
	params.OutputDir = osutil.Abs(params.OutputDir)

	disks, err := prepareBSDDisks(params.UserspaceDir, params.OutputDir, params.BuilderImage)
	if err != nil {
		return ImageDetails{}, bsdInfraError("%w", err)
	}

	tempParent := params.OutputDir
	if strings.ContainsAny(tempParent, " \t\n") {
		tempParent = ""
	}
	workDir, err := os.MkdirTemp(tempParent, ".bsd-build-*")
	if err != nil {
		return ImageDetails{}, bsdInfraError("failed to create build temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	srcTar := filepath.Join(workDir, "src.tar")
	scratchRaw := filepath.Join(workDir, "scratch.raw")
	outTar := filepath.Join(workDir, "out.tar")
	scriptFile := filepath.Join(workDir, "build.sh")
	configFile := filepath.Join(workDir, "kernel.config")

	t0 := time.Now()
	params.Tracer.Logf("bsd-vm-build: archiving kernel tree %v", params.KernelDir)
	if err := writeKernelSourceTar(srcTar, params.KernelDir); err != nil {
		return ImageDetails{}, bsdInfraError("failed to archive kernel source: %w", err)
	}
	params.Tracer.Logf("bsd-vm-build: source archive created in %v", time.Since(t0).Round(time.Millisecond))

	for _, disk := range []struct {
		path string
		size int64
	}{
		{scratchRaw, spec.ScratchGB << 30},
		{outTar, spec.OutTarMB << 20},
	} {
		if err := os.WriteFile(disk.path, nil, 0600); err != nil {
			return ImageDetails{}, bsdInfraError("%w", err)
		}
		if err := os.Truncate(disk.path, disk.size); err != nil {
			return ImageDetails{}, bsdInfraError("%w", err)
		}
	}
	if err := os.WriteFile(scriptFile, []byte(spec.BuildScript), 0700); err != nil {
		return ImageDetails{}, bsdInfraError("%w", err)
	}
	if err := os.WriteFile(configFile, spec.Config, 0600); err != nil {
		return ImageDetails{}, bsdInfraError("%w", err)
	}

	mgrCfg, err := buildBSDMgrConfig(params, sysTarget, workDir, disks)
	if err != nil {
		return ImageDetails{}, bsdInfraError("%w", err)
	}
	if err := runBSDVM(params, mgrCfg, scriptFile, configFile); err != nil {
		return ImageDetails{}, err
	}
	compilerID, err := extractExpectedTarOutputs(outTar, params.OutputDir, spec.ExpectedOutputs, defaultMaxOutBytes)
	if err != nil {
		return ImageDetails{}, bsdInfraError("failed to extract build outputs: %w", err)
	}
	return ImageDetails{CompilerID: compilerID}, nil
}

func prepareBSDDisks(userspaceDir, outputDir, builderImage string) (bsdVMDisks, error) {
	var d bsdVMDisks
	if userspaceDir == "" {
		return d, fmt.Errorf("userspace dir is not specified")
	}
	info, err := os.Stat(userspaceDir)
	if err != nil {
		return d, fmt.Errorf("failed to stat userspace %v: %w", userspaceDir, err)
	}
	d.outputImage = filepath.Join(outputDir, "image")
	srcImage := userspaceDir
	var outputKey string
	if info.IsDir() {
		srcImage = filepath.Join(userspaceDir, "image")
		if srcKey := filepath.Join(userspaceDir, "key"); osutil.IsExist(srcKey) {
			outputKey = filepath.Join(outputDir, "key")
			if err := osutil.CopyFile(srcKey, outputKey); err != nil {
				return d, fmt.Errorf("failed to copy %v -> %v: %w", srcKey, outputKey, err)
			}
			if err := os.Chmod(outputKey, 0600); err != nil {
				return d, fmt.Errorf("failed to chmod key: %w", err)
			}
		}
	}
	if err := osutil.CopyFile(srcImage, d.outputImage); err != nil {
		return d, fmt.Errorf("failed to copy %v -> %v: %w", srcImage, d.outputImage, err)
	}
	if builderImage != "" {
		d.bootImage = osutil.Abs(builderImage)
	} else {
		d.bootImage = osutil.Abs(srcImage)
		d.bootSSHKey = outputKey
	}
	if strings.ContainsAny(d.bootImage, " \t\n,") {
		return d, fmt.Errorf("boot image path must not contain whitespace or commas: %q", d.bootImage)
	}
	return d, nil
}

func bsdBuildCPUs(buildCPUs int) int {
	return min(max(buildCPUs, 1), 16)
}

func bsdEnsureConfig(params Params, defaultConfig string) ([]byte, error) {
	if len(params.Config) != 0 {
		return params.Config, nil
	}
	config := []byte(defaultConfig)
	if err := osutil.WriteFile(filepath.Join(params.OutputDir, "kernel.config"), config); err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}
	return config, nil
}

func buildBSDMgrConfig(
	params Params, sysTarget *targets.Target, workDir string, disks bsdVMDisks,
) (*mgrconfig.Config, error) {
	availMem, err := osutil.AvailableMemorySize()
	if err != nil {
		return nil, err
	}
	if availMB := availMem >> 20; availMB < bsdBuildMemMB {
		return nil, fmt.Errorf("not enough available memory for build VM: have %v MiB, need %v MiB",
			availMB, bsdBuildMemMB)
	}
	cpus := bsdBuildCPUs(params.BuildCPUs)
	scratchRaw := filepath.Join(workDir, "scratch.raw")
	srcTar := filepath.Join(workDir, "src.tar")
	outTar := filepath.Join(workDir, "out.tar")
	for _, p := range []string{scratchRaw, srcTar, outTar, disks.outputImage} {
		if strings.ContainsAny(p, " \t\n") {
			return nil, fmt.Errorf("QEMU file path must not contain whitespace: %q", p)
		}
	}
	esc := func(p string) string { return strings.ReplaceAll(p, ",", ",,") }
	// Assign deterministic PCI addresses after boot0 (addr=0x6) so bootImage is always
	// probed first (vtbd0/sd0), followed by scratch (vtbd1/sd1), src.tar (vtbd2/sd2),
	// out.tar (vtbd3/sd3), and outputImage (vtbd4/sd4).
	qemuArgs := strings.Join([]string{
		"-enable-kvm", "-cpu", "host,migratable=off",
		"-drive", "id=syz1,if=none,format=raw,file=" + esc(scratchRaw),
		"-device", "virtio-blk-pci,drive=syz1,addr=0x8",
		"-drive", "id=syz2,if=none,format=raw,readonly=on,file=" + esc(srcTar),
		"-device", "virtio-blk-pci,drive=syz2,addr=0x9",
		"-drive", "id=syz3,if=none,format=raw,file=" + esc(outTar),
		"-device", "virtio-blk-pci,drive=syz3,addr=0xa",
		"-drive", "id=syz4,if=none,format=raw,file=" + esc(disks.outputImage),
		"-device", "virtio-blk-pci,drive=syz4,addr=0xb",
	}, " ")
	const imageDev = "device virtio-blk-pci,drive=boot0,addr=0x6,bootindex=0 " +
		"-drive id=boot0,if=none,format=raw,snapshot=on,file="
	vmCfgRaw, err := json.Marshal(map[string]any{
		"count":        1,
		"cpu":          cpus,
		"mem":          bsdBuildMemMB,
		"image_device": imageDev,
		"qemu_args":    qemuArgs,
		"snapshot":     false,
	})
	if err != nil {
		return nil, err
	}
	vmWorkdir := filepath.Join(workDir, "vm")
	if err := osutil.MkdirAll(vmWorkdir); err != nil {
		return nil, err
	}
	params.Tracer.Logf("bsd-vm-build: booting QEMU VM (cpus=%v, mem=%vMiB, builder=%v)",
		cpus, bsdBuildMemMB, disks.bootImage)
	return &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     params.TargetOS,
			TargetArch:   params.TargetArch,
			TargetVMArch: targets.AMD64,
			SysTarget:    sysTarget,
			Timeouts:     sysTarget.Timeouts(1),
		},
		Name:     "bsd-build",
		Type:     vmTypeQemu,
		Workdir:  vmWorkdir,
		Image:    disks.bootImage,
		SSHKey:   disks.bootSSHKey,
		SSHUser:  "root",
		Snapshot: false,
		VM:       vmCfgRaw,
	}, nil
}

func runBSDVM(params Params, mgrCfg *mgrconfig.Config, scriptFile, configFile string) error {
	bootStart := time.Now()
	pool, err := vm.Create(mgrCfg, false)
	if err != nil {
		return bsdInfraError("failed to create build VM pool: %w", err)
	}
	defer pool.Close()

	inst, err := pool.Create(context.Background(), 0)
	if err != nil {
		return bsdInfraError("failed to boot build VM: %w", err)
	}
	defer inst.Close()
	params.Tracer.Logf("bsd-vm-build: VM booted and SSH ready in %v", time.Since(bootStart).Round(time.Millisecond))

	vmScript, err := inst.Copy(scriptFile)
	if err != nil {
		return bsdInfraError("failed to copy build script into VM: %w", err)
	}
	vmConfig, err := inst.Copy(configFile)
	if err != nil {
		return bsdInfraError("failed to copy kernel config into VM: %w", err)
	}

	buildStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
	defer cancel()

	outc, errc, err := inst.RunStream(ctx, fmt.Sprintf("/bin/sh %s %s", vmScript, vmConfig))
	if err != nil {
		return bsdInfraError("failed to start build in VM: %w", err)
	}
	var output bytes.Buffer
	for {
		select {
		case chunk, ok := <-outc:
			if !ok {
				outc = nil
				continue
			}
			output.Write(chunk.Data)
		case runErr := <-errc:
			for len(outc) > 0 {
				output.Write((<-outc).Data)
			}
			outBytes := bytes.ReplaceAll(output.Bytes(), []byte("/build/src/"), []byte(filepath.Clean(params.KernelDir)+"/"))
			params.Tracer.SaveFile("build.log", outBytes)
			if runErr != nil {
				// A non-zero exit of the guest build script (or a build timeout) is attributed
				// to the kernel tree, the same way a failed native make invocation would be.
				return &osutil.VerboseError{Err: runErr, Output: outBytes}
			}
			params.Tracer.Logf("bsd-vm-build: guest build completed in %v", time.Since(buildStart).Round(time.Millisecond))
			return nil
		}
	}
}

// writeKernelSourceTar archives kernelDir into dstPath without dereferencing symlinks
// inside kernelDir or modifying kernelDir.
func writeKernelSourceTar(dstPath, kernelDir string) error {
	root, err := filepath.EvalSymlinks(kernelDir)
	if err != nil {
		return err
	}
	_, err = osutil.RunCmd(10*time.Minute, "", "tar",
		"--anchored", "--exclude=./.git", "--exclude=./obj",
		"-C", root, "-cf", dstPath, ".")
	return err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// extractExpectedTarOutputs safely extracts only the expected regular files in expected
// (archiveName -> relative path under outDir) plus optional compiler.id from outTar.
func extractExpectedTarOutputs(tarPath, outDir string, expected map[string]string, maxFileBytes int64) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	seen := make(map[string]bool, len(expected)+1)
	var compilerID string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("invalid tar stream from guest: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if hdr.Typeflag != tar.TypeReg {
			return "", fmt.Errorf("archive entry %q has non-regular type %v", hdr.Name, hdr.Typeflag)
		}
		if seen[name] {
			return "", fmt.Errorf("duplicate archive entry %q", hdr.Name)
		}
		seen[name] = true
		if name == bsdCompilerIDEntry {
			if hdr.Size < 0 || hdr.Size > 4096 {
				return "", fmt.Errorf("compiler.id size %v out of bounds", hdr.Size)
			}
			idBytes, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
			if err != nil {
				return "", err
			}
			compilerID = strings.TrimSpace(string(idBytes))
			continue
		}
		dstRel, ok := expected[name]
		if !ok {
			return "", fmt.Errorf("unexpected archive entry %q from guest", hdr.Name)
		}
		if hdr.Size < 0 || hdr.Size > maxFileBytes {
			return "", fmt.Errorf("archive entry %q size %v out of bounds [0, %v]", hdr.Name, hdr.Size, maxFileBytes)
		}
		dstPath := filepath.Join(outDir, filepath.FromSlash(dstRel))
		if err := osutil.MkdirAll(filepath.Dir(dstPath)); err != nil {
			return "", err
		}
		if err := writeReaderToFile(dstPath, tr, hdr.Size); err != nil {
			return "", err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(expected)) {
		if !seen[name] {
			return compilerID, fmt.Errorf("missing expected build outputs in guest archive: %v", name)
		}
	}
	return compilerID, nil
}

func writeReaderToFile(dstPath string, r io.Reader, size int64) error {
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(out, r, size)
	return errors.Join(copyErr, out.Close())
}
