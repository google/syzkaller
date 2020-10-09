// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate ./linux_gen.sh

package build

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type linux struct{}

var _ signer = linux{}

// Key for module signing.
const moduleSigningKey = `-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAxu5GRXw7d13xTLlZ
GT1y63U4Firk3WjXapTgf9radlfzpqheFr5HWO8f11U/euZQWXDzi+Bsq+6s/2lJ
AU9XWQIDAQABAkB24ZxTGBv9iMGURUvOvp83wRRkgvvEqUva4N+M6MAXagav3GRi
K/gl3htzQVe+PLGDfbIkstPJUvI2izL8ZWmBAiEA/P72IitEYE4NQj4dPcYglEYT
Hbh2ydGYFbYxvG19DTECIQDJSvg7NdAaZNd9faE5UIAcLF35k988m9hSqBjtz0tC
qQIgGOJC901mJkrHBxLw8ViBb9QMoUm5dVRGLyyCa9QhDqECIQCQGLX4lP5DVrsY
X43BnMoI4Q3o8x1Uou/JxAIMg1+J+QIgamNCPBLeP8Ce38HtPcm8BXmhPKkpCXdn
uUf4bYtfSSw=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIBvzCCAWmgAwIBAgIUKoM7Idv4nw571nWDgYFpw6I29u0wDQYJKoZIhvcNAQEF
BQAwLjEsMCoGA1UEAwwjQnVpbGQgdGltZSBhdXRvZ2VuZXJhdGVkIGtlcm5lbCBr
ZXkwIBcNMjAxMDA4MTAzMzIwWhgPMjEyMDA5MTQxMDMzMjBaMC4xLDAqBgNVBAMM
I0J1aWxkIHRpbWUgYXV0b2dlbmVyYXRlZCBrZXJuZWwga2V5MFwwDQYJKoZIhvcN
AQEBBQADSwAwSAJBAMbuRkV8O3dd8Uy5WRk9cut1OBYq5N1o12qU4H/a2nZX86ao
Xha+R1jvH9dVP3rmUFlw84vgbKvurP9pSQFPV1kCAwEAAaNdMFswDAYDVR0TAQH/
BAIwADALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFPhQx4etmYw5auCJwIO5QP8Kmrt3
MB8GA1UdIwQYMBaAFPhQx4etmYw5auCJwIO5QP8Kmrt3MA0GCSqGSIb3DQEBBQUA
A0EAK5moCH39eLLn98pBzSm3MXrHpLtOWuu2p696fg/ZjiUmRSdHK3yoRONxMHLJ
1nL9cAjWPantqCm5eoyhj7V7gg==
-----END CERTIFICATE-----`

func (linux linux) build(params *Params) error {
	if err := linux.buildKernel(params); err != nil {
		return err
	}
	if err := linux.createImage(params); err != nil {
		return err
	}
	return nil
}

func (linux linux) sign(params *Params) (string, error) {
	return elfBinarySignature(filepath.Join(params.OutputDir, "obj", "vmlinux"))
}

func (linux) buildKernel(params *Params) error {
	configFile := filepath.Join(params.KernelDir, ".config")
	if err := osutil.WriteFile(configFile, params.Config); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}
	if err := osutil.SandboxChown(configFile); err != nil {
		return err
	}
	// One would expect olddefconfig here, but olddefconfig is not present in v3.6 and below.
	// oldconfig is the same as olddefconfig if stdin is not set.
	// Note: passing in compiler is important since 4.17 (at the very least it's noted in the config).
	if err := runMake(params.KernelDir, "oldconfig", "CC="+params.Compiler); err != nil {
		return err
	}
	// Write updated kernel config early, so that it's captured on build failures.
	outputConfig := filepath.Join(params.OutputDir, "kernel.config")
	if err := osutil.CopyFile(configFile, outputConfig); err != nil {
		return err
	}
	// We build only zImage/bzImage as we currently don't use modules.
	var target string
	switch params.TargetArch {
	case "386", "amd64", "s390x":
		target = "bzImage"
	case "ppc64le":
		target = "zImage"
	}

	ccParam := params.Compiler
	if params.Ccache != "" {
		ccParam = params.Ccache + " " + ccParam
		// Ensure CONFIG_GCC_PLUGIN_RANDSTRUCT doesn't prevent ccache usage.
		// See /Documentation/kbuild/reproducible-builds.rst.
		gccPluginsDir := filepath.Join(params.KernelDir, "scripts", "gcc-plugins")
		if osutil.IsExist(gccPluginsDir) {
			err := osutil.WriteFile(filepath.Join(gccPluginsDir,
				"randomize_layout_seed.h"),
				[]byte("const char *randstruct_seed = "+
					"\"e9db0ca5181da2eedb76eba144df7aba4b7f9359040ee58409765f2bdc4cb3b8\";"))
			if err != nil {
				return err
			}
		}
	}

	// Different key is generated for each build if key is not provided.
	// see Documentation/reproducible-builds.rst. This is causing problems to our signature
	// calculation.
	certsDir := filepath.Join(params.KernelDir, "certs")
	if osutil.IsExist(certsDir) {
		err := osutil.WriteFile(filepath.Join(certsDir, "signing_key.pem"), []byte(moduleSigningKey))
		if err != nil {
			return err
		}
	}
	if err := runMake(params.KernelDir, target, "CC="+ccParam); err != nil {
		return err
	}
	vmlinux := filepath.Join(params.KernelDir, "vmlinux")
	outputVmlinux := filepath.Join(params.OutputDir, "obj", "vmlinux")
	if err := osutil.Rename(vmlinux, outputVmlinux); err != nil {
		return fmt.Errorf("failed to rename vmlinux: %v", err)
	}
	return nil
}

func (linux) createImage(params *Params) error {
	tempDir, err := ioutil.TempDir("", "syz-build")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	scriptFile := filepath.Join(tempDir, "create.sh")
	if err := osutil.WriteExecFile(scriptFile, []byte(createImageScript)); err != nil {
		return fmt.Errorf("failed to write script file: %v", err)
	}

	var kernelImage string
	switch params.TargetArch {
	case "386", "amd64":
		kernelImage = "arch/x86/boot/bzImage"
	case "ppc64le":
		kernelImage = "arch/powerpc/boot/zImage.pseries"
	case "s390x":
		kernelImage = "arch/s390/boot/bzImage"
	}
	kernelImagePath := filepath.Join(params.KernelDir, filepath.FromSlash(kernelImage))
	cmd := osutil.Command(scriptFile, params.UserspaceDir, kernelImagePath, params.TargetArch)
	cmd.Dir = tempDir
	cmd.Env = append([]string{}, os.Environ()...)
	cmd.Env = append(cmd.Env,
		"SYZ_VM_TYPE="+params.VMType,
		"SYZ_CMDLINE_FILE="+osutil.Abs(params.CmdlineFile),
		"SYZ_SYSCTL_FILE="+osutil.Abs(params.SysctlFile),
	)
	if _, err = osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}
	// Note: we use CopyFile instead of Rename because src and dst can be on different filesystems.
	imageFile := filepath.Join(params.OutputDir, "image")
	if err := osutil.CopyFile(filepath.Join(tempDir, "disk.raw"), imageFile); err != nil {
		return err
	}
	keyFile := filepath.Join(params.OutputDir, "key")
	if err := osutil.CopyFile(filepath.Join(tempDir, "key"), keyFile); err != nil {
		return err
	}
	if err := os.Chmod(keyFile, 0600); err != nil {
		return err
	}
	return nil
}

func (linux) clean(kernelDir, targetArch string) error {
	return runMake(kernelDir, "distclean")
}

func runMake(kernelDir string, args ...string) error {
	args = append(args, fmt.Sprintf("-j%v", runtime.NumCPU()))
	cmd := osutil.Command("make", args...)
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return err
	}
	cmd.Dir = kernelDir
	cmd.Env = append([]string{}, os.Environ()...)
	// This makes the build [more] deterministic:
	// 2 builds from the same sources should result in the same vmlinux binary.
	// Build on a release commit and on the previous one should result in the same vmlinux too.
	// We use it for detecting no-op changes during bisection.
	cmd.Env = append(cmd.Env,
		"KBUILD_BUILD_VERSION=0",
		"KBUILD_BUILD_TIMESTAMP=now",
		"KBUILD_BUILD_USER=syzkaller",
		"KBUILD_BUILD_HOST=syzkaller",
		"KERNELVERSION=syzkaller",
		"LOCALVERSION=-syzkaller",
	)
	_, err := osutil.Run(time.Hour, cmd)
	return err
}

// elfBinarySignature calculates signature of an elf binary aiming at runtime behavior
// (text/data, debug info is ignored).
func elfBinarySignature(bin string) (string, error) {
	f, err := os.Open(bin)
	if err != nil {
		return "", fmt.Errorf("failed to open binary for signature: %v", err)
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("failed to open elf binary: %v", err)
	}
	hasher := sha256.New()
	for _, sec := range ef.Sections {
		// Hash allocated sections (e.g. no debug info as it's not allocated)
		// with file data (e.g. no bss). We also ignore .notes section as it
		// contains some small changing binary blob that seems irrelevant.
		// It's unclear if it's better to check NOTE type,
		// or ".notes" name or !PROGBITS type.
		if sec.Flags&elf.SHF_ALLOC == 0 || sec.Type == elf.SHT_NOBITS || sec.Type == elf.SHT_NOTE {
			continue
		}
		io.Copy(hasher, sec.Open())
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
