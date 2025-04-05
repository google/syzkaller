// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
)

type android struct{}

type BuildParams struct {
	BuildScript      string   `json:"build_script"`
	EnvVars          []string `json:"env_vars"`
	Flags            []string `json:"flags"`
	AdditionalImages []string `json:"additional_images"`
	AutoconfPath     string   `json:"autoconf_path"`
	ConfigPath       string   `json:"config_path"`
}

var ccCompilerRegexp = regexp.MustCompile(`#define\s+CONFIG_CC_VERSION_TEXT\s+"(.*)"`)

func parseConfig(conf []byte) (*BuildParams, error) {
	buildCfg := new(BuildParams)
	if err := config.LoadData(conf, buildCfg); err != nil {
		return nil, fmt.Errorf("failed to parse build config: %w", err)
	}

	if buildCfg.BuildScript == "" {
		return nil, fmt.Errorf("build script not specified for Android build")
	}

	if buildCfg.ConfigPath == "" {
		return nil, fmt.Errorf("kernel config path not specified for Android build")
	}

	return buildCfg, nil
}

func (a android) readCompiler(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	result := ccCompilerRegexp.FindSubmatch(bytes)
	if result == nil {
		return "", fmt.Errorf("%s does not contain build information", path)
	}
	return string(result[1]), nil
}

func (a android) build(params Params) (ImageDetails, error) {
	var details ImageDetails
	if params.CmdlineFile != "" {
		return details, fmt.Errorf("cmdline file is not supported for android images")
	}
	if params.SysctlFile != "" {
		return details, fmt.Errorf("sysctl file is not supported for android images")
	}

	buildCfg, err := parseConfig(params.Build)
	if err != nil {
		return details, fmt.Errorf("error parsing android configs: %w", err)
	}

	// Build kernel.
	cmd := osutil.Command(fmt.Sprintf("./%v", buildCfg.BuildScript), buildCfg.Flags...)
	cmd.Dir = params.KernelDir
	cmd.Env = append(cmd.Env, buildCfg.EnvVars...)

	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return details, fmt.Errorf("failed to build kernel: %w", err)
	}

	buildDistDir := filepath.Join(params.KernelDir, "dist")

	vmlinux := filepath.Join(buildDistDir, "vmlinux")

	if buildCfg.AutoconfPath != "" {
		details.CompilerID, err = a.readCompiler(filepath.Join(params.KernelDir, buildCfg.AutoconfPath))
		if err != nil {
			return details, fmt.Errorf("failed to read compiler: %w", err)
		}
	}

	if err := osutil.CopyFile(vmlinux, filepath.Join(params.OutputDir, "obj", "vmlinux")); err != nil {
		return details, fmt.Errorf("failed to copy vmlinux: %w", err)
	}
	if err := osutil.CopyFile(filepath.Join(params.KernelDir, buildCfg.ConfigPath),
		filepath.Join(params.OutputDir, "obj", "kernel.config")); err != nil {
		return details, fmt.Errorf("failed to copy kernel config: %w", err)
	}

	imageFile, err := os.Create(filepath.Join(params.OutputDir, "image"))
	if err != nil {
		return details, fmt.Errorf("failed to create output file: %w", err)
	}
	defer imageFile.Close()

	if err := copyModuleFiles(filepath.Join(params.KernelDir, "out"), params.OutputDir); err != nil {
		return details, fmt.Errorf("failed copying module files: %w", err)
	}

	images := append(buildCfg.AdditionalImages, "boot.img")
	if err := a.embedImages(imageFile, buildDistDir, images...); err != nil {
		return details, fmt.Errorf("failed to embed images: %w", err)
	}

	details.Signature, err = elfBinarySignature(vmlinux, params.Tracer)
	if err != nil {
		return details, fmt.Errorf("failed to generate signature: %w", err)
	}

	return details, nil
}

func copyModuleFiles(srcDir, dstDir string) error {
	err := filepath.WalkDir(srcDir,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return fmt.Errorf("error walking out dir: %w", err)
			}
			// Staging directories contain stripped module object files.
			if strings.Contains(path, "staging") {
				return nil
			}

			if filepath.Ext(path) == ".ko" {
				if err := osutil.CopyFile(path, filepath.Join(dstDir, d.Name())); err != nil {
					return fmt.Errorf("error copying file: %w", err)
				}
			}
			return nil
		})
	if err != nil {
		return fmt.Errorf("failed to copy module objects: %w", err)
	}
	return nil
}

func (a android) embedImages(w io.Writer, srcDir string, imageNames ...string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	for _, name := range imageNames {
		path := filepath.Join(srcDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %q: %w", name, err)
		}

		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}); err != nil {
			return fmt.Errorf("failed to write header for %q: %w", name, err)
		}

		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("failed to write data for %q: %w", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}

	return nil
}

func (a android) clean(params Params) error {
	if err := osutil.RemoveAll(filepath.Join(params.KernelDir, "out")); err != nil {
		return fmt.Errorf("failed to clean 'out' directory: %w", err)
	}
	if err := osutil.RemoveAll(filepath.Join(params.KernelDir, "dist")); err != nil {
		return fmt.Errorf("failed to clean 'dist' directory: %w", err)
	}
	return nil
}
