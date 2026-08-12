// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math/rand"
	"os"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/kconfig"
	"gopkg.in/yaml.v3"
)

type Matrix struct {
	Base     BaseConfig               `yaml:"base"`
	Axes     map[string][]AxisOption  `yaml:"axes"`
	Overlays map[string]OverlayOption `yaml:"overlays"`
}

type BaseConfig struct {
	Features []string `yaml:"features"`
	Config   string   `yaml:"config"`
	Cmdline  string   `yaml:"cmdline"`
	QemuArgs string   `yaml:"qemu_args"`
}

type AxisOption struct {
	Name     string            `yaml:"name"`
	Weight   float64           `yaml:"weight"`
	Features []string          `yaml:"features"`
	Kconfig  map[string]string `yaml:"kconfig"`
	Cmdline  string            `yaml:"cmdline"`
	QemuArgs string            `yaml:"qemu_args"`
}

type OverlayOption struct {
	Prob        float64           `yaml:"prob"`
	Description string            `yaml:"description"`
	Platforms   []string          `yaml:"platforms"`
	Features    []string          `yaml:"features"`
	Kconfig     map[string]string `yaml:"kconfig"`
	Cmdline     string            `yaml:"cmdline"`
	QemuArgs    string            `yaml:"qemu_args"`
}

type SampledConfig struct {
	Tag              string            `json:"tag"`
	Platform         string            `json:"platform"`
	SelectedAxes     map[string]string `json:"selected_axes"`
	SelectedOverlays []string          `json:"selected_overlays"`
	Features         []string          `json:"features"`
	KconfigOverrides map[string]string `json:"kconfig_overrides"`
	Cmdline          string            `json:"cmdline"`
	QemuArgs         string            `json:"qemu_args"`
}

func LoadMatrix(filename string) (*Matrix, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read matrix file: %w", err)
	}

	var matrix Matrix
	if err := yaml.Unmarshal(data, &matrix); err != nil {
		return nil, fmt.Errorf("failed to parse matrix YAML: %w", err)
	}

	return &matrix, nil
}

func (m *Matrix) Sample(rng *rand.Rand) (*SampledConfig, error) {
	sampled := &SampledConfig{
		SelectedAxes:     make(map[string]string),
		SelectedOverlays: []string{},
		KconfigOverrides: make(map[string]string),
	}

	featureSet := make(map[string]bool)
	for _, f := range m.Base.Features {
		featureSet[f] = true
	}

	var cmdlineParts []string
	if m.Base.Cmdline != "" {
		cmdlineParts = append(cmdlineParts, m.Base.Cmdline)
	}

	var qemuParts []string
	if m.Base.QemuArgs != "" {
		qemuParts = append(qemuParts, m.Base.QemuArgs)
	}

	// 1. Sample mutually exclusive axes (sorted for determinism)
	axisNames := slices.Sorted(maps.Keys(m.Axes))
	for _, axisName := range axisNames {
		options := m.Axes[axisName]
		if len(options) == 0 {
			continue
		}

		chosen := sampleAxisOption(options, rng)
		sampled.SelectedAxes[axisName] = chosen.Name
		if axisName == "platform" {
			sampled.Platform = chosen.Name
		}

		for _, f := range chosen.Features {
			featureSet[f] = true
		}
		maps.Copy(sampled.KconfigOverrides, chosen.Kconfig)
		if chosen.Cmdline != "" {
			cmdlineParts = append(cmdlineParts, chosen.Cmdline)
		}
		if chosen.QemuArgs != "" {
			qemuParts = append(qemuParts, chosen.QemuArgs)
		}
	}

	// 2. Sample probabilistic overlays (sorted for determinism)
	overlayNames := slices.Sorted(maps.Keys(m.Overlays))
	for _, overlayName := range overlayNames {
		overlay := m.Overlays[overlayName]

		// Check platform constraint if present.
		if len(overlay.Platforms) > 0 && sampled.Platform != "" {
			if !slices.Contains(overlay.Platforms, sampled.Platform) {
				continue
			}
		}

		if rng.Float64() < overlay.Prob {
			sampled.SelectedOverlays = append(sampled.SelectedOverlays, overlayName)
			for _, f := range overlay.Features {
				featureSet[f] = true
			}
			maps.Copy(sampled.KconfigOverrides, overlay.Kconfig)
			if overlay.Cmdline != "" {
				cmdlineParts = append(cmdlineParts, overlay.Cmdline)
			}
			if overlay.QemuArgs != "" {
				qemuParts = append(qemuParts, overlay.QemuArgs)
			}
		}
	}

	sampled.Features = slices.Sorted(maps.Keys(featureSet))
	sampled.Cmdline = strings.Join(cmdlineParts, " ")
	sampled.QemuArgs = strings.Join(qemuParts, " ")
	sampled.Tag = generateConfigTag(sampled)

	return sampled, nil
}

func sampleAxisOption(options []AxisOption, rng *rand.Rand) AxisOption {
	var totalWeight float64
	for _, opt := range options {
		totalWeight += opt.Weight
	}

	if totalWeight <= 0 {
		return options[rng.Intn(len(options))]
	}

	r := rng.Float64() * totalWeight
	var running float64
	for _, opt := range options {
		running += opt.Weight
		if r <= running {
			return opt
		}
	}
	return options[len(options)-1]
}

func generateConfigTag(sc *SampledConfig) string {
	var parts []string
	axisKeys := slices.Sorted(maps.Keys(sc.SelectedAxes))
	for _, k := range axisKeys {
		parts = append(parts, sc.SelectedAxes[k])
	}
	parts = append(parts, sc.SelectedOverlays...)

	tagBase := strings.Join(parts, "-")
	tagBase = strings.ReplaceAll(tagBase, "_", "-")

	hasher := sha256.New()
	hasher.Write([]byte(tagBase))
	hasher.Write([]byte(sc.Cmdline))
	hasher.Write([]byte(sc.QemuArgs))
	hashHex := hex.EncodeToString(hasher.Sum(nil))[:6]

	if len(tagBase) > 40 {
		tagBase = tagBase[:40]
	}
	return fmt.Sprintf("matrix-%s-%s", tagBase, hashHex)
}

func (m *Matrix) MergeKconfig(baseData []byte, sc *SampledConfig) ([]byte, error) {
	cf, err := kconfig.ParseConfigData(baseData, "base.config")
	if err != nil {
		return nil, fmt.Errorf("failed to parse base kconfig: %w", err)
	}

	for k, v := range sc.KconfigOverrides {
		switch v {
		case "y":
			cf.Set(k, kconfig.Yes)
		case "n":
			cf.Set(k, kconfig.No)
		case "m":
			cf.Set(k, kconfig.Mod)
		default:
			cf.Set(k, v)
		}
	}

	return cf.Serialize(), nil
}

func FormatKconfInstancesYAML(manifest []*SampledConfig) (string, error) {
	type InstanceSpec map[string][]string
	var instances []InstanceSpec

	for _, sc := range manifest {
		instances = append(instances, InstanceSpec{
			sc.Tag: sc.Features,
		})
	}

	root := map[string]any{
		"instances": instances,
	}

	out, err := yaml.Marshal(root)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
