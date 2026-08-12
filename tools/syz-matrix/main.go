// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var (
		flagMatrix   = flag.String("matrix", "tools/syz-matrix/matrix.yaml", "path to matrix.yaml")
		flagSample   = flag.Bool("sample", false, "sample a single config and print summary")
		flagGenerate = flag.Int("generate", 0, "number of diverse configs to generate")
		flagOutDir   = flag.String("out-dir", "generated_configs", "output directory for generated configs")
		flagSeed     = flag.Int64("seed", 0, "random seed (0 for current timestamp)")
	)
	flag.Parse()

	matrix, err := LoadMatrix(*flagMatrix)
	if err != nil {
		log.Fatalf("failed to load matrix: %v", err)
	}

	seed := *flagSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))

	if *flagSample {
		sampled, err := matrix.Sample(rng)
		if err != nil {
			log.Fatalf("failed to sample: %v", err)
		}
		printSampleSummary(sampled)
		return
	}

	if *flagGenerate > 0 {
		if err := generateBatch(matrix, *flagGenerate, rng, *flagOutDir); err != nil {
			log.Fatalf("failed to generate batch: %v", err)
		}
		return
	}

	flag.Usage()
}

func printSampleSummary(sc *SampledConfig) {
	fmt.Printf("=== sampled configuration: %s ===\n", sc.Tag)
	fmt.Printf("platform:       %s\n", sc.Platform)
	fmt.Println("selected axes:")
	for axis, val := range sc.SelectedAxes {
		fmt.Printf("  - %s: %s\n", axis, val)
	}
	fmt.Println("active overlays:")
	for _, ov := range sc.SelectedOverlays {
		fmt.Printf("  - %s\n", ov)
	}
	fmt.Printf("kconf features: [%s]\n", strings.Join(sc.Features, ", "))
	fmt.Printf("kernel cmdline: %s\n", sc.Cmdline)
	fmt.Printf("qemu args:      %s\n", sc.QemuArgs)
	if len(sc.KconfigOverrides) > 0 {
		fmt.Printf("kconfig overrides (%d symbols):\n", len(sc.KconfigOverrides))
		for k, v := range sc.KconfigOverrides {
			fmt.Printf("  CONFIG_%s=%s\n", k, v)
		}
	}
}

func generateBatch(matrix *Matrix, count int, rng *rand.Rand, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var baseData []byte
	if matrix.Base.Config != "" {
		var err error
		baseData, err = os.ReadFile(matrix.Base.Config)
		if err != nil {
			return fmt.Errorf("failed to read base config (%s): %w", matrix.Base.Config, err)
		}
	}

	seenTags := make(map[string]bool)
	var sampledList []*SampledConfig

	fmt.Printf("generating %d configurations into %s...\n", count, outDir)

	maxAttempts := count * 20
	for attempts := 0; len(sampledList) < count && attempts < maxAttempts; attempts++ {
		sampled, err := matrix.Sample(rng)
		if err != nil {
			return fmt.Errorf("sample #%d failed: %w", len(sampledList), err)
		}

		if seenTags[sampled.Tag] {
			continue
		}
		seenTags[sampled.Tag] = true

		configDir := filepath.Join(outDir, fmt.Sprintf("%03d_%s", len(sampledList)+1, sampled.Tag))
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return err
		}

		if len(baseData) > 0 {
			mergedKconfig, err := matrix.MergeKconfig(baseData, sampled)
			if err != nil {
				return fmt.Errorf("failed to merge kconfig for %s: %w", sampled.Tag, err)
			}
			if err := os.WriteFile(filepath.Join(configDir, "kernel.config"), mergedKconfig, 0644); err != nil {
				return err
			}
		}

		metaJSON, err := json.MarshalIndent(sampled, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(configDir, "meta.json"), metaJSON, 0644); err != nil {
			return err
		}

		sampledList = append(sampledList, sampled)
	}

	manifestData, err := json.MarshalIndent(sampledList, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), manifestData, 0644); err != nil {
		return err
	}

	kconfYAML, err := FormatKconfInstancesYAML(sampledList)
	if err != nil {
		return fmt.Errorf("failed to format kconf YAML: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "kconf_instances.yml"), []byte(kconfYAML), 0644); err != nil {
		return err
	}

	fmt.Printf("successfully generated %d unique configurations in %s (manifest.json & kconf_instances.yml)\n",
		len(sampledList), outDir)
	return nil
}
