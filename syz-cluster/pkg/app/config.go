// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	// How many workflows are scheduled in parallel.
	ParallelWorkflows int `yaml:"parallelWorkflows"`
	// What Lore archives are to be polled for new patch series.
	LoreArchives []string `yaml:"loreArchives"`
}

// The project configuration is expected to be mounted at /config/config.yaml.

func Config() (*AppConfig, error) {
	configLoadedOnce.Do(loadConfig)
	return config, configErr
}

const configPath = `/config/config.yaml`

var configLoadedOnce sync.Once
var configErr error
var config *AppConfig

func loadConfig() {
	data, err := os.ReadFile(configPath)
	if err != nil {
		configErr = fmt.Errorf("failed to read %q: %w", configPath, err)
		return
	}
	obj := AppConfig{
		ParallelWorkflows: 1,
	}
	err = yaml.Unmarshal(data, &obj)
	if err != nil {
		configErr = fmt.Errorf("failed to parse: %w", err)
		return
	}
	err = obj.Validate()
	if err != nil {
		configErr = err
		return
	}
	config = &obj
}

func (c AppConfig) Validate() error {
	if c.ParallelWorkflows < 0 {
		return fmt.Errorf("parallelWorkflows must be non-negative")
	}
	return nil
}
