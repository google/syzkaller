// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/dashboard/dashapi"
)

type Config struct {
	// Debug mode forces syz-ci upload artifacts on each syz-manager restart and also forces
	// it to produce more logs.
	Debug bool `json:"debug"`
	// Where to upload artifacts.
	// If "gs://bucket/" is specified, assets will be stored in the corresponding GCS bucket.
	// If "dummy://" is specified, assets will not be actually stored anywhere. May be helpful
	// for debugging.
	UploadTo string `json:"upload_to"`
	// Perform asset deprecation from this instance. If several syz-ci's share a common stoage,
	// it make sense to enable derprecation only on one of them.
	DoDeprecation bool `json:"do_deprecation"`
	// Make assets publicly available (note that it also might require special configuration
	// on the storage backend's side).
	PublicAccess bool `json:"public_access"`
	// Some asset type-specific configurations. By default all asset types are enabled.
	Assets map[dashapi.AssetType]TypeConfig `json:"assets"`
}

type TypeConfig struct {
	Never bool `json:"never"`
	// TODO: in future there'll also be `OnlyOn` and `NeverOn`, but so far we don't really need that.
	// TODO: here will also go compression settings, should we ever want to make it configurable.
}

func (tc *TypeConfig) Validate() error {
	return nil
}

func (c *Config) IsEnabled(assetType dashapi.AssetType) bool {
	return !c.Assets[assetType].Never
}

func (c *Config) IsEmpty() bool {
	return c == nil
}

func (c *Config) Validate() error {
	for assetType, cfg := range c.Assets {
		if GetTypeDescription(assetType) == nil {
			return fmt.Errorf("invalid asset type: %s", assetType)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid config for %s: %w", assetType, err)
		}
	}
	if c.UploadTo == "" && len(c.Assets) != 0 {
		return fmt.Errorf("assets are specified, but upload_to is empty")
	}
	allowedFormats := []string{"gs://", "dummy://"}
	if c.UploadTo != "" {
		any := false
		for _, prefix := range allowedFormats {
			if strings.HasPrefix(c.UploadTo, prefix) {
				any = true
			}
		}
		if !any {
			return fmt.Errorf("the currently supported upload destinations are: %v", allowedFormats)
		}
	}
	return nil
}
