// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"fmt"
	"net/mail"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	// How many workflows are scheduled in parallel.
	ParallelWorkflows int `yaml:"parallelWorkflows"`
	// What Lore archives are to be polled for new patch series.
	LoreArchives []string `yaml:"loreArchives"`
	// Parameters used for sending/generating emails.
	EmailReporting *EmailConfig `yaml:"emailReporting"`
}

type EmailConfig struct {
	// The public name of the system.
	Name string `yaml:"name"`
	// Link to the public documentation.
	DocsLink string `yaml:"docs"`
	// Contact email.
	SupportEmail string `yaml:"supportEmail"`
	// The email from which to send the reports.
	Sender string `yaml:"sender"`
	// Moderation requests will be sent there.
	ModerationList string `yaml:"moderationList"`
	// The list we listen on.
	ArchiveList string `yaml:"archiveList"`
	// Lore git archive to poll for incoming messages.
	LoreArchiveURL string `yaml:"loreArchiveURL"`
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
	if c.EmailReporting != nil {
		if err := c.EmailReporting.Validate(); err != nil {
			return fmt.Errorf("emailReporting: %w", err)
		}
	}
	return nil
}

func (c EmailConfig) Validate() error {
	for _, err := range []error{
		ensureNonEmpty("name", c.Name),
		ensureEmail("supportEmail", c.SupportEmail),
		ensureEmail("sender", c.Sender),
		ensureEmail("moderationList", c.ModerationList),
		ensureEmail("archiveList", c.ArchiveList),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

func ensureNonEmpty(name, val string) error {
	if val == "" {
		return fmt.Errorf("%v must not be empty", name)
	}
	return nil
}

func ensureEmail(name, val string) error {
	if err := ensureNonEmpty(name, val); err != nil {
		return err
	}
	_, err := mail.ParseAddress(val)
	if err != nil {
		return fmt.Errorf("%v contains invalid email address", name)
	}
	return nil
}
