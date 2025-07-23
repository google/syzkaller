// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"fmt"
	"net/mail"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	// The name that will be shown on the Web UI.
	Name string `yaml:"name"`
	// Public URL of the web dashboard (without / at the end).
	URL string `yaml:"URL"`
	// How many workflows are scheduled in parallel.
	ParallelWorkflows int `yaml:"parallelWorkflows"`
	// What Lore archives are to be polled for new patch series.
	LoreArchives []string `yaml:"loreArchives"`
	// Parameters used for sending/generating emails.
	EmailReporting *EmailConfig `yaml:"emailReporting"`
}

const (
	SenderSMTP    = "smtp"
	SenderDashapi = "dashapi"
)

type EmailConfig struct {
	// The public name of the system.
	Name string `yaml:"name"`
	// Link to the public documentation.
	DocsLink string `yaml:"docs"`
	// Contact email.
	SupportEmail string `yaml:"supportEmail"`
	// The address will be suggested for the Tested-by tag.
	CreditEmail string `yaml:"creditEmail"`
	// The means to send the emails ("smtp", "dashapi").
	Sender string `yaml:"sender"`
	// Will be used if Sender is "smtp".
	SMTP *SMTPConfig `yaml:"smtpConfig"`
	// Will be used if Sender is "dashapi".
	Dashapi *DashapiConfig `yaml:"dashapiConfig"`
	// Moderation requests will be sent there.
	ModerationList string `yaml:"moderationList"`
	// The list email-reporter listens on.
	ArchiveList string `yaml:"archiveList"`
	// The lists/emails to be Cc'd for actual reports (not moderation).
	ReportCC []string `yaml:"reportCc"`
	// Lore git archive to poll for incoming messages.
	LoreArchiveURL string `yaml:"loreArchiveURL"`
	// The prefix which will be added to all reports' titles.
	SubjectPrefix string `yaml:"subjectPrefix"`
}

type SMTPConfig struct {
	// The email from which to send the reports.
	From string `yaml:"from"`
}

type DashapiConfig struct {
	// The URI at which the dashboard is accessible.
	Addr string `yaml:"addr"`
	// Client name to be used for authorization.
	// OAuth will be used instead of a key.
	Client string `yaml:"client"`
	// The email from which to send the reports.
	From string `yaml:"from"`
	// The emails will be sent from "name+" + contextPrefix + ID + "@domain".
	ContextPrefix string `yaml:"contextPrefix"`
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
		Name:              "Syzbot CI",
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
	if err := ensureURL("url", c.URL); err != nil {
		return err
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
		ensureEmail("moderationList", c.ModerationList),
		ensureEmail("archiveList", c.ArchiveList),
	} {
		if err != nil {
			return err
		}
	}
	if c.SMTP != nil {
		if err := c.SMTP.Validate(); err != nil {
			return err
		}
	}
	if c.Dashapi != nil {
		if err := c.Dashapi.Validate(); err != nil {
			return err
		}
	}
	switch c.Sender {
	case SenderSMTP:
		if c.SMTP == nil {
			return fmt.Errorf("sender is %q, but smtpConfig is empty", SenderSMTP)
		}
	case SenderDashapi:
		if c.Dashapi == nil {
			return fmt.Errorf("sender is %q, but dashapiConfig is empty", SenderDashapi)
		}
	default:
		return fmt.Errorf("invalid sender value, must be %q or %q", SenderSMTP, SenderDashapi)
	}
	return nil
}

func (c SMTPConfig) Validate() error {
	return ensureEmail("from", c.From)
}

func (c DashapiConfig) Validate() error {
	for _, err := range []error{
		ensureNonEmpty("addr", c.Addr),
		ensureNonEmpty("client", c.Client),
		ensureEmail("from", c.From),
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

func ensureURL(name, val string) error {
	if err := ensureNonEmpty(name, val); err != nil {
		return err
	}
	if strings.HasSuffix(val, "/") {
		return fmt.Errorf("%v should not contain / at the end", name)
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
