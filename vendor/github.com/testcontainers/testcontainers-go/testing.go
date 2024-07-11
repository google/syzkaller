package testcontainers

import (
	"context"
	"fmt"
	"testing"
)

// SkipIfProviderIsNotHealthy is a utility function capable of skipping tests
// if the provider is not healthy, or running at all.
// This is a function designed to be used in your test, when Docker is not mandatory for CI/CD.
// In this way tests that depend on Testcontainers won't run if the provider is provisioned correctly.
func SkipIfProviderIsNotHealthy(t *testing.T) {
	ctx := context.Background()
	provider, err := ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker is not running. TestContainers can't perform is work without it: %s", err)
	}
	err = provider.Health(ctx)
	if err != nil {
		t.Skipf("Docker is not running. TestContainers can't perform is work without it: %s", err)
	}
}

// SkipIfDockerDesktop is a utility function capable of skipping tests
// if tests are run using Docker Desktop.
func SkipIfDockerDesktop(t *testing.T, ctx context.Context) {
	cli, err := NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatalf("failed to create docker client: %s", err)
	}

	info, err := cli.Info(ctx)
	if err != nil {
		t.Fatalf("failed to get docker info: %s", err)
	}

	if info.OperatingSystem == "Docker Desktop" {
		t.Skip("Skipping test that requires host network access when running in Docker Desktop")
	}
}

// exampleLogConsumer {

// StdoutLogConsumer is a LogConsumer that prints the log to stdout
type StdoutLogConsumer struct{}

// Accept prints the log to stdout
func (lc *StdoutLogConsumer) Accept(l Log) {
	fmt.Print(string(l.Content))
}

// }
