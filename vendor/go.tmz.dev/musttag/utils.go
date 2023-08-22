package musttag

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var (
	getwd = os.Getwd

	commandOutput = func(name string, args ...string) (string, error) {
		output, err := exec.Command(name, args...).Output()
		return string(output), err
	}
)

func getMainModule() (string, error) {
	args := []string{"go", "list", "-m", "-json"}

	output, err := commandOutput(args[0], args[1:]...)
	if err != nil {
		return "", fmt.Errorf("running `%s`: %w", strings.Join(args, " "), err)
	}

	cwd, err := getwd()
	if err != nil {
		return "", fmt.Errorf("getting wd: %w", err)
	}

	decoder := json.NewDecoder(strings.NewReader(output))

	for {
		// multiple JSON objects will be returned when using Go workspaces; see #63 for details.
		var module struct {
			Path      string `json:"Path"`
			Main      bool   `json:"Main"`
			Dir       string `json:"Dir"`
			GoMod     string `json:"GoMod"`
			GoVersion string `json:"GoVersion"`
		}
		if err := decoder.Decode(&module); err != nil {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("main module not found\n%s", output)
			}
			return "", fmt.Errorf("decoding json: %w\n%s", err, output)
		}

		if module.Main && strings.HasPrefix(cwd, module.Dir) {
			return module.Path, nil
		}
	}
}
