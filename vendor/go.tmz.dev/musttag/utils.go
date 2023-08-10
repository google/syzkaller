package musttag

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func getMainModule() (string, error) {
	args := []string{"go", "list", "-m", "-json"}

	data, err := exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		return "", fmt.Errorf("running `%s`: %w", strings.Join(args, " "), err)
	}

	var module struct {
		Path      string `json:"Path"`
		Main      bool   `json:"Main"`
		Dir       string `json:"Dir"`
		GoMod     string `json:"GoMod"`
		GoVersion string `json:"GoVersion"`
	}
	if err := json.Unmarshal(data, &module); err != nil {
		return "", fmt.Errorf("decoding json: %w: %s", err, string(data))
	}

	return module.Path, nil
}
