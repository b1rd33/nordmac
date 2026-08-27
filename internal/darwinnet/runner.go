// Package darwinnet contains narrowly typed macOS network command adapters.
// No shell is used and callers inject a runner for offline tests.
package darwinnet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "LC_ALL=") {
			command.Env = append(command.Env, variable)
		}
	}
	command.Env = append(command.Env, "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return nil, fmt.Errorf("run %s: %w", name, err)
		}
		return nil, fmt.Errorf("run %s: %w: %s", name, err, message)
	}
	return output, nil
}
