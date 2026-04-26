package cleanup

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type Options struct {
	DryRun bool
	Force  bool
	Runner Runner
}

type Runner interface {
	Run(command []string) error
}

type ExecRunner struct{}

func (ExecRunner) Run(command []string) error {
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", FormatCommand(command), err, strings.TrimSpace(string(output)))
	}
	return nil
}

type Result struct {
	Step     Step   `json:"step"`
	Executed bool   `json:"executed"`
	Error    string `json:"error,omitempty"`
}

func Execute(w io.Writer, steps []Step, options Options) ([]Result, error) {
	if options.Runner == nil {
		options.Runner = ExecRunner{}
	}

	results := make([]Result, 0, len(steps))
	for _, step := range steps {
		if !step.Validate() {
			return results, fmt.Errorf("invalid cleanup step: %#v", step)
		}

		result := Result{Step: step}
		if _, err := fmt.Fprintf(w, "- %s\n  command: %s\n", step.Description, FormatCommand(step.Command)); err != nil {
			return results, err
		}

		if options.DryRun {
			if _, err := fmt.Fprintln(w, "  status: dry-run"); err != nil {
				return results, err
			}
			results = append(results, result)
			continue
		}

		if step.Destructive && !options.Force {
			if _, err := fmt.Fprintln(w, "  status: skipped, requires --force"); err != nil {
				return results, err
			}
			results = append(results, result)
			continue
		}

		if !options.Force {
			if _, err := fmt.Fprintln(w, "  status: skipped, requires --force"); err != nil {
				return results, err
			}
			results = append(results, result)
			continue
		}

		if err := options.Runner.Run(step.Command); err != nil {
			result.Error = err.Error()
			results = append(results, result)
			return results, err
		}

		result.Executed = true
		if _, err := fmt.Fprintln(w, "  status: executed"); err != nil {
			return results, err
		}
		results = append(results, result)
	}

	return results, nil
}

func FormatCommand(command []string) string {
	parts := make([]string, 0, len(command))
	for _, arg := range command {
		parts = append(parts, quoteArg(arg))
	}
	return strings.Join(parts, " ")
}

func quoteArg(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.ContainsAny(arg, " \t\n'\"\\$`!*?[]{}()<>|&;") {
		return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return arg
}
