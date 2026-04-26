package cleanup

import (
	"bytes"
	"errors"
	"testing"
)

func TestExecuteDryRunSkipsDestructiveStep(t *testing.T) {
	var buf bytes.Buffer
	steps := []Step{{Description: "delete veth", Command: []string{"ip", "link", "delete", "veth0"}, Destructive: true}}

	results, err := Execute(&buf, steps, Options{DryRun: true, Runner: failingRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Executed {
		t.Fatalf("unexpected results: %#v", results)
	}
	if got := buf.String(); !contains(got, "status: dry-run") {
		t.Fatalf("output missing dry-run status:\n%s", got)
	}
}

func TestExecuteWithoutForceSkipsDestructiveStep(t *testing.T) {
	var buf bytes.Buffer
	steps := []Step{{Description: "delete netns", Command: []string{"ip", "netns", "delete", "test"}, Destructive: true}}

	results, err := Execute(&buf, steps, Options{Runner: failingRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Executed {
		t.Fatalf("unexpected results: %#v", results)
	}
	if got := buf.String(); !contains(got, "requires --force") {
		t.Fatalf("output missing force warning:\n%s", got)
	}
}

func TestExecuteForceRunsStep(t *testing.T) {
	var buf bytes.Buffer
	runner := &recordingRunner{}
	steps := []Step{{Description: "delete veth", Command: []string{"ip", "link", "delete", "veth0"}, Destructive: true}}

	results, err := Execute(&buf, steps, Options{Force: true, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Executed {
		t.Fatalf("unexpected results: %#v", results)
	}
	if len(runner.commands) != 1 || runner.commands[0][3] != "veth0" {
		t.Fatalf("unexpected commands: %#v", runner.commands)
	}
}

func TestExecuteRejectsInvalidStep(t *testing.T) {
	_, err := Execute(&bytes.Buffer{}, []Step{{Description: "bad"}}, Options{})
	if err == nil {
		t.Fatal("Execute returned nil error")
	}
}

func TestFormatCommandQuotesUnsafeArgs(t *testing.T) {
	got := FormatCommand([]string{"ip", "netns", "delete", "name with space"})
	want := "ip netns delete 'name with space'"
	if got != want {
		t.Fatalf("FormatCommand = %q, want %q", got, want)
	}
}

type recordingRunner struct {
	commands [][]string
}

func (r *recordingRunner) Run(command []string) error {
	r.commands = append(r.commands, append([]string{}, command...))
	return nil
}

type failingRunner struct{}

func (failingRunner) Run([]string) error {
	return errors.New("runner should not execute")
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
