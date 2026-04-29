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

func TestExecuteWithoutForceRunsNonDestructiveStep(t *testing.T) {
	var buf bytes.Buffer
	runner := &recordingRunner{}
	steps := []Step{{Description: "show status", Command: []string{"true"}}}

	results, err := Execute(&buf, steps, Options{Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Executed {
		t.Fatalf("unexpected results: %#v", results)
	}
	if len(runner.commands) != 1 || runner.commands[0][0] != "true" {
		t.Fatalf("unexpected commands: %#v", runner.commands)
	}
	if got := buf.String(); !contains(got, "status: executed") {
		t.Fatalf("output missing executed status:\n%s", got)
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

func TestExecuteForceRunsMixedPlanInOrder(t *testing.T) {
	var buf bytes.Buffer
	runner := &recordingRunner{}
	steps := []Step{
		{Description: "show status", Command: []string{"true"}},
		{Description: "delete veth", Command: []string{"ip", "link", "delete", "veth0"}, Destructive: true},
	}

	results, err := Execute(&buf, steps, Options{Force: true, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || !results[0].Executed || !results[1].Executed {
		t.Fatalf("unexpected results: %#v", results)
	}
	if len(runner.commands) != 2 || runner.commands[0][0] != "true" || runner.commands[1][3] != "veth0" {
		t.Fatalf("unexpected commands: %#v", runner.commands)
	}
	if got := buf.String(); count(got, "status: executed") != 2 {
		t.Fatalf("output missing executed statuses:\n%s", got)
	}
}

func TestExecuteReportsFailedStep(t *testing.T) {
	var buf bytes.Buffer
	steps := []Step{{Description: "delete veth", Command: []string{"ip", "link", "delete", "veth0"}, Destructive: true}}

	results, err := Execute(&buf, steps, Options{Force: true, Runner: failingRunner{err: errors.New("boom")}})
	if err == nil {
		t.Fatal("Execute returned nil error")
	}
	if len(results) != 1 || results[0].Executed || results[0].Error != "boom" {
		t.Fatalf("unexpected results: %#v", results)
	}
	if got := buf.String(); !contains(got, "status: failed: boom") {
		t.Fatalf("output missing failed status:\n%s", got)
	}
}

func TestExecuteStopsAfterFailedStep(t *testing.T) {
	var buf bytes.Buffer
	runner := &orderedFailingRunner{failAt: 1, err: errors.New("boom")}
	steps := []Step{
		{Description: "show status", Command: []string{"true"}},
		{Description: "delete veth", Command: []string{"ip", "link", "delete", "veth0"}, Destructive: true},
		{Description: "delete namespace", Command: []string{"ip", "netns", "delete", "stale"}, Destructive: true},
	}

	results, err := Execute(&buf, steps, Options{Force: true, Runner: runner})
	if err == nil {
		t.Fatal("Execute returned nil error")
	}
	if len(results) != 2 || !results[0].Executed || results[1].Executed || results[1].Error != "boom" {
		t.Fatalf("unexpected results: %#v", results)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v, want first two commands only", runner.commands)
	}
	if got := buf.String(); contains(got, "delete namespace") {
		t.Fatalf("output includes step after failure:\n%s", got)
	}
}

func TestExecuteRejectsInvalidStep(t *testing.T) {
	_, err := Execute(&bytes.Buffer{}, []Step{{Description: "bad"}}, Options{})
	if err == nil {
		t.Fatal("Execute returned nil error")
	}
}

func TestFormatCommandQuotesUnsafeArgs(t *testing.T) {
	tests := []struct {
		name    string
		command []string
		want    string
	}{
		{
			name:    "space",
			command: []string{"ip", "netns", "delete", "name with space"},
			want:    "ip netns delete 'name with space'",
		},
		{
			name:    "single quote",
			command: []string{"printf", "can't"},
			want:    "printf 'can'\\''t'",
		},
		{
			name:    "empty arg",
			command: []string{"printf", ""},
			want:    "printf ''",
		},
		{
			name:    "shell metacharacters",
			command: []string{"umount", "/tmp/a;b"},
			want:    "umount '/tmp/a;b'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatCommand(tt.command)
			if got != tt.want {
				t.Fatalf("FormatCommand = %q, want %q", got, tt.want)
			}
		})
	}
}

type recordingRunner struct {
	commands [][]string
}

func (r *recordingRunner) Run(command []string) error {
	r.commands = append(r.commands, append([]string{}, command...))
	return nil
}

type orderedFailingRunner struct {
	commands [][]string
	failAt   int
	err      error
}

func (r *orderedFailingRunner) Run(command []string) error {
	r.commands = append(r.commands, append([]string{}, command...))
	if len(r.commands)-1 == r.failAt {
		return r.err
	}
	return nil
}

type failingRunner struct {
	err error
}

func (r failingRunner) Run([]string) error {
	if r.err != nil {
		return r.err
	}
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

func count(haystack, needle string) int {
	var total int
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			total++
		}
	}
	return total
}
