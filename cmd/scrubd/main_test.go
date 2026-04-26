package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"--help"}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "scrubd scan") {
		t.Fatalf("help output missing usage:\n%s", buf.String())
	}
}

func TestRunMissingCommandReturnsUsageError(t *testing.T) {
	err := run(nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}

	var cmdErr commandError
	if !errors.As(err, &cmdErr) || !cmdErr.usage {
		t.Fatalf("error = %#v, want usage commandError", err)
	}
}

func TestRunUnknownCommandReturnsUsageError(t *testing.T) {
	err := run([]string{"nope"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}

	var cmdErr commandError
	if !errors.As(err, &cmdErr) || !cmdErr.usage || !strings.Contains(cmdErr.message, "unknown command") {
		t.Fatalf("error = %#v, want unknown command usage error", err)
	}
}

func TestRunScanRejectsInvalidRuntime(t *testing.T) {
	err := runScan([]string{"--runtime", "podman"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}

	var cmdErr commandError
	if !errors.As(err, &cmdErr) || !cmdErr.usage || !strings.Contains(cmdErr.message, "invalid runtime") {
		t.Fatalf("error = %#v, want invalid runtime usage error", err)
	}
}

func TestRunScanRejectsInvalidMinSeverity(t *testing.T) {
	err := runScan([]string{"--min-severity", "urgent"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}

	var cmdErr commandError
	if !errors.As(err, &cmdErr) || !cmdErr.usage || !strings.Contains(cmdErr.message, "invalid minimum severity") {
		t.Fatalf("error = %#v, want invalid minimum severity usage error", err)
	}
}

func TestRunScanRejectsPositionalArgs(t *testing.T) {
	err := runScan([]string{"extra"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}

	var cmdErr commandError
	if !errors.As(err, &cmdErr) || !cmdErr.usage || !strings.Contains(cmdErr.message, "takes no positional arguments") {
		t.Fatalf("error = %#v, want positional usage error", err)
	}
}

func TestParseLeakCommandArgs(t *testing.T) {
	args, err := parseLeakCommandArgs("explain", []string{"--runtime=containerd", "leak-abc"})
	if err != nil {
		t.Fatal(err)
	}
	if args.leakID != "leak-abc" || args.runtimeName != "containerd" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseLeakCommandArgsRejectsUnknownFlag(t *testing.T) {
	if _, err := parseLeakCommandArgs("explain", []string{"--bad", "leak-abc"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseCleanupArgs(t *testing.T) {
	args, err := parseCleanupArgs([]string{"leak-abc", "--dry-run", "--runtime", "docker"})
	if err != nil {
		t.Fatal(err)
	}
	if args.leakID != "leak-abc" || !args.dryRun || args.force || args.runtimeName != "docker" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseCleanupArgsFlagsBeforeID(t *testing.T) {
	args, err := parseCleanupArgs([]string{"--force", "--runtime=containerd", "leak-abc"})
	if err != nil {
		t.Fatal(err)
	}
	if args.leakID != "leak-abc" || !args.force || args.runtimeName != "containerd" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestParseCleanupArgsRequiresOneID(t *testing.T) {
	if _, err := parseCleanupArgs([]string{"one", "two"}); err == nil {
		t.Fatal("expected error for multiple ids")
	}
	if _, err := parseCleanupArgs([]string{"--dry-run"}); err == nil {
		t.Fatal("expected error for missing id")
	}
}
