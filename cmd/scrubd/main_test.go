package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"scrubd/internal/cleanup"
	"scrubd/internal/detect"
	"scrubd/internal/inspect"
	"scrubd/internal/report"
	runtimeinv "scrubd/internal/runtime"
)

func withBuildScanReportFunc(t *testing.T, fn func(runtimeinv.Name, detect.Severity) report.Report) {
	t.Helper()
	previous := buildScanReportFunc
	buildScanReportFunc = fn
	t.Cleanup(func() {
		buildScanReportFunc = previous
	})
}

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

func TestBuildScanReportSkipsRuntimeCorrelatedLeaksWithoutRuntimeInventory(t *testing.T) {
	scanReport := buildScanReportFromInventory(
		runtimeinv.NameAuto,
		detect.SeverityLow,
		inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "veth0", Index: 2, Kind: "veth"}},
			Warnings:          []string{"host warning"},
		},
		[]runtimeinv.Inventory{{
			Runtime:  runtimeinv.NameDocker,
			Warnings: []string{"runtime warning"},
		}},
	)

	if len(scanReport.Leaks) != 0 {
		t.Fatalf("leaks = %#v, want none without runtime inventory", scanReport.Leaks)
	}
	if !containsString(scanReport.Warnings, "host warning") || !containsString(scanReport.Warnings, "runtime warning") {
		t.Fatalf("warnings = %#v, want host and runtime warnings", scanReport.Warnings)
	}
	if !containsString(scanReport.Warnings, "runtime-correlated detections skipped: no container runtime inventory available") {
		t.Fatalf("warnings = %#v, want runtime-correlation skip warning", scanReport.Warnings)
	}
}

func TestBuildScanReportWarnsOnPartialRuntimeInventory(t *testing.T) {
	scanReport := buildScanReportFromInventory(
		runtimeinv.NameAuto,
		detect.SeverityLow,
		inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "veth0", Index: 2, Kind: "veth"}},
		},
		[]runtimeinv.Inventory{
			{Runtime: runtimeinv.NameDocker, Available: true},
			{Runtime: runtimeinv.NameContainerd, Available: false, Warnings: []string{"containerd missing"}},
		},
	)

	if len(scanReport.Leaks) != 0 {
		t.Fatalf("leaks = %#v, want none with partial runtime inventory", scanReport.Leaks)
	}
	if !containsString(scanReport.Warnings, "some runtime inventory unavailable: global orphan checks are skipped and runtime-correlated detections are conservative") {
		t.Fatalf("warnings = %#v, want partial runtime warning", scanReport.Warnings)
	}
}

func TestBuildScanReportFiltersByMinimumSeverity(t *testing.T) {
	scanReport := buildScanReportFromInventory(
		runtimeinv.NameAuto,
		detect.SeverityHigh,
		inspect.Inventory{
			NetworkInterfaces: []inspect.NetworkInterface{{Name: "veth0", Index: 2, Kind: "veth"}},
			NetworkNamespaces: []inspect.NetworkNamespace{{Path: "/var/run/netns/stale", Inode: "10", Source: "netns"}},
		},
		[]runtimeinv.Inventory{{Runtime: runtimeinv.NameDocker, Available: true}},
	)

	if len(scanReport.Leaks) != 1 {
		t.Fatalf("leaks = %#v, want one high severity leak", scanReport.Leaks)
	}
	if scanReport.Leaks[0].Type != detect.LeakTypeVethInterface {
		t.Fatalf("leak = %#v, want veth leak after severity filter", scanReport.Leaks[0])
	}
}

func TestRunScanJSONUsesBuilderOutput(t *testing.T) {
	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		if runtimeName != runtimeinv.NameContainerd {
			t.Fatalf("runtimeName = %q, want containerd", runtimeName)
		}
		if minSeverity != detect.SeverityMedium {
			t.Fatalf("minSeverity = %q, want medium", minSeverity)
		}
		return report.Report{
			SchemaVersion: report.SchemaVersion,
			Runtime:       runtimeName,
			Runtimes:      []runtimeinv.Inventory{{Runtime: runtimeinv.NameContainerd, Available: false}},
			Warnings:      []string{"runtime warning"},
		}
	})

	var buf bytes.Buffer
	if err := runScan([]string{"--json", "--runtime", "containerd", "--min-severity", "medium"}, &buf); err != nil {
		t.Fatal(err)
	}

	var out report.Report
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if out.Runtime != runtimeinv.NameContainerd {
		t.Fatalf("runtime = %q, want containerd", out.Runtime)
	}
	if out.SchemaVersion != report.SchemaVersion {
		t.Fatalf("schema version = %q", out.SchemaVersion)
	}
	if len(out.Warnings) != 1 || out.Warnings[0] != "runtime warning" {
		t.Fatalf("warnings = %#v, want builder warnings", out.Warnings)
	}
}

func TestRunScanTextShowsDegradedWarnings(t *testing.T) {
	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		return report.Report{
			Runtime: runtimeName,
			Runtimes: []runtimeinv.Inventory{
				{Runtime: runtimeinv.NameDocker},
				{Runtime: runtimeinv.NameContainerd},
			},
			Warnings: []string{
				"host inspection unsupported on darwin: scrubd must run on Linux to inspect container runtime resources",
				"runtime-correlated detections skipped: no container runtime inventory available",
			},
			Summary: report.Summary{RuntimeCount: 2},
		}
	})

	var buf bytes.Buffer
	if err := runScan(nil, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "warnings:") {
		t.Fatalf("output missing warnings section:\n%s", output)
	}
	if !strings.Contains(output, "runtime-correlated detections skipped: no container runtime inventory available") {
		t.Fatalf("output missing degraded runtime warning:\n%s", output)
	}
	if !strings.Contains(output, "No leaks detected.") {
		t.Fatalf("output missing no leaks message:\n%s", output)
	}
}

func TestRunExplainUsesBuilderLeak(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeMount, detect.SeverityMedium, "/var/lib/docker/overlay2/leaked/merged", "container runtime mount has no matching running container reference")
	leak.Evidence = []string{"mount id: 42"}
	leak.SafeAction = "umount /var/lib/docker/overlay2/leaked/merged"

	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		if runtimeName != runtimeinv.NameDocker {
			t.Fatalf("runtimeName = %q, want docker", runtimeName)
		}
		if minSeverity != detect.SeverityLow {
			t.Fatalf("minSeverity = %q, want low", minSeverity)
		}
		return report.Report{Runtime: runtimeName, Leaks: []detect.Leak{leak}}
	})

	var buf bytes.Buffer
	if err := runExplain([]string{leak.ID, "--runtime", "docker"}, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "Leak explanation") || !strings.Contains(output, leak.ID) {
		t.Fatalf("output missing leak explanation header:\n%s", output)
	}
	if !strings.Contains(output, "mount id: 42") || !strings.Contains(output, leak.SafeAction) {
		t.Fatalf("output missing evidence or action:\n%s", output)
	}
}

func TestRunCleanupDryRunUsesBuilderLeak(t *testing.T) {
	leak := sampleCleanupLeak()
	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		return report.Report{Runtime: runtimeName, Leaks: []detect.Leak{leak}}
	})

	var buf bytes.Buffer
	if err := runCleanup([]string{leak.ID, "--dry-run"}, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "mode: dry-run") {
		t.Fatalf("output missing dry-run mode:\n%s", output)
	}
	if !strings.Contains(output, "dry-run: no commands will be executed") {
		t.Fatalf("output missing dry-run execution note:\n%s", output)
	}
	if !strings.Contains(output, "status: dry-run") {
		t.Fatalf("output missing dry-run status:\n%s", output)
	}
	if !strings.Contains(output, "ip link delete veth0") {
		t.Fatalf("output missing cleanup command:\n%s", output)
	}
}

func TestRunCleanupWithoutForceSkipsDestructiveStep(t *testing.T) {
	leak := sampleCleanupLeak()
	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		return report.Report{Runtime: runtimeName, Leaks: []detect.Leak{leak}}
	})

	var buf bytes.Buffer
	if err := runCleanup([]string{leak.ID}, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "mode: plan") {
		t.Fatalf("output missing plan mode:\n%s", output)
	}
	if !strings.Contains(output, "force not set: destructive steps will be skipped") {
		t.Fatalf("output missing no-force execution note:\n%s", output)
	}
	if !strings.Contains(output, "requires --force") {
		t.Fatalf("output missing force guard:\n%s", output)
	}
}

func TestRunCleanupWithoutForceRunsNonDestructiveStep(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeMount, detect.SeverityLow, "status", "diagnostic step")
	leak.CleanupPlan = []cleanup.Step{{
		Description: "run harmless diagnostic",
		Command:     []string{"true"},
	}}
	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		return report.Report{Runtime: runtimeName, Leaks: []detect.Leak{leak}}
	})

	var buf bytes.Buffer
	if err := runCleanup([]string{leak.ID}, &buf); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if strings.Contains(output, "force not set: destructive steps will be skipped") {
		t.Fatalf("output has destructive warning for non-destructive plan:\n%s", output)
	}
	if strings.Contains(output, "requires --force") {
		t.Fatalf("output has force guard for non-destructive plan:\n%s", output)
	}
	if !strings.Contains(output, "status: executed") {
		t.Fatalf("output missing executed status:\n%s", output)
	}
}

func TestRunCleanupReturnsNotFoundForMissingLeak(t *testing.T) {
	withBuildScanReportFunc(t, func(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
		return report.Report{Runtime: runtimeName}
	})

	err := runCleanup([]string{"leak-missing", "--dry-run"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `leak "leak-missing" not found`) {
		t.Fatalf("err = %v, want missing leak error", err)
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

func sampleCleanupLeak() detect.Leak {
	leak := detect.NewLeak(detect.LeakTypeVethInterface, detect.SeverityHigh, "veth0", "veth interface found but no running runtime container references are available")
	leak.CleanupPlan = []cleanup.Step{{
		Description: "delete veth interface veth0",
		Command:     []string{"ip", "link", "delete", "veth0"},
		Destructive: true,
	}}
	return leak
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
