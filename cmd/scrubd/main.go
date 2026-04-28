package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"scrubd/internal/cleanup"
	"scrubd/internal/detect"
	"scrubd/internal/inspect"
	"scrubd/internal/report"
	runtimeinv "scrubd/internal/runtime"
)

var buildScanReportFunc = buildScanReport

const usageText = `scrubd detects leaked container runtime resources.

Usage:
  scrubd scan [--json] [--runtime docker|containerd|auto] [--min-severity low|medium|high|critical]
  scrubd explain <leak-id> [--runtime docker|containerd|auto]
  scrubd cleanup <leak-id> [--dry-run] [--force] [--runtime docker|containerd|auto]

Commands:
  scan      scan host resources for likely leaks
  explain   explain a leak from the latest scan output
  cleanup   plan or execute cleanup for a leak
`

type commandError struct {
	message string
	usage   bool
}

func (e commandError) Error() string {
	return e.message
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)

		var cmdErr commandError
		if errors.As(err, &cmdErr) && cmdErr.usage {
			fmt.Fprint(os.Stderr, usageText)
			os.Exit(2)
		}

		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return commandError{message: "missing command", usage: true}
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout)
	case "explain":
		return runExplain(args[1:], stdout)
	case "cleanup":
		return runCleanup(args[1:], stdout)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return nil
	default:
		return commandError{message: fmt.Sprintf("unknown command %q", args[0]), usage: true}
	}
}

func runScan(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	jsonOutput := flags.Bool("json", false, "emit JSON report")
	runtimeName := flags.String("runtime", "auto", "runtime to inspect: docker, containerd, or auto")
	minSeverity := flags.String("min-severity", "low", "minimum leak severity to report: low, medium, high, or critical")

	if err := flags.Parse(args); err != nil {
		return commandError{message: err.Error(), usage: true}
	}
	if flags.NArg() != 0 {
		return commandError{message: fmt.Sprintf("scan takes no positional arguments, got %q", flags.Arg(0)), usage: true}
	}
	if !validRuntime(*runtimeName) {
		return commandError{message: fmt.Sprintf("invalid runtime %q", *runtimeName), usage: true}
	}
	severity := detect.Severity(*minSeverity)
	if !detect.ValidSeverity(severity) {
		return commandError{message: fmt.Sprintf("invalid minimum severity %q", *minSeverity), usage: true}
	}

	scanReport := buildScanReportFunc(runtimeinv.Name(*runtimeName), severity)

	if *jsonOutput {
		return report.WriteJSON(stdout, scanReport)
	}

	return report.WriteText(stdout, scanReport)
}

func buildScanReport(runtimeName runtimeinv.Name, minSeverity detect.Severity) report.Report {
	host := inspect.NewDefaultCollector().Inventory()
	runtimes := runtimeinv.NewDefaultCollector().Inventories(runtimeName)
	return buildScanReportFromInventory(runtimeName, minSeverity, host, runtimes)
}

func buildScanReportFromInventory(runtimeName runtimeinv.Name, minSeverity detect.Severity, host inspect.Inventory, runtimes []runtimeinv.Inventory) report.Report {
	leaks := detect.Detect(detect.Input{
		Host:     host,
		Runtimes: runtimes,
	})
	leaks = detect.FilterByMinSeverity(leaks, minSeverity)

	warnings := append([]string{}, host.Warnings...)
	for _, runtimeInventory := range runtimes {
		warnings = append(warnings, runtimeInventory.Warnings...)
	}
	if !runtimeInventoryAvailable(runtimes) {
		warnings = append(warnings, "runtime-correlated detections skipped: no container runtime inventory available")
	} else if runtimeInventoryPartial(runtimes) {
		warnings = append(warnings, "some runtime inventory unavailable: global orphan checks are skipped and runtime-correlated detections are conservative")
	}
	return report.New(runtimeName, runtimes, leaks, warnings)
}

func runtimeInventoryAvailable(runtimes []runtimeinv.Inventory) bool {
	for _, runtimeInventory := range runtimes {
		if runtimeInventory.Available {
			return true
		}
	}
	return false
}

func runtimeInventoryPartial(runtimes []runtimeinv.Inventory) bool {
	for _, runtimeInventory := range runtimes {
		if !runtimeInventory.Available {
			return true
		}
	}
	return false
}

func runExplain(args []string, stdout io.Writer) error {
	options, err := parseLeakCommandArgs("explain", args)
	if err != nil {
		return commandError{message: err.Error(), usage: true}
	}
	if !validRuntime(options.runtimeName) {
		return commandError{message: fmt.Sprintf("invalid runtime %q", options.runtimeName), usage: true}
	}

	scanReport := buildScanReportFunc(runtimeinv.Name(options.runtimeName), detect.SeverityLow)
	target := findLeak(scanReport.Leaks, options.leakID)
	if target == nil {
		return fmt.Errorf("leak %q not found in current scan", options.leakID)
	}

	return report.WriteExplain(stdout, *target)
}

func runCleanup(args []string, stdout io.Writer) error {
	options, err := parseCleanupArgs(args)
	if err != nil {
		return commandError{message: err.Error(), usage: true}
	}
	if !validRuntime(options.runtimeName) {
		return commandError{message: fmt.Sprintf("invalid runtime %q", options.runtimeName), usage: true}
	}

	scanReport := buildScanReportFunc(runtimeinv.Name(options.runtimeName), detect.SeverityLow)
	target := findLeak(scanReport.Leaks, options.leakID)
	if target == nil {
		return fmt.Errorf("leak %q not found in current scan", options.leakID)
	}
	if len(target.CleanupPlan) == 0 {
		return fmt.Errorf("leak %q has no cleanup plan", options.leakID)
	}

	mode := "plan"
	switch {
	case options.dryRun:
		mode = "dry-run"
	case options.force:
		mode = "force"
	}

	if _, err := fmt.Fprintf(stdout, "cleanup %s\nmode: %s\n\n", options.leakID, mode); err != nil {
		return err
	}
	switch {
	case options.dryRun:
		if _, err := fmt.Fprint(stdout, "dry-run: no commands will be executed\n\n"); err != nil {
			return err
		}
	case !options.force && cleanupPlanHasDestructive(target.CleanupPlan):
		if _, err := fmt.Fprint(stdout, "force not set: destructive steps will be skipped\n\n"); err != nil {
			return err
		}
	}
	_, err = cleanup.Execute(stdout, target.CleanupPlan, cleanup.Options{
		DryRun: options.dryRun,
		Force:  options.force,
	})
	return err
}

func cleanupPlanHasDestructive(steps []cleanup.Step) bool {
	for _, step := range steps {
		if step.Destructive {
			return true
		}
	}
	return false
}

type cleanupArgs struct {
	leakID      string
	dryRun      bool
	force       bool
	runtimeName string
}

type leakCommandArgs struct {
	leakID      string
	runtimeName string
}

func parseLeakCommandArgs(command string, args []string) (leakCommandArgs, error) {
	out := leakCommandArgs{runtimeName: "auto"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--runtime":
			i++
			if i >= len(args) {
				return out, errors.New("--runtime requires a value")
			}
			out.runtimeName = args[i]
		case len(arg) > len("--runtime=") && arg[:len("--runtime=")] == "--runtime=":
			out.runtimeName = arg[len("--runtime="):]
		case len(arg) > 0 && arg[0] == '-':
			return out, fmt.Errorf("unknown %s flag %q", command, arg)
		default:
			if out.leakID != "" {
				return out, fmt.Errorf("%s requires exactly one leak id", command)
			}
			out.leakID = arg
		}
	}
	if out.leakID == "" {
		return out, fmt.Errorf("%s requires exactly one leak id", command)
	}
	return out, nil
}

func parseCleanupArgs(args []string) (cleanupArgs, error) {
	leakArgs, err := parseLeakCommandArgs("cleanup", filterCleanupFlags(args))
	if err != nil {
		return cleanupArgs{}, err
	}
	out := cleanupArgs{leakID: leakArgs.leakID, runtimeName: leakArgs.runtimeName}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dry-run":
			out.dryRun = true
		case arg == "--force":
			out.force = true
		case arg == "--runtime":
			i++
		case len(arg) > len("--runtime=") && arg[:len("--runtime=")] == "--runtime=":
			continue
		}
	}
	return out, nil
}

func filterCleanupFlags(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--dry-run" || arg == "--force" {
			continue
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func findLeak(leaks []detect.Leak, id string) *detect.Leak {
	for i := range leaks {
		if leaks[i].ID == id {
			return &leaks[i]
		}
	}
	return nil
}

func validRuntime(name string) bool {
	return runtimeinv.ValidName(runtimeinv.Name(name))
}
