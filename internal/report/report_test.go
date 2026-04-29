package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"scrubd/internal/cleanup"
	"scrubd/internal/detect"
	runtimeinv "scrubd/internal/runtime"
)

func TestNewSummarizesReport(t *testing.T) {
	leaks := []detect.Leak{
		detect.NewLeak(detect.LeakTypeVethInterface, detect.SeverityHigh, "veth0", "test"),
		detect.NewLeak(detect.LeakTypeNetworkNS, detect.SeverityMedium, "/var/run/netns/test", "test"),
	}
	runtimes := []runtimeinv.Inventory{{
		Runtime:    runtimeinv.NameDocker,
		Available:  true,
		Containers: []runtimeinv.Container{{ID: "abc"}},
	}}

	report := New(runtimeinv.NameAuto, runtimes, leaks, []string{"warning"})
	if report.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q", report.SchemaVersion)
	}
	if report.Summary.LeakCount != 2 || report.Summary.HighCount != 1 || report.Summary.MediumCount != 1 {
		t.Fatalf("unexpected leak summary: %#v", report.Summary)
	}
	if report.Summary.AvailableCount != 1 || report.Summary.ContainerCount != 1 {
		t.Fatalf("unexpected runtime summary: %#v", report.Summary)
	}
}

func TestNewUsesEmptySlices(t *testing.T) {
	report := New(runtimeinv.NameAuto, nil, nil, nil)
	if report.Runtimes == nil {
		t.Fatal("runtimes is nil")
	}
	if report.Leaks == nil {
		t.Fatal("leaks is nil")
	}
}

func TestNewNormalizesWarnings(t *testing.T) {
	report := New(runtimeinv.NameAuto, nil, nil, []string{
		" docker unavailable ",
		"",
		"containerd unavailable",
		"docker unavailable",
		"  ",
	})

	want := []string{"docker unavailable", "containerd unavailable"}
	if len(report.Warnings) != len(want) {
		t.Fatalf("warnings = %#v, want %#v", report.Warnings, want)
	}
	for i := range want {
		if report.Warnings[i] != want[i] {
			t.Fatalf("warnings = %#v, want %#v", report.Warnings, want)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	report := Report{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Runtime:     runtimeinv.NameDocker,
		Summary:     Summary{},
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, report); err != nil {
		t.Fatal(err)
	}

	var decoded Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Runtime != runtimeinv.NameDocker {
		t.Fatalf("runtime = %q", decoded.Runtime)
	}
	if decoded.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q", decoded.SchemaVersion)
	}
}

func TestWriteText(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeVethInterface, detect.SeverityHigh, "veth0", "test reason")
	leak.SafeAction = "ip link delete veth0"
	leak.CleanupPlan = []cleanup.Step{{
		Description: "delete veth interface veth0",
		Command:     []string{"ip", "link", "delete", "veth0"},
		Destructive: true,
	}}
	report := Report{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Runtime:     runtimeinv.NameAuto,
		Leaks:       []detect.Leak{leak},
		Warnings:    []string{"docker unavailable"},
		Summary:     summarize(nil, []detect.Leak{leak}),
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, report); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"Container leak scan report",
		"[HIGH] orphaned_veth_interface",
		"suggested action: ip link delete veth0",
		"cleanup: available (1 step)",
		"next step: run `scrubd cleanup " + leak.ID + " --dry-run`, confirm the interface is not attached to a live workload",
		"warnings:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTextShowsManualCleanupForPlanlessLeak(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeOverlaySnapshot, detect.SeverityLow, "/var/lib/docker/overlay2/snap", "snapshot is not mounted")
	leak.SafeAction = "docker runtime garbage collection or manual snapshot review"
	report := Report{
		GeneratedAt: time.Unix(0, 0).UTC(),
		Runtime:     runtimeinv.NameDocker,
		Leaks:       []detect.Leak{leak},
		Summary:     summarize(nil, []detect.Leak{leak}),
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, report); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"cleanup: manual review required",
		"next step: review runtime snapshot metadata and use runtime-supported garbage collection",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteExplain(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeNetworkNS, detect.SeverityMedium, "/var/run/netns/test ns", "no process owns namespace")
	leak.Evidence = []string{"namespace inode: 10"}
	leak.SafeAction = "ip netns delete test ns"
	leak.RiskNotes = "verify owner first"
	leak.CleanupPlan = []cleanup.Step{{
		Description: "delete network namespace test ns",
		Command:     []string{"ip", "netns", "delete", "test ns"},
		Destructive: true,
	}}

	var buf bytes.Buffer
	if err := WriteExplain(&buf, leak); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"Leak explanation",
		"namespace inode: 10",
		"risk: verify owner first",
		"suggested action: ip netns delete test ns",
		"next step: run `scrubd cleanup " + leak.ID + " --dry-run`, confirm no process, CNI plugin, or workload still owns the namespace",
		"command: ip netns delete 'test ns'",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteExplainWithoutCleanupPlanShowsManualNextStep(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeOverlaySnapshot, detect.SeverityLow, "/var/lib/docker/overlay2/snap", "snapshot is not mounted")
	leak.SafeAction = "docker runtime garbage collection or manual snapshot review"

	var buf bytes.Buffer
	if err := WriteExplain(&buf, leak); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"suggested action: docker runtime garbage collection or manual snapshot review",
		"next step: review runtime snapshot metadata and use runtime-supported garbage collection",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cleanup plan:") {
		t.Fatalf("output includes cleanup plan for manual-only leak:\n%s", out)
	}
}
