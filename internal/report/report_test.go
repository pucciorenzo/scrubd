package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

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
}

func TestWriteText(t *testing.T) {
	leak := detect.NewLeak(detect.LeakTypeVethInterface, detect.SeverityHigh, "veth0", "test reason")
	leak.SafeAction = "ip link delete veth0"
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
	for _, want := range []string{"Container leak scan report", "[HIGH] orphaned_veth_interface", "suggested action: ip link delete veth0", "warnings:"} {
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
	leak.CleanupPlan = leak.CleanupPlan[:0]

	var buf bytes.Buffer
	if err := WriteExplain(&buf, leak); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{"Leak explanation", "namespace inode: 10", "risk: verify owner first", "suggested action: ip netns delete test ns"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}
