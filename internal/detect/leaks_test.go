package detect

import "testing"

func TestStableID(t *testing.T) {
	first := StableID(LeakTypeVethInterface, "veth9f31a2")
	second := StableID(LeakTypeVethInterface, "veth9f31a2")

	if first != second {
		t.Fatalf("StableID changed across calls: %q != %q", first, second)
	}
	if first != "leak-f03aba9c2c00" {
		t.Fatalf("StableID = %q, want %q", first, "leak-f03aba9c2c00")
	}
}

func TestNewLeak(t *testing.T) {
	leak := NewLeak(LeakTypeNetworkNS, SeverityMedium, "/var/run/netns/cni-test", "no active container task found")

	if !leak.Validate() {
		t.Fatalf("NewLeak produced invalid leak: %#v", leak)
	}
	if leak.ID == "" {
		t.Fatal("NewLeak did not assign ID")
	}
}

func TestValidSeverity(t *testing.T) {
	for _, severity := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !ValidSeverity(severity) {
			t.Fatalf("ValidSeverity(%q) = false, want true", severity)
		}
	}
	if ValidSeverity("unknown") {
		t.Fatal("ValidSeverity accepted unknown severity")
	}
}

func TestFilterByMinSeverity(t *testing.T) {
	leaks := []Leak{
		NewLeak(LeakTypeCgroup, SeverityLow, "low", "test"),
		NewLeak(LeakTypeNetworkNS, SeverityMedium, "medium", "test"),
		NewLeak(LeakTypeVethInterface, SeverityHigh, "high", "test"),
	}

	filtered := FilterByMinSeverity(leaks, SeverityMedium)
	if len(filtered) != 2 {
		t.Fatalf("len(filtered) = %d, want 2: %#v", len(filtered), filtered)
	}
	if filtered[0].Severity != SeverityMedium || filtered[1].Severity != SeverityHigh {
		t.Fatalf("unexpected filtered leaks: %#v", filtered)
	}
}

func TestFilterByMinSeverityKeepsAllForLowOrUnknown(t *testing.T) {
	leaks := []Leak{
		NewLeak(LeakTypeCgroup, SeverityLow, "low", "test"),
	}
	if got := FilterByMinSeverity(leaks, SeverityLow); len(got) != 1 {
		t.Fatalf("low filter len = %d, want 1", len(got))
	}
	if got := FilterByMinSeverity(leaks, "unknown"); len(got) != 1 {
		t.Fatalf("unknown filter len = %d, want 1", len(got))
	}
}
