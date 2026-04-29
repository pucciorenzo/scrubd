package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"scrubd/internal/cleanup"
)

type LeakType string

const (
	LeakTypeVethInterface   LeakType = "orphaned_veth_interface"
	LeakTypeNetworkBridge   LeakType = "stale_network_bridge"
	LeakTypeRoute           LeakType = "stale_network_route"
	LeakTypeNetworkNS       LeakType = "stale_network_namespace"
	LeakTypeOverlaySnapshot LeakType = "dangling_overlay_snapshot"
	LeakTypeMount           LeakType = "abandoned_container_mount"
	LeakTypeCgroup          LeakType = "stale_cgroup"
	LeakTypeRuntimeProcess  LeakType = "orphaned_runtime_process"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Leak struct {
	ID          string         `json:"id"`
	Type        LeakType       `json:"type"`
	Severity    Severity       `json:"severity"`
	Resource    string         `json:"resource"`
	Reason      string         `json:"reason"`
	Evidence    []string       `json:"evidence,omitempty"`
	SafeAction  string         `json:"safe_action,omitempty"`
	RiskNotes   string         `json:"risk_notes,omitempty"`
	CleanupPlan []cleanup.Step `json:"cleanup_plan,omitempty"`
}

func NewLeak(leakType LeakType, severity Severity, resource, reason string) Leak {
	leak := Leak{
		Type:     leakType,
		Severity: severity,
		Resource: resource,
		Reason:   reason,
	}
	leak.ID = StableID(leakType, resource)
	return leak
}

func StableID(leakType LeakType, resource string) string {
	key := strings.ToLower(strings.TrimSpace(string(leakType))) + "\x00" + strings.TrimSpace(resource)
	sum := sha256.Sum256([]byte(key))
	return "leak-" + hex.EncodeToString(sum[:])[:12]
}

func (l Leak) Validate() bool {
	return l.ID != "" &&
		l.Type != "" &&
		l.Severity != "" &&
		l.Resource != "" &&
		l.Reason != ""
}

func ValidSeverity(severity Severity) bool {
	return SeverityRank(severity) > 0
}

func SeverityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func FilterByMinSeverity(leaks []Leak, min Severity) []Leak {
	if !ValidSeverity(min) || min == SeverityLow {
		return leaks
	}

	filtered := make([]Leak, 0, len(leaks))
	for _, leak := range leaks {
		if SeverityRank(leak.Severity) >= SeverityRank(min) {
			filtered = append(filtered, leak)
		}
	}
	return filtered
}
