package report

import (
	"fmt"
	"io"

	"scrubd/internal/cleanup"
	"scrubd/internal/detect"
)

func WriteExplain(w io.Writer, leak detect.Leak) error {
	if _, err := fmt.Fprintf(w, "Leak explanation\n\nid: %s\n", leak.ID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "type: %s\nseverity: %s\nresource: %s\n", leak.Type, leak.Severity, leak.Resource); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "reason: %s\n", leak.Reason); err != nil {
		return err
	}

	if len(leak.Evidence) > 0 {
		if _, err := fmt.Fprintln(w, "\nevidence:"); err != nil {
			return err
		}
		for _, item := range leak.Evidence {
			if _, err := fmt.Fprintf(w, "  - %s\n", item); err != nil {
				return err
			}
		}
	}

	if leak.RiskNotes != "" {
		if _, err := fmt.Fprintf(w, "\nrisk: %s\n", leak.RiskNotes); err != nil {
			return err
		}
	}
	if leak.SafeAction != "" {
		if _, err := fmt.Fprintf(w, "suggested action: %s\n", leak.SafeAction); err != nil {
			return err
		}
	}
	if next := explainNextStep(leak); next != "" {
		if _, err := fmt.Fprintf(w, "next step: %s\n", next); err != nil {
			return err
		}
	}

	if len(leak.CleanupPlan) > 0 {
		if _, err := fmt.Fprintln(w, "\ncleanup plan:"); err != nil {
			return err
		}
		for _, step := range leak.CleanupPlan {
			if _, err := fmt.Fprintf(w, "  - %s\n    command: %s\n", step.Description, cleanup.FormatCommand(step.Command)); err != nil {
				return err
			}
		}
	}

	return nil
}

func explainNextStep(leak detect.Leak) string {
	if len(leak.CleanupPlan) > 0 {
		return fmt.Sprintf("run `scrubd cleanup %s --dry-run`, %s, then rerun with `--force` only if the resource is safe to modify", leak.ID, cleanupReviewGuidance(leak.Type))
	}

	switch leak.Type {
	case detect.LeakTypeOverlaySnapshot:
		return "review runtime snapshot metadata and use runtime-supported garbage collection; scrubd does not generate a direct remove command for snapshot directories"
	default:
		if leak.SafeAction != "" {
			return "review the suggested action manually; scrubd does not have a direct cleanup plan for this finding"
		}
		return "review the evidence manually; scrubd does not have a direct cleanup plan for this finding"
	}
}

func cleanupReviewGuidance(leakType detect.LeakType) string {
	switch leakType {
	case detect.LeakTypeVethInterface:
		return "confirm the interface is not attached to a live workload"
	case detect.LeakTypeNetworkNS:
		return "confirm no process, CNI plugin, or workload still owns the namespace"
	case detect.LeakTypeMount:
		return "confirm no process or runtime task is using the mount"
	case detect.LeakTypeCgroup:
		return "confirm the cgroup is empty and no runtime still owns it"
	case detect.LeakTypeRuntimeProcess:
		return "confirm the helper process is not attached to a live workload"
	default:
		return "review the command and evidence"
	}
}
