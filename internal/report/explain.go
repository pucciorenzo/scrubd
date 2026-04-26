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
