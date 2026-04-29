package report

import (
	"fmt"
	"io"
	"strings"
)

func WriteText(w io.Writer, report Report) error {
	if _, err := fmt.Fprintln(w, "Container leak scan report"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\ngenerated: %s\n", report.GeneratedAt.Format("2006-01-02T15:04:05Z07:00")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "runtime: %s\n", report.Runtime); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "runtimes: %d available / %d checked\n", report.Summary.AvailableCount, report.Summary.RuntimeCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "containers: %d\n", report.Summary.ContainerCount); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "leaks: %d (critical=%d high=%d medium=%d low=%d)\n",
		report.Summary.LeakCount,
		report.Summary.CriticalCount,
		report.Summary.HighCount,
		report.Summary.MediumCount,
		report.Summary.LowCount,
	); err != nil {
		return err
	}

	if len(report.Warnings) > 0 {
		if _, err := fmt.Fprintln(w, "\nwarnings:"); err != nil {
			return err
		}
		for _, warning := range report.Warnings {
			if _, err := fmt.Fprintf(w, "  - %s\n", warning); err != nil {
				return err
			}
		}
	}

	if len(report.Leaks) == 0 {
		_, err := fmt.Fprintln(w, "\nNo leaks detected.")
		return err
	}

	for _, leak := range report.Leaks {
		if _, err := fmt.Fprintf(w, "\n[%s] %s\n", strings.ToUpper(string(leak.Severity)), leak.Type); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  id: %s\n", leak.ID); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  resource: %s\n", leak.Resource); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  reason: %s\n", leak.Reason); err != nil {
			return err
		}
		if leak.SafeAction != "" {
			if _, err := fmt.Fprintf(w, "  suggested action: %s\n", leak.SafeAction); err != nil {
				return err
			}
		}
		for _, evidence := range leak.Evidence {
			if _, err := fmt.Fprintf(w, "  evidence: %s\n", evidence); err != nil {
				return err
			}
		}
		if leak.RiskNotes != "" {
			if _, err := fmt.Fprintf(w, "  risk: %s\n", leak.RiskNotes); err != nil {
				return err
			}
		}
		if len(leak.CleanupPlan) > 0 {
			if _, err := fmt.Fprintf(w, "  cleanup: available (%d step%s)\n", len(leak.CleanupPlan), plural(len(leak.CleanupPlan))); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintln(w, "  cleanup: manual review required"); err != nil {
				return err
			}
		}
		if next := explainNextStep(leak); next != "" {
			if _, err := fmt.Fprintf(w, "  next step: %s\n", next); err != nil {
				return err
			}
		}
	}

	return nil
}

func plural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
