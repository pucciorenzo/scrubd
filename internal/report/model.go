package report

import (
	"time"

	"scrubd/internal/detect"
	runtimeinv "scrubd/internal/runtime"
)

const SchemaVersion = "scrubd.scan.v1"

type Report struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   time.Time              `json:"generated_at"`
	Runtime       runtimeinv.Name        `json:"runtime"`
	Runtimes      []runtimeinv.Inventory `json:"runtimes"`
	Leaks         []detect.Leak          `json:"leaks"`
	Warnings      []string               `json:"warnings,omitempty"`
	Summary       Summary                `json:"summary"`
}

type Summary struct {
	LeakCount      int `json:"leak_count"`
	CriticalCount  int `json:"critical_count"`
	HighCount      int `json:"high_count"`
	MediumCount    int `json:"medium_count"`
	LowCount       int `json:"low_count"`
	RuntimeCount   int `json:"runtime_count"`
	AvailableCount int `json:"available_runtime_count"`
	ContainerCount int `json:"container_count"`
}

func New(runtime runtimeinv.Name, runtimes []runtimeinv.Inventory, leaks []detect.Leak, warnings []string) Report {
	if runtimes == nil {
		runtimes = []runtimeinv.Inventory{}
	}
	if leaks == nil {
		leaks = []detect.Leak{}
	}
	return Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Runtime:       runtime,
		Runtimes:      runtimes,
		Leaks:         leaks,
		Warnings:      warnings,
		Summary:       summarize(runtimes, leaks),
	}
}

func summarize(runtimes []runtimeinv.Inventory, leaks []detect.Leak) Summary {
	summary := Summary{
		LeakCount:    len(leaks),
		RuntimeCount: len(runtimes),
	}

	for _, inv := range runtimes {
		if inv.Available {
			summary.AvailableCount++
		}
		summary.ContainerCount += len(inv.Containers)
	}

	for _, leak := range leaks {
		switch leak.Severity {
		case detect.SeverityCritical:
			summary.CriticalCount++
		case detect.SeverityHigh:
			summary.HighCount++
		case detect.SeverityMedium:
			summary.MediumCount++
		case detect.SeverityLow:
			summary.LowCount++
		}
	}

	return summary
}
