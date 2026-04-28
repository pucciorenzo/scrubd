package report

import (
	"encoding/json"
	"io"
)

func WriteJSON(w io.Writer, report Report) error {
	if report.SchemaVersion == "" {
		report.SchemaVersion = SchemaVersion
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
