package cleanup

// Step describes one command in a cleanup plan. Command is argv-form and must
// be executed without shell expansion.
type Step struct {
	Description string   `json:"description"`
	Command     []string `json:"command"`
	Destructive bool     `json:"destructive"`
}

func (s Step) Validate() bool {
	return s.Description != "" && len(s.Command) > 0 && s.Command[0] != ""
}
