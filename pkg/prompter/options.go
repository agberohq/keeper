package prompter

import "fmt"

// Formatter formats a prompt string for display.
type Formatter func(prompt string) string

// WithConfirm adds a confirmation prompt.
func WithConfirm() func(*Input) {
	return func(p *Input) {
		p.confirm = true
	}
}

// WithConfirmMsg sets a custom confirmation prompt message and enables confirmation.
func WithConfirmMsg(msg string) func(*Input) {
	return func(p *Input) {
		p.confirm = true
		p.confirmMsg = msg
	}
}

// WithMismatchMsg sets the error message shown when confirmation does not match.
func WithMismatchMsg(msg string) func(*Input) {
	return func(p *Input) {
		p.mismatchMsg = msg
	}
}

// WithRequired marks the input as required (non-empty).
func WithRequired(required bool, msg string) func(*Input) {
	return func(p *Input) {
		p.required = required
		p.requiredMsg = msg
	}
}

// WithMinLength sets a minimum byte length for the entered value.
func WithMinLength(n int, msg string) func(*Input) {
	return func(p *Input) {
		p.minLength = n
		p.minMsg = msg
	}
}

// defaultPromptFormatter is the default prompt formatter.
func defaultPromptFormatter(prompt string) string {
	return fmt.Sprintf("%s: ", prompt)
}

// Quick prompts for a single password with minimal options.
func Quick(prompt string) (*Result, error) {
	return NewInput(prompt).Run()
}

// QuickWithConfirm prompts for a password with confirmation.
func QuickWithConfirm(prompt string) (*Result, error) {
	return NewInput(prompt, WithConfirm()).Run()
}
