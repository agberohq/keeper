package prompter

import "fmt"

// PromptFormatter is a function that formats a prompt string
type Formatter func(prompt string) string

// WithConfirm adds confirmation prompt
func WithConfirm() func(*Input) {
	return func(p *Input) {
		p.confirm = true
	}
}

// WithConfirmMsg custom confirmation prompt message
func WithConfirmMsg(msg string) func(*Input) {
	return func(p *Input) {
		p.confirm = true
		p.confirmMsg = msg
	}
}

// WithMismatchMsg custom mismatch error message
func WithMismatchMsg(msg string) func(*Input) {
	return func(p *Input) {
		p.mismatchMsg = msg
	}
}

// WithRequired marks password as required
func WithRequired(required bool, msg string) func(*Input) {
	return func(p *Input) {
		p.required = required
		p.requiredMsg = msg
	}
}

// WithMinLength sets minimum password length
func WithMinLength(n int, msg string) func(*Input) {
	return func(p *Input) {
		p.minLength = n
		p.minMsg = msg
	}
}

// defaultPromptFormatter is the default prompt formatter
func defaultPromptFormatter(prompt string) string {
	return fmt.Sprintf("%s: ", prompt)
}

// Quick prompts for a single password with minimal options
func Quick(prompt string) (*Result, error) {
	return NewInput(prompt).Run()
}

// QuickWithConfirm prompts for a password with confirmation
func QuickWithConfirm(prompt string) (*Result, error) {
	return NewInput(prompt, WithConfirm()).Run()
}
