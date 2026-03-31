package prompter

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Input represents a password prompt (no UI dependencies)
type Input struct {
	prompt      string
	confirm     bool
	confirmMsg  string
	mismatchMsg string
	required    bool
	requiredMsg string
	minLength   int
	minMsg      string
	promptFunc  func(prompt string) string // Optional prompt formatter
}

// WithPromptFormatter sets a custom prompt formatter
func (p *Input) WithPromptFormatter(formatter Formatter) *Input {
	p.promptFunc = formatter
	return p
}

// NewInput creates a new password input builder with optional functional options.
//
//	input := NewInput("Master passphrase", WithConfirm(), WithRequired(true, "required"))
func NewInput(prompt string, opts ...func(*Input)) *Input {
	p := &Input{
		prompt:      prompt,
		confirm:     false,
		confirmMsg:  "Confirm password",
		mismatchMsg: "passwords do not match",
		required:    false,
		requiredMsg: "password is required",
		minLength:   0,
		minMsg:      "password is too short",
		promptFunc:  defaultPromptFormatter,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Run executes the password input and returns a secure result.
// term.ReadPassword manages raw-mode internally.
func (p *Input) Run() (*Result, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("input is not a terminal")
	}

	fmt.Fprint(os.Stdout, p.promptFunc(p.prompt))
	pass1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return nil, err
	}

	defer func() {
		for i := range pass1 {
			pass1[i] = 0
		}
	}()

	if p.required && len(pass1) == 0 {
		return nil, errors.New(p.requiredMsg)
	}

	if p.minLength > 0 && len(pass1) < p.minLength {
		return nil, fmt.Errorf("%s (minimum %d characters)", p.minMsg, p.minLength)
	}

	if p.confirm {
		fmt.Fprint(os.Stdout, p.promptFunc(p.confirmMsg))
		pass2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stdout)
		if err != nil {
			return nil, err
		}
		defer func() {
			for i := range pass2 {
				pass2[i] = 0
			}
		}()

		if !bytes.Equal(pass1, pass2) {
			return nil, errors.New(p.mismatchMsg)
		}
	}

	result := make([]byte, len(pass1))
	copy(result, pass1)
	return NewResult(result), nil
}
