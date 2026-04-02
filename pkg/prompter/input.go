package prompter

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// Input represents a no-echo password/passphrase prompt.
type Input struct {
	prompt      string
	confirm     bool
	confirmMsg  string
	mismatchMsg string
	required    bool
	requiredMsg string
	minLength   int
	minMsg      string
	promptFunc  func(prompt string) string
}

// WithPromptFormatter sets a custom prompt formatter.
func (p *Input) WithPromptFormatter(formatter Formatter) *Input {
	p.promptFunc = formatter
	return p
}

// NewInput creates a new no-echo input builder with optional functional options.
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

// Run executes the no-echo prompt and returns a secure Result.
// Returns an error if stdin is not a terminal.
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
	defer wipeSlice(pass1)

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
		defer wipeSlice(pass2)

		if !bytes.Equal(pass1, pass2) {
			return nil, errors.New(p.mismatchMsg)
		}
	}

	result := make([]byte, len(pass1))
	copy(result, pass1)
	return NewResult(result), nil
}

// ── SecretInput ───────────────────────────────────────────────────────────────

// SecretInput reads a single secret value from the terminal with no echo.
// It is intentionally simpler than Input — no confirmation, no min-length —
// because it is used for storing secret values, not for passphrase entry.
//
// Use this in the REPL's "set" command instead of reading the value as a
// command-line argument, which would expose it in terminal scrollback and
// shell history.
//
//	result, err := prompter.ReadSecret("Value for " + key)
//	if err != nil { ... }
//	defer result.Zero()
//	cmds.Set(key, string(result.Bytes()), keepcmd.SetOptions{})
func ReadSecret(prompt string) (*Result, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("input is not a terminal")
	}

	fmt.Fprintf(os.Stdout, "%s (hidden): ", prompt)
	val, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return nil, err
	}
	defer wipeSlice(val)

	if len(val) == 0 {
		return nil, errors.New("value cannot be empty")
	}

	result := make([]byte, len(val))
	copy(result, val)
	return NewResult(result), nil
}

// ── Select ────────────────────────────────────────────────────────────────────

// Select displays a numbered list of choices on stderr and reads the user's
// selection from stdin. It does not use raw mode — the user sees their input.
// This replaces huh.Select for non-secret interactive menus.
//
//	path, err := prompter.Select("Multiple databases found", paths)
func Select(prompt string, choices []string) (int, error) {
	if len(choices) == 0 {
		return 0, errors.New("no choices provided")
	}

	fmt.Fprintln(os.Stderr, prompt+":")
	for i, c := range choices {
		fmt.Fprintf(os.Stderr, "  [%d] %s\n", i+1, c)
	}
	fmt.Fprintf(os.Stderr, "Select [1-%d] (default 1): ", len(choices))

	var line string
	fmt.Scanln(&line)
	if line == "" {
		return 0, nil // caller gets index 0 = first choice
	}

	var n int
	if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(choices) {
		return 0, fmt.Errorf("invalid selection %q", line)
	}
	return n - 1, nil
}

// Confirm prints prompt to stderr and returns true only when the user
// types "y" or "Y". Any other input, including empty, returns false.
// This replaces huh.Confirm for simple yes/no prompts.
func Confirm(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt+" [y/N] ")
	var line string
	fmt.Scanln(&line)
	return line == "y" || line == "Y", nil
}

// ── internal ──────────────────────────────────────────────────────────────────

func wipeSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
