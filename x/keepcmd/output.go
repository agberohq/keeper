package keepcmd

import "fmt"

// Output is the display contract keepcmd writes to.
// Implementations can render to a terminal, a test buffer, or anywhere else.
type Output interface {
	// Table renders a header row followed by data rows.
	Table(headers []string, rows [][]string)
	// KeyValue prints a single labelled value.
	KeyValue(label, value string)
	// Success prints a success message.
	Success(msg string)
	// Info prints an informational message.
	Info(msg string)
	// Error prints an error message without terminating.
	Error(msg string)
}

// PlainOutput writes plain text to stdout. It is the default used by the
// standalone binary when not in interactive/TUI mode.
type PlainOutput struct{}

// Table renders headers and rows as a simple fixed-width table.
func (p PlainOutput) Table(headers []string, rows [][]string) {
	if len(headers) > 0 {
		for i, h := range headers {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("%-30s", h)
		}
		fmt.Println()
		for range headers {
			fmt.Printf("%-30s", "──────────────────────────────")
		}
		fmt.Println()
	}
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("%-30s", cell)
		}
		fmt.Println()
	}
}

// KeyValue prints "label: value".
func (p PlainOutput) KeyValue(label, value string) {
	fmt.Printf("%s: %s\n", label, value)
}

// Success prints a prefixed success message.
func (p PlainOutput) Success(msg string) { fmt.Println("✓ " + msg) }

// Info prints a prefixed informational message.
func (p PlainOutput) Info(msg string) { fmt.Println("  " + msg) }

// Error prints a prefixed error message.
func (p PlainOutput) Error(msg string) { fmt.Println("✗ " + msg) }
