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

// Table renders headers and rows as a dynamic-width table.
// Column widths are computed from the actual content so long keys
// (e.g. vault://system/jwt_secret) are never truncated or padded excessively.
func (p PlainOutput) Table(headers []string, rows [][]string) {
	if len(headers) == 0 && len(rows) == 0 {
		return
	}

	// Compute column widths: max of header width and widest cell.
	ncols := len(headers)
	for _, row := range rows {
		if len(row) > ncols {
			ncols = len(row)
		}
	}
	widths := make([]int, ncols)
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < ncols && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	if len(headers) > 0 {
		for i, h := range headers {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("%-*s", widths[i], h)
		}
		fmt.Println()
		for i, w := range widths {
			if i > 0 {
				fmt.Print("  ")
			}
			for j := 0; j < w; j++ {
				fmt.Print("─")
			}
		}
		fmt.Println()
	}
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Print("  ")
			}
			if i < ncols {
				fmt.Printf("%-*s", widths[i], cell)
			} else {
				fmt.Print(cell)
			}
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
