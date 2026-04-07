package main

import (
	"fmt"
	"path/filepath"

	"github.com/olekukonko/prompter"
)

// pickDB asks the user to select from multiple .db files found in the current
// directory. Uses prompter.Select — no TUI dependency required.
func pickDB(paths []string) (string, error) {
	labels := make([]string, len(paths))
	for i, p := range paths {
		labels[i] = filepath.Base(p)
	}
	idx, err := prompter.Select("Multiple databases found", labels)
	if err != nil {
		return "", fmt.Errorf("db selection: %w", err)
	}
	return paths[idx], nil
}
