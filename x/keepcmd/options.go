// Package keepcmd provides reusable keeper command operations decoupled from
// any specific CLI framework or application. Callers supply a StoreFactory and
// an Output implementation; keepcmd handles all business logic.
//
// Passphrase resolution is entirely the caller's responsibility — keepcmd never
// prompts for input directly. This keeps the package safe in headless server
// contexts where no terminal exists.
package keepcmd

import "time"

// SetOptions controls how Set stores a value.
type SetOptions struct {
	// FromFile reads the value from this path instead of Value.
	FromFile string
	// Base64 decodes Value as standard base64 before storing.
	Base64 bool
}

// BackupOptions controls the Backup operation.
type BackupOptions struct {
	// Dest is the file path to write the backup. If empty, a timestamped
	// name is generated in the current directory.
	Dest string
}

// generatedBackupName returns a timestamped backup filename.
func generatedBackupName() string {
	return "keeper-backup-" + time.Now().Format("20060102-150405") + ".db"
}
