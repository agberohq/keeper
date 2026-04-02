// Command keeper is a standalone secret management CLI backed by keeper.Keeper.
// Run with: go run ./cmd/keeper  (not go run main.go — multiple source files)
package main

import (
	"fmt"
	"os"

	"github.com/integrii/flaggy"
	"golang.org/x/term"
)

func main() {
	flaggy.SetName("keeper")
	flaggy.SetDescription("Encrypted secret store — manage secrets from the command line")
	flaggy.SetVersion(version + " (" + commit + ") built " + date)

	var dbFlag string
	flaggy.String(&dbFlag, "d", "db", "Database file path (env: KEEPER_DB)")

	listCmd := flaggy.NewSubcommand("list")
	listCmd.ShortName = "ls"
	listCmd.Description = "List all secret keys"
	flaggy.AttachSubcommand(listCmd, 1)

	getCmd := flaggy.NewSubcommand("get")
	getCmd.ShortName = "cat"
	getCmd.Description = "Read a secret value"
	var getKey string
	getCmd.AddPositionalValue(&getKey, "key", 1, true, "Secret key to retrieve")
	flaggy.AttachSubcommand(getCmd, 1)

	setCmd := flaggy.NewSubcommand("set")
	setCmd.ShortName = "put"
	setCmd.Description = "Store a secret value"
	var setKey, setValue, setFile string
	var setB64 bool
	setCmd.AddPositionalValue(&setKey, "key", 1, true, "Secret key")
	setCmd.AddPositionalValue(&setValue, "value", 2, false, "Secret value (omit with --file)")
	setCmd.String(&setFile, "f", "file", "Read value from file instead of argument")
	setCmd.Bool(&setB64, "b", "base64", "Decode value as base64 before storing")
	flaggy.AttachSubcommand(setCmd, 1)

	deleteCmd := flaggy.NewSubcommand("delete")
	deleteCmd.ShortName = "rm"
	deleteCmd.Description = "Remove a secret"
	var deleteKey string
	var deleteForce bool
	deleteCmd.AddPositionalValue(&deleteKey, "key", 1, true, "Secret key to delete")
	deleteCmd.Bool(&deleteForce, "f", "force", "Skip confirmation prompt")
	flaggy.AttachSubcommand(deleteCmd, 1)

	rotateCmd := flaggy.NewSubcommand("rotate")
	rotateCmd.Description = "Change the master passphrase"
	flaggy.AttachSubcommand(rotateCmd, 1)

	rotateSaltCmd := flaggy.NewSubcommand("rotate-salt")
	rotateSaltCmd.Description = "Rotate the KDF salt (re-encrypts all secrets)"
	flaggy.AttachSubcommand(rotateSaltCmd, 1)

	backupCmd := flaggy.NewSubcommand("backup")
	backupCmd.Description = "Backup the database to a file"
	var backupDest string
	backupCmd.String(&backupDest, "o", "out", "Output file (default: timestamped name)")
	flaggy.AttachSubcommand(backupCmd, 1)

	statusCmd := flaggy.NewSubcommand("status")
	statusCmd.Description = "Show lock state of the store"
	flaggy.AttachSubcommand(statusCmd, 1)

	flaggy.Parse()

	// No subcommand + TTY → launch REPL session (unlock once, loop commands).
	if !anyUsed(listCmd, getCmd, setCmd, deleteCmd, rotateCmd, rotateSaltCmd, backupCmd, statusCmd) {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			res, err := resolveDBPath(dbFlag)
			if err != nil {
				fatalf("db path: %v", err)
			}
			if err := runREPL(res); err != nil {
				fatalf("%v", err)
			}
			return
		}
		flaggy.ShowHelp("")
		os.Exit(1)
	}

	res, err := resolveDBPath(dbFlag)
	if err != nil {
		fatalf("db path: %v", err)
	}

	switch {
	case listCmd.Used:
		must(runSubcommand(res, "list", "", "", "", false))
	case getCmd.Used:
		must(runSubcommand(res, "get", getKey, "", "", false))
	case setCmd.Used:
		must(runSubcommand(res, "set", setKey, setValue, setFile, setB64))
	case deleteCmd.Used:
		if !deleteForce && !confirmDelete(deleteKey) {
			fmt.Println("aborted")
			return
		}
		must(runSubcommand(res, "delete", deleteKey, "", "", false))
	case rotateCmd.Used:
		must(runSubcommand(res, "rotate", "", "", "", false))
	case rotateSaltCmd.Used:
		must(runSubcommand(res, "rotate-salt", "", "", "", false))
	case backupCmd.Used:
		must(runSubcommand(res, "backup", "", "", backupDest, false))
	case statusCmd.Used:
		must(runSubcommand(res, "status", "", "", "", false))
	}
}

// anyUsed returns true if any of the provided subcommands was activated.
func anyUsed(cmds ...*flaggy.Subcommand) bool {
	for _, c := range cmds {
		if c.Used {
			return true
		}
	}
	return false
}

// confirmDelete prompts for y/N confirmation before a destructive delete.
func confirmDelete(key string) bool {
	fmt.Printf("Delete %q? This cannot be undone. [y/N] ", key)
	var answer string
	fmt.Scanln(&answer)
	return answer == "y" || answer == "Y"
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, "keeper: "+format+"\n", v...)
	os.Exit(1)
}
