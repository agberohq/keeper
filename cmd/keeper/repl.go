package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
	"github.com/olekukonko/prompter"
)

// replSession holds state for an interactive session.
type replSession struct {
	store *keeper.Keeper
	cmds  *keepcmd.Commands
	db    string
}

// runREPL opens the store once, then loops reading commands from stdin until
// the user types "quit", "exit", or sends EOF.
//
// The store is unlocked once for the lifetime of the session — the user never
// re-enters their passphrase between commands. NoClose is set on Commands so
// that individual operations do not close the shared store.
func runREPL(res dbResolution) error {
	var store *keeper.Keeper
	var err error

	if res.isNew {
		store, err = initStore(res.path)
	} else {
		store, err = openStore(res.path)
	}
	if err != nil {
		return err
	}
	defer store.Close()

	sess := &replSession{
		store: store,
		db:    res.path,
		cmds: &keepcmd.Commands{
			// The REPL owns the store — StoreFactory returns the shared instance.
			// NoClose prevents Commands from closing it after each operation.
			Store:   func() (*keeper.Keeper, error) { return store, nil },
			Out:     keepcmd.PlainOutput{},
			NoClose: true,
		},
	}

	fmt.Printf("keeper — %s  (help for commands, quit to exit)\n\n", res.path)
	return sess.loop()
}

// loop is the read-eval-print loop.
func (s *replSession) loop() error {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("keeper> ")
		if !scanner.Scan() {
			fmt.Println()
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		done, err := s.dispatch(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		}
		if done {
			break
		}
	}
	return scanner.Err()
}

// dispatch parses line and calls the appropriate keepcmd method.
// Returns (true, nil) when the user requests exit.
func (s *replSession) dispatch(line string) (exit bool, err error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false, nil
	}

	// Convenience: strip a leading "keeper" token so muscle-memory invocations
	// like "keeper ls" or "keeper set foo" work without producing an error.
	if parts[0] == "keeper" {
		parts = parts[1:]
		if len(parts) == 0 {
			return false, nil
		}
	}

	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "quit", "exit", "q":
		fmt.Println("bye")
		return true, nil

	case "help", "?":
		warnExtraArgs(cmd, args)
		s.printHelp()

	case "clear":
		// ANSI: move cursor to home then erase display.
		fmt.Print("\033[H\033[2J")

	case "list", "ls":
		// list                    — all keys across all schemes/namespaces
		// list <scheme>           — all keys in every namespace of that scheme
		// list <scheme> <ns>      — all keys in a specific bucket
		switch len(args) {
		case 0:
			err = s.cmds.List()
		case 1:
			err = s.cmds.List(args[0])
		default:
			err = s.cmds.List(args[0], args[1])
		}

	case "get", "cat":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: get <key>")
			return false, nil
		}
		err = s.cmds.Get(args[0])

	case "set", "put":
		// Value is prompted with no-echo so it never appears in terminal
		// scrollback or shell history. The key is not a secret.
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: set <key>")
			return false, nil
		}
		key := args[0]
		secret, e := prompter.NewSecret("Value for "+key, prompter.WithRequired(true)).Run()
		if e != nil {
			return false, e
		}
		defer secret.Zero()
		err = s.cmds.Set(key, string(secret.Bytes()), keepcmd.SetOptions{})

	case "delete", "rm", "del":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: delete <key>")
			return false, nil
		}
		ok, e := prompter.Confirm(fmt.Sprintf("Delete %q? This cannot be undone.", args[0]))
		if e != nil {
			return false, e
		}
		if !ok {
			fmt.Println("aborted")
			return false, nil
		}
		err = s.cmds.Delete(args[0])

	case "status":
		warnExtraArgs(cmd, args)
		// Query the shared store directly — no factory indirection — so the
		// result always reflects the session's actual live lock state.
		if s.store.IsLocked() {
			fmt.Println("  store is locked")
		} else {
			fmt.Println("  store is unlocked")
		}

	case "lock":
		warnExtraArgs(cmd, args)
		if err = s.store.Lock(); err == nil {
			fmt.Println("  store locked — use 'unlock' to resume")
		}

	case "unlock":
		warnExtraArgs(cmd, args)
		if !s.store.IsLocked() {
			fmt.Println("  store is already unlocked")
			return false, nil
		}
		pass, e := resolvePassphrase()
		if e != nil {
			return false, e
		}
		defer pass.Zero()
		err = s.store.Unlock(pass.Bytes())

	case "backup":
		dest := ""
		if len(args) > 0 {
			dest = args[0]
		}
		err = s.cmds.Backup(keepcmd.BackupOptions{Dest: dest})

	case "rotate":
		warnExtraArgs(cmd, args)
		pass, e := resolveNewPassphrase()
		if e != nil {
			return false, e
		}
		defer pass.Zero()
		err = s.cmds.Rotate(pass.Bytes())

	case "rotate-salt":
		warnExtraArgs(cmd, args)
		pass, e := resolvePassphrase()
		if e != nil {
			return false, e
		}
		defer pass.Zero()
		err = s.cmds.RotateSalt(pass.Bytes())

	default:
		fmt.Fprintf(os.Stderr, "unknown command %q — type 'help' for a list\n", cmd)
	}

	return false, err
}

// warnExtraArgs prints a notice when the user passes arguments to a command
// that takes none. Catches "rotate newpassword" style mistakes before the
// user wonders why their argument was silently ignored.
func warnExtraArgs(cmd string, args []string) {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "note: %q takes no arguments (got: %s) — ignored\n",
			cmd, strings.Join(args, " "))
	}
}

// printHelp prints the list of available REPL commands.
func (s *replSession) printHelp() {
	fmt.Print(`
Commands:
  ls  | list [s] [ns]   List all keys (optional: filter by scheme / namespace)
  cat | get  <key>       Read a secret value
  put | set  <key>       Store a secret (value prompted hidden — not in scrollback)
  rm  | delete <key>     Remove a key (asks for confirmation)
  status                 Show lock state
  lock                   Lock the store (drops keys from memory)
  unlock                 Re-unlock the store (prompts for passphrase)
  backup [dest]          Backup database (dest defaults to timestamped name)
  rotate                 Change master passphrase (prompts for new passphrase)
  rotate-salt            Rotate KDF salt (re-encrypts all secrets)
  clear                  Clear the screen
  help | ?               Show this help
  quit | exit | q        End the session

`)
}
