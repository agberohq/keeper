package main

import (
	"fmt"

	"github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
)

// openOrInit opens an existing store or, when res.isNew is true, runs the
// new-database initialisation flow. Returns an open, unlocked Keeper.
// The caller must Close it.
func openOrInit(res dbResolution) (*keeper.Keeper, error) {
	if res.isNew {
		return initStore(res.path)
	}
	return openStore(res.path)
}

// runSubcommand executes cmd against the database described by res using
// keepcmd.Commands. For status the store is opened locked; all other commands
// open (and if new, initialise) it unlocked.
func runSubcommand(res dbResolution, cmd, key, value, file string, b64 bool) error {
	cmds := &keepcmd.Commands{
		Store: func() (*keeper.Keeper, error) {
			if cmd == "status" {
				return openStoreLocked(res.path)
			}
			return openOrInit(res)
		},
		Out: keepcmd.PlainOutput{},
	}

	switch cmd {
	case "list":
		return cmds.List()
	case "get":
		return cmds.Get(key)
	case "set":
		return cmds.Set(key, value, keepcmd.SetOptions{FromFile: file, Base64: b64})
	case "delete":
		return cmds.Delete(key)

	case "rotate":
		// Resolve new passphrase here — keepcmd.Rotate never prompts.
		pass, err := resolveNewPassphrase()
		if err != nil {
			return err
		}
		defer pass.Zero()
		return cmds.Rotate(pass.Bytes())

	case "rotate-salt":
		// Resolve current passphrase here — keepcmd.RotateSalt never prompts.
		pass, err := resolvePassphrase()
		if err != nil {
			return err
		}
		defer pass.Zero()
		return cmds.RotateSalt(pass.Bytes())

	case "backup":
		return cmds.Backup(keepcmd.BackupOptions{Dest: file})
	case "status":
		return cmds.Status()
	}
	return fmt.Errorf("unknown command: %s", cmd)
}
