package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agberohq/keeper"
	"github.com/agberohq/keeper/pkg/prompter"
)

// initStore handles the new-database flow:
// Confirms with the user that they want to create a DB at dbPath.
// Prompts for a new passphrase with confirmation.
// Opens the store and unlocks it (first unlock writes the verification hash).
//
// Returns an open, unlocked Keeper. The caller must call Close when done.
func initStore(dbPath string) (*keeper.Keeper, error) {
	// Step 1 — confirm creation.
	ok, err := prompter.Confirm(
		fmt.Sprintf("No keeper database found. Create one at %s?", filepath.Clean(dbPath)),
	)
	if err != nil {
		return nil, fmt.Errorf("confirmation: %w", err)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "keeper: no database created")
		os.Exit(0)
	}

	// Step 2 — prompt for initial passphrase.
	pass, err := prompter.NewInput("Passphrase (new)",
		prompter.WithRequired(true, "passphrase is required"),
		prompter.WithConfirm(),
		prompter.WithConfirmMsg("Confirm passphrase"),
	).Run()
	if err != nil {
		return nil, fmt.Errorf("passphrase: %w", err)
	}
	defer pass.Zero()

	// Step 3 — open and unlock (first Unlock writes the verification hash).
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("create store at %s: %w", dbPath, err)
	}
	if err := store.Unlock(pass.Bytes()); err != nil {
		store.Close()
		return nil, fmt.Errorf("init unlock: %w", err)
	}
	fmt.Printf("keeper: created %s\n", filepath.Clean(dbPath))
	return store, nil
}

// openStore opens and unlocks an existing keeper.Keeper at dbPath.
// Passphrase resolution order:
// KEEPER_PASSPHRASE environment variable
// Interactive prompt via pkg/prompter (secure, no echo)
func openStore(dbPath string) (*keeper.Keeper, error) {
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("open store at %s: %w", dbPath, err)
	}

	pass, err := resolvePassphrase()
	if err != nil {
		store.Close()
		return nil, err
	}
	defer pass.Zero()

	if err := store.Unlock(pass.Bytes()); err != nil {
		store.Close()
		return nil, fmt.Errorf("unlock: %w", err)
	}
	return store, nil
}

// openStoreLocked opens a keeper.Keeper without unlocking it.
// Used by commands that operate on a locked store (e.g. status).
func openStoreLocked(dbPath string) (*keeper.Keeper, error) {
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		return nil, fmt.Errorf("open store at %s: %w", dbPath, err)
	}
	return store, nil
}

// resolvePassphrase returns the passphrase as a prompter.Result.
// The caller must call result.Zero() when done.
func resolvePassphrase() (*prompter.Result, error) {
	if env := os.Getenv(envPassphrase); env != "" {
		return prompter.NewResult([]byte(env)), nil
	}
	return prompter.NewInput("Passphrase",
		prompter.WithRequired(true, "passphrase is required"),
	).Run()
}

// resolveNewPassphrase prompts for a new passphrase with confirmation.
// Never reads from env — a new passphrase must always be entered interactively.
func resolveNewPassphrase() (*prompter.Result, error) {
	return prompter.NewInput("New passphrase",
		prompter.WithRequired(true, "passphrase is required"),
		prompter.WithConfirm(),
		prompter.WithConfirmMsg("Confirm new passphrase"),
	).Run()
}
