package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	envDBPath     = "KEEPER_DB"
	envPassphrase = "KEEPER_PASSPHRASE"
	defaultDBName = "keeper.db"
)

// dbResolution is the result of resolveDBPath.
type dbResolution struct {
	path  string
	isNew bool // true when the file does not exist yet
}

// resolveDBPath returns the database path from, in order:
//  1. The --db flag value (passed as flagDB, may be empty)
//  2. The KEEPER_DB environment variable
//  3. A *.db file found in the current directory
//     — if exactly one found: use it
//     — if multiple found: prompt via huh to select one
//     — if none found: return "keeper.db" in the current directory with isNew=true
//
// isNew is true only when the resolved path does not yet exist on disk.
// The caller is responsible for prompting the user before creating the store.
func resolveDBPath(flagDB string) (dbResolution, error) {
	if flagDB != "" {
		return dbResolution{path: flagDB, isNew: !fileExists(flagDB)}, nil
	}
	if env := os.Getenv(envDBPath); env != "" {
		return dbResolution{path: env, isNew: !fileExists(env)}, nil
	}
	return scanCurrentDir()
}

// scanCurrentDir looks for *.db files in the working directory.
func scanCurrentDir() (dbResolution, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return dbResolution{}, fmt.Errorf("getwd: %w", err)
	}

	matches, err := filepath.Glob(filepath.Join(cwd, "*.db"))
	if err != nil {
		return dbResolution{}, fmt.Errorf("glob: %w", err)
	}

	switch len(matches) {
	case 0:
		p := filepath.Join(cwd, defaultDBName)
		return dbResolution{path: p, isNew: true}, nil
	case 1:
		return dbResolution{path: matches[0], isNew: false}, nil
	default:
		path, err := pickDB(matches)
		if err != nil {
			return dbResolution{}, err
		}
		return dbResolution{path: path, isNew: false}, nil
	}
}

// fileExists returns true when path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
