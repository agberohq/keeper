package keepcmd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keepcmd"
)

// bufOut captures Output calls for assertion in tests.
type bufOut struct {
	lines []string
}

func (b *bufOut) Table(headers []string, rows [][]string) {
	for _, r := range rows {
		b.lines = append(b.lines, strings.Join(r, "|"))
	}
}
func (b *bufOut) KeyValue(label, value string) { b.lines = append(b.lines, label+": "+value) }
func (b *bufOut) Success(msg string)           { b.lines = append(b.lines, "ok: "+msg) }
func (b *bufOut) Info(msg string)              { b.lines = append(b.lines, "info: "+msg) }
func (b *bufOut) Error(msg string)             { b.lines = append(b.lines, "err: "+msg) }

func (b *bufOut) contains(s string) bool {
	for _, l := range b.lines {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// newTestCommands returns Commands backed by a fresh unlocked store.
// NoClose is false — each operation opens and closes the store (one-shot mode).
func newTestCommands(t *testing.T) (*keepcmd.Commands, *bufOut) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	out := &bufOut{}
	cmds := &keepcmd.Commands{
		Store: func() (*keeper.Keeper, error) {
			s, err := keeper.New(keeper.Config{DBPath: dbPath})
			if err != nil {
				return nil, err
			}
			if err := s.Unlock([]byte("testpass")); err != nil {
				s.Close()
				return nil, err
			}
			return s, nil
		},
		Out: out,
	}
	return cmds, out
}

// newSessionCommands returns Commands backed by a shared open store.
// NoClose is true — simulates the REPL session where the store must not be
// closed between commands.
func newSessionCommands(t *testing.T) (*keepcmd.Commands, *bufOut, func()) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "session.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("keeper.New: %v", err)
	}
	if err := store.Unlock([]byte("testpass")); err != nil {
		store.Close()
		t.Fatalf("Unlock: %v", err)
	}
	out := &bufOut{}
	cmds := &keepcmd.Commands{
		Store:   func() (*keeper.Keeper, error) { return store, nil },
		Out:     out,
		NoClose: true,
	}
	return cmds, out, func() { store.Close() }
}

func TestCommands_ListEmpty(t *testing.T) {
	cmds, out := newTestCommands(t)
	if err := cmds.List(); err != nil {
		t.Fatalf("List: %v", err)
	}
	if !out.contains("empty") {
		t.Error("expected empty message")
	}
}

func TestCommands_SetAndGet(t *testing.T) {
	cmds, out := newTestCommands(t)

	if err := cmds.Set("mykey", "myvalue", keepcmd.SetOptions{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !out.contains("mykey") {
		t.Error("Set success message should mention key")
	}

	out.lines = nil
	if err := cmds.Get("mykey"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !out.contains("myvalue") {
		t.Error("Get should display value")
	}
}

func TestCommands_SetBase64(t *testing.T) {
	cmds, _ := newTestCommands(t)
	// "hello" in standard base64 is "aGVsbG8="
	if err := cmds.Set("b64key", "aGVsbG8=", keepcmd.SetOptions{Base64: true}); err != nil {
		t.Fatalf("Set base64: %v", err)
	}
}

func TestCommands_SetFromFile(t *testing.T) {
	cmds, out := newTestCommands(t)
	f := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(f, []byte("file-content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmds.Set("filekey", "", keepcmd.SetOptions{FromFile: f}); err != nil {
		t.Fatalf("Set from file: %v", err)
	}
	if !out.contains("12 bytes") {
		t.Error("expected byte count in success message")
	}
}

func TestCommands_ListAfterSet(t *testing.T) {
	cmds, out := newTestCommands(t)
	cmds.Set("a", "1", keepcmd.SetOptions{})
	cmds.Set("b", "2", keepcmd.SetOptions{})

	out.lines = nil
	if err := cmds.List(); err != nil {
		t.Fatalf("List: %v", err)
	}
	if !out.contains("a") || !out.contains("b") {
		t.Errorf("expected both keys in list output, got: %v", out.lines)
	}
}

func TestCommands_Delete(t *testing.T) {
	cmds, out := newTestCommands(t)
	cmds.Set("delkey", "val", keepcmd.SetOptions{})

	out.lines = nil
	if err := cmds.Delete("delkey"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !out.contains("deleted") {
		t.Error("expected deleted confirmation")
	}

	if err := cmds.Get("delkey"); err == nil {
		t.Error("expected error after delete")
	}
}

func TestCommands_DeleteMissing(t *testing.T) {
	cmds, _ := newTestCommands(t)
	if err := cmds.Delete("nonexistent"); err == nil {
		t.Error("expected error deleting nonexistent key")
	}
}

func TestCommands_SetEmptyKey(t *testing.T) {
	cmds, _ := newTestCommands(t)
	if err := cmds.Set("", "value", keepcmd.SetOptions{}); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestCommands_GetEmptyKey(t *testing.T) {
	cmds, _ := newTestCommands(t)
	if err := cmds.Get(""); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestCommands_Status(t *testing.T) {
	cmds, out := newTestCommands(t)
	if err := cmds.Status(); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !out.contains("unlocked") {
		t.Error("expected unlocked status")
	}
}

func TestCommands_Backup(t *testing.T) {
	cmds, out := newTestCommands(t)
	cmds.Set("bk", "val", keepcmd.SetOptions{})

	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := cmds.Backup(keepcmd.BackupOptions{Dest: dest}); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if !out.contains("backup written") {
		t.Error("expected backup success message")
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Error("backup file is empty")
	}
}

func TestCommands_BackupGeneratedName(t *testing.T) {
	cmds, _ := newTestCommands(t)
	tmp := t.TempDir()
	orig, _ := os.Getwd()
	os.Chdir(tmp)
	defer os.Chdir(orig)

	if err := cmds.Backup(keepcmd.BackupOptions{}); err != nil {
		t.Fatalf("Backup (auto name): %v", err)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) == 0 {
		t.Error("expected a backup file to be created")
	}
}

func TestCommands_Rotate(t *testing.T) {
	cmds, out := newTestCommands(t)
	cmds.Set("rk", "rv", keepcmd.SetOptions{})

	if err := cmds.Rotate([]byte("newpass")); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !out.contains("rotated") {
		t.Error("expected rotation confirmation")
	}
}

func TestCommands_RotateEmptyPassphrase(t *testing.T) {
	cmds, _ := newTestCommands(t)
	if err := cmds.Rotate(nil); err == nil {
		t.Error("expected error for nil new passphrase")
	}
	if err := cmds.Rotate([]byte("")); err == nil {
		t.Error("expected error for blank new passphrase")
	}
}

func TestCommands_RotateSalt(t *testing.T) {
	cmds, out := newTestCommands(t)
	cmds.Set("sk", "sv", keepcmd.SetOptions{})

	if err := cmds.RotateSalt([]byte("testpass")); err != nil {
		t.Fatalf("RotateSalt: %v", err)
	}
	if !out.contains("rotated") {
		t.Error("expected rotation confirmation")
	}
}

func TestCommands_RotateSaltEmptyPassphrase(t *testing.T) {
	cmds, _ := newTestCommands(t)
	if err := cmds.RotateSalt(nil); err == nil {
		t.Error("expected error for nil passphrase")
	}
}

// NoClose / session mode

// TestNoClose_StoreRemainsOpenAcrossOperations verifies that when NoClose is
// true the store is not closed after each command, allowing multiple sequential
// operations against the same open store (the REPL use-case).
func TestNoClose_StoreRemainsOpenAcrossOperations(t *testing.T) {
	cmds, out, close := newSessionCommands(t)
	defer close()

	// Multiple operations without re-opening between them.
	if err := cmds.Set("sk1", "sv1", keepcmd.SetOptions{}); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := cmds.Set("sk2", "sv2", keepcmd.SetOptions{}); err != nil {
		t.Fatalf("Set 2 (would fail if store was closed): %v", err)
	}
	if err := cmds.Get("sk1"); err != nil {
		t.Fatalf("Get (would fail if store was closed): %v", err)
	}
	if !out.contains("sv1") {
		t.Error("expected sv1 in output")
	}
	if err := cmds.List(); err != nil {
		t.Fatalf("List: %v", err)
	}
	if !out.contains("sk1") || !out.contains("sk2") {
		t.Errorf("expected both keys, got: %v", out.lines)
	}
}

// TestNoClose_False_DefaultBehaviourUnchanged verifies that NoClose=false
// (the default) still works correctly for one-shot commands.
func TestNoClose_False_DefaultBehaviourUnchanged(t *testing.T) {
	cmds, out := newTestCommands(t)
	if err := cmds.Set("k", "v", keepcmd.SetOptions{}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// A second call re-opens via StoreFactory — this must succeed.
	if err := cmds.Get("k"); err != nil {
		t.Fatalf("Get after close: %v", err)
	}
	if !out.contains("v") {
		t.Error("expected value in output")
	}
}
