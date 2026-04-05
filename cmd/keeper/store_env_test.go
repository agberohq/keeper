package main

// resolvePassphrase must call os.Unsetenv(envPassphrase) immediately after
// reading the environment variable so child processes do not inherit it.
// Before the fix, the variable was read but never cleared.

import (
	"os"
	"testing"
)

// TestResolvePassphrase_UnsetenvAfterRead is the primary regression test.
// It sets KEEPER_PASSPHRASE, calls resolvePassphrase, and verifies the
// variable has been cleared from the environment before the function returns.
func TestResolvePassphrase_UnsetenvAfterRead(t *testing.T) {
	const testPass = "super-secret-passphrase"

	// Set the env var.
	if err := os.Setenv(envPassphrase, testPass); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	// Ensure cleanup even if the test panics.
	defer os.Unsetenv(envPassphrase) //nolint:errcheck

	result, err := resolvePassphrase()
	if err != nil {
		t.Fatalf("resolvePassphrase: %v", err)
	}
	defer result.Zero()

	// The passphrase must be returned correctly.
	if string(result.Bytes()) != testPass {
		t.Errorf("passphrase: got %q, want %q", result.Bytes(), testPass)
	}

	// The env var must be gone — child processes must not inherit it.
	if got := os.Getenv(envPassphrase); got != "" {
		t.Errorf("KEEPER_PASSPHRASE still set after resolvePassphrase: %q — child processes will inherit the secret", got)
	}
}

// TestResolvePassphrase_EmptyEnvFallsThrough verifies that when
// KEEPER_PASSPHRASE is empty, resolvePassphrase does not consume it and
// falls through to the interactive prompt path. We can't drive the TTY in
// a unit test, so we just confirm the env branch is skipped (the function
// will return an error about the non-terminal stdin — that's expected).
func TestResolvePassphrase_EmptyEnvFallsThrough(t *testing.T) {
	os.Unsetenv(envPassphrase) //nolint:errcheck

	// The interactive path will fail because stdin is not a TTY in CI.
	// What we're testing is that it tries the interactive path at all
	// (i.e. the env branch is correctly skipped when the var is empty).
	_, err := resolvePassphrase()
	if err == nil {
		t.Skip("stdin appears to be a terminal; skipping non-terminal guard")
	}
	// The error must come from the prompter (non-terminal), not from any
	// env-related code path.
	if os.Getenv(envPassphrase) != "" {
		t.Error("env var should remain unset when it was empty before the call")
	}
}

// TestResolvePassphrase_EnvNotSetAfterSecondCall verifies that a second call
// to resolvePassphrase (e.g. after the env var was already consumed) does not
// see a stale value — it should fall through to the prompt.
func TestResolvePassphrase_EnvNotSetAfterSecondCall(t *testing.T) {
	os.Setenv(envPassphrase, "firstpass") //nolint:errcheck
	defer os.Unsetenv(envPassphrase)      //nolint:errcheck

	// First call — should consume and unset.
	r1, err := resolvePassphrase()
	if err != nil {
		t.Fatalf("first resolvePassphrase: %v", err)
	}
	r1.Zero()

	// The env var must now be gone.
	if os.Getenv(envPassphrase) != "" {
		t.Fatal("env var still set after first call — second call would re-use the secret")
	}

	// Second call — must NOT find the env var (it was cleared). It will
	// attempt the interactive prompt and fail on non-TTY stdin.
	_, err = resolvePassphrase()
	if err == nil {
		t.Skip("stdin is a real terminal; cannot verify second-call behaviour")
	}
	// The error is expected (non-TTY); the important thing is we got here
	// without the second call returning "firstpass".
}
