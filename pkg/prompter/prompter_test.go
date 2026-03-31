package prompter

import (
	"testing"
)

func TestResult_StringAndBytes(t *testing.T) {
	pass := []byte("s3cr3t")
	r := NewResult(pass)

	if r.String() != "s3cr3t" {
		t.Fatalf("String(): got %q want %q", r.String(), "s3cr3t")
	}
	if string(r.Bytes()) != "s3cr3t" {
		t.Fatalf("Bytes(): got %q want %q", r.Bytes(), "s3cr3t")
	}
}

func TestResult_Zero(t *testing.T) {
	r := NewResult([]byte("wipe-me"))
	r.Zero()

	if r.Bytes() != nil {
		t.Fatal("Bytes() should be nil after Zero()")
	}
	if r.String() != "" {
		t.Fatalf("String() should be empty after Zero(), got %q", r.String())
	}
}

func TestResult_ZeroNil(t *testing.T) {
	r := NewResult(nil)
	r.Zero() // must not panic
}

func TestResult_ZeroIdempotent(t *testing.T) {
	r := NewResult([]byte("data"))
	r.Zero()
	r.Zero() // second call must not panic
}

func TestResult_Confirm_Match(t *testing.T) {
	r1 := NewResult([]byte("password"))
	r2 := NewResult([]byte("password"))

	if !r1.Confirm(r2) {
		t.Fatal("Confirm should return true for equal passwords")
	}
	// Both should be zeroed after Confirm
	if r1.Bytes() != nil || r2.Bytes() != nil {
		t.Fatal("Confirm should zero both results")
	}
}

func TestResult_Confirm_Mismatch(t *testing.T) {
	r1 := NewResult([]byte("abc"))
	r2 := NewResult([]byte("xyz"))

	if r1.Confirm(r2) {
		t.Fatal("Confirm should return false for different passwords")
	}
}

func TestResult_Confirm_DifferentLength(t *testing.T) {
	r1 := NewResult([]byte("short"))
	r2 := NewResult([]byte("longer-password"))

	if r1.Confirm(r2) {
		t.Fatal("Confirm should return false for different-length passwords")
	}
}

func TestResult_Confirm_NilLeft(t *testing.T) {
	r1 := NewResult(nil)
	r2 := NewResult([]byte("pass"))
	if r1.Confirm(r2) {
		t.Fatal("Confirm with nil left should return false")
	}
}

func TestResult_Confirm_NilRight(t *testing.T) {
	r1 := NewResult([]byte("pass"))
	r2 := NewResult(nil)
	if r1.Confirm(r2) {
		t.Fatal("Confirm with nil right should return false")
	}
}

func TestNewInput_Defaults(t *testing.T) {
	p := NewInput("Enter password")
	if p.prompt != "Enter password" {
		t.Fatalf("prompt not set: %q", p.prompt)
	}
	if p.confirm {
		t.Fatal("confirm should default to false")
	}
	if p.required {
		t.Fatal("required should default to false")
	}
	if p.minLength != 0 {
		t.Fatalf("minLength should default to 0, got %d", p.minLength)
	}
	if p.promptFunc == nil {
		t.Fatal("promptFunc must be set")
	}
}

func TestNewInput_WithConfirm(t *testing.T) {
	p := NewInput("Pass", WithConfirm())
	if !p.confirm {
		t.Fatal("WithConfirm() should set confirm=true")
	}
}

func TestNewInput_WithConfirmMsg(t *testing.T) {
	p := NewInput("Pass", WithConfirmMsg("Re-enter"))
	if !p.confirm {
		t.Fatal("WithConfirmMsg should also set confirm=true")
	}
	if p.confirmMsg != "Re-enter" {
		t.Fatalf("confirmMsg not set: %q", p.confirmMsg)
	}
}

func TestNewInput_WithMismatchMsg(t *testing.T) {
	p := NewInput("Pass", WithMismatchMsg("no match"))
	if p.mismatchMsg != "no match" {
		t.Fatalf("mismatchMsg not set: %q", p.mismatchMsg)
	}
}

func TestNewInput_WithRequired(t *testing.T) {
	p := NewInput("Pass", WithRequired(true, "must provide"))
	if !p.required {
		t.Fatal("required should be true")
	}
	if p.requiredMsg != "must provide" {
		t.Fatalf("requiredMsg not set: %q", p.requiredMsg)
	}
}

func TestNewInput_WithRequired_False(t *testing.T) {
	p := NewInput("Pass", WithRequired(false, ""))
	if p.required {
		t.Fatal("required should be false")
	}
}

func TestNewInput_WithMinLength(t *testing.T) {
	p := NewInput("Pass", WithMinLength(8, "too short"))
	if p.minLength != 8 {
		t.Fatalf("minLength not set: %d", p.minLength)
	}
	if p.minMsg != "too short" {
		t.Fatalf("minMsg not set: %q", p.minMsg)
	}
}

func TestNewInput_MultipleOptions(t *testing.T) {
	p := NewInput("Pass",
		WithConfirm(),
		WithRequired(true, "required"),
		WithMinLength(12, "too short"),
		WithMismatchMsg("mismatch"),
	)
	if !p.confirm {
		t.Fatal("confirm should be true")
	}
	if !p.required {
		t.Fatal("required should be true")
	}
	if p.minLength != 12 {
		t.Fatalf("minLength: got %d", p.minLength)
	}
	if p.mismatchMsg != "mismatch" {
		t.Fatalf("mismatchMsg: got %q", p.mismatchMsg)
	}
}

func TestNewInput_WithPromptFormatter(t *testing.T) {
	custom := func(prompt string) string { return "[" + prompt + "] " }
	p := NewInput("Pass").WithPromptFormatter(custom)
	if p.promptFunc("test") != "[test] " {
		t.Fatalf("custom formatter not applied: %q", p.promptFunc("test"))
	}
}

func TestQuick_NotTerminal(t *testing.T) {
	// In CI stdin is not a terminal; Quick must return an error, not panic.
	_, err := Quick("Password")
	if err == nil {
		t.Skip("stdin appears to be a terminal; skipping non-terminal test")
	}
}

func TestQuickWithConfirm_NotTerminal(t *testing.T) {
	_, err := QuickWithConfirm("Password")
	if err == nil {
		t.Skip("stdin appears to be a terminal; skipping non-terminal test")
	}
}

func TestDefaultPromptFormatter(t *testing.T) {
	got := defaultPromptFormatter("Master password")
	want := "Master password: "
	if got != want {
		t.Fatalf("defaultPromptFormatter: got %q want %q", got, want)
	}
}
