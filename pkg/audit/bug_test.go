package audit

import (
	"testing"
)

// It ensures that an empty HMAC is rejected when a signing key is active.
func TestVerifyHMAC_RejectsEmptyHMACWithActiveKey(t *testing.T) {
	key := []byte("a-very-secret-signing-key")

	event := &Event{
		ID:   "forged-event-1",
		HMAC: "",
	}

	result := event.VerifyHMAC(key)

	if result {
		t.Errorf("VULNERABILITY: VerifyHMAC incorrectly accepted an empty HMAC when a signing key was present.")
	}
}
