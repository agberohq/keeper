package keeper

import (
	"github.com/awnumar/memguard"
)

// Master encapsulates the master key for the secret store.
// It uses memguard for secure memory handling.
type Master struct {
	enclave *memguard.Enclave
}

// NewMaster creates a new Master from a raw key.
// The raw key is immediately sealed into an enclave and wiped from memory.
func NewMaster(key []byte) (*Master, error) {
	if len(key) == 0 {
		return nil, ErrInvalidConfig
	}

	enclave := memguard.NewEnclave(key)
	if enclave == nil {
		return nil, ErrInvalidConfig
	}

	return &Master{enclave: enclave}, nil
}

// Open retrieves the master key from the enclave.
// The returned LockedBuffer must be destroyed after use with defer buf.Destroy()
func (m *Master) Open() (*memguard.LockedBuffer, error) {
	if m == nil || m.enclave == nil {
		return nil, ErrStoreLocked
	}

	return m.enclave.Open()
}

// Bytes retrieves the master key as a byte slice.
// This creates a temporary copy that should be used immediately and not stored.
// The caller should call secureZero on the returned bytes when done.
func (m *Master) Bytes() ([]byte, error) {
	buf, err := m.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()

	data := make([]byte, buf.Size())
	copy(data, buf.Bytes())
	return data, nil
}

// Destroy removes the reference to the enclave.
func (m *Master) Destroy() {
	if m != nil {
		m.enclave = nil
	}
}

// IsValid returns true if the master has a valid enclave.
func (m *Master) IsValid() bool {
	return m != nil && m.enclave != nil
}
