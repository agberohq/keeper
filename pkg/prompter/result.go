package prompter

// Result holds the secure password bytes with a zeroing method
type Result struct {
	value []byte
}

// NewResult creates a new Result
func NewResult(pass []byte) *Result {
	return &Result{value: pass}
}

// String returns the password as a string (use sparingly, only when absolutely needed)
// This defeats the security purpose - prefer Bytes() and Zero()
func (p *Result) String() string {
	return string(p.value)
}

// Bytes returns the password bytes - call Zero() when done
func (p *Result) Bytes() []byte {
	return p.value
}

// Zero securely wipes the password from memory
func (p *Result) Zero() {
	if p.value == nil {
		return
	}
	for i := range p.value {
		p.value[i] = 0
	}
	p.value = nil
}

// Confirm compares two password results and zeroes both
func (p *Result) Confirm(other *Result) bool {
	if p.value == nil || other.value == nil {
		p.Zero()
		other.Zero()
		return false
	}
	if len(p.value) != len(other.value) {
		p.Zero()
		other.Zero()
		return false
	}
	for i := range p.value {
		if p.value[i] != other.value[i] {
			p.Zero()
			other.Zero()
			return false
		}
	}
	p.Zero()
	other.Zero()
	return true
}
