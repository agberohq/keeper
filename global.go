// global.go - Updated with constants

package keeper

import (
	stdErrors "errors"
	"sync"
)

var globalStore *Keeper
var globalMu sync.RWMutex

// GlobalStore sets the process-wide default Keeper instance.
func GlobalStore(store *Keeper) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalStore = store
}

// GlobalGet returns the process-wide default Keeper instance.
func GlobalGet() *Keeper {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore
}

// GlobalGetKey retrieves a secret from the global store.
func GlobalGetKey(key string) ([]byte, error) {
	globalMu.RLock()
	store := globalStore
	globalMu.RUnlock()
	if store == nil {
		return nil, stdErrors.New("global secret store not initialized")
	}
	return store.Get(key)
}
