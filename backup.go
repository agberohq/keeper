package keeper

import (
	"fmt"
	"io"
	"time"

	pkgstore "github.com/agberohq/keeper/pkg/store"
	bolt "go.etcd.io/bbolt"
)

// BackupTo streams a consistent, point-in-time hot backup of the encrypted
// database directly to w.
func (s *Keeper) BackupTo(w io.Writer) (int64, error) {
	bs, ok := s.db.(*pkgstore.BoltStore)
	if !ok {
		return 0, fmt.Errorf("backup: underlying store is not a BoltStore (in-memory stores cannot be backed up this way)")
	}
	var written int64
	err := bs.DB().View(func(tx *bolt.Tx) error {
		n, err := tx.WriteTo(w)
		written = n
		return err
	})
	if err != nil {
		return written, fmt.Errorf("backup: bbolt WriteTo failed: %w", err)
	}
	return written, nil
}

// BackupInfo holds metadata about a completed backup.
type BackupInfo struct {
	Bytes     int64
	Timestamp time.Time
	DBPath    string
}

// Backup writes to w and returns BackupInfo.
func (s *Keeper) Backup(w io.Writer) (BackupInfo, error) {
	n, err := s.BackupTo(w)
	return BackupInfo{
		Bytes:     n,
		Timestamp: time.Now().UTC(),
		DBPath:    s.config.DBPath,
	}, err
}
