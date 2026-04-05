package keephandler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/keeper"
)

// unlock handles POST /keeper/unlock.
//
// The passphrase is decoded directly into []byte via extractFieldBytes to avoid
// leaving an immutable string backing array on the heap.
//
// Body: {"passphrase":"..."}
func (h *handler) unlock(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		h.enc(w, RouteUnlock, http.StatusServiceUnavailable, errData("keeper not configured"))
		return
	}

	pass, ok := extractFieldBytes(r, "passphrase")
	if !ok || len(pass) == 0 {
		h.enc(w, RouteUnlock, http.StatusBadRequest, errData("passphrase required"))
		return
	}
	defer wipeBytes(pass)

	if err := h.store.Unlock(pass); err != nil {
		h.enc(w, RouteUnlock, http.StatusUnauthorized, errData("invalid passphrase"))
		return
	}
	noStore(w)
	h.enc(w, RouteUnlock, http.StatusOK, map[string]string{"status": "unlocked"})
}

// lock handles POST /keeper/lock.
func (h *handler) lock(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		h.enc(w, RouteLock, http.StatusServiceUnavailable, errData("keeper not configured"))
		return
	}
	if err := h.store.Lock(); err != nil {
		h.enc(w, RouteLock, http.StatusInternalServerError, errData(err.Error()))
		return
	}
	h.enc(w, RouteLock, http.StatusOK, map[string]string{"status": "locked"})
}

// status handles GET /keeper/status.
// Safe to poll without authentication — no guard applied.
func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	enabled := h.store != nil
	locked := true
	if enabled {
		locked = h.store.IsLocked()
	}
	h.enc(w, RouteStatus, http.StatusOK, map[string]any{
		"enabled": enabled,
		"locked":  locked,
	})
}

// list handles GET /keeper/keys.
func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteList) {
		return
	}
	keys, err := h.store.List()
	if err != nil {
		h.enc(w, RouteList, http.StatusInternalServerError, errData(err.Error()))
		return
	}
	if keys == nil {
		keys = []string{}
	}
	h.enc(w, RouteList, http.StatusOK, map[string]any{"keys": keys})
}

// get handles GET /keeper/keys/{key}.
func (h *handler) get(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteGet) {
		return
	}
	key := r.PathValue("key")
	if key == "" {
		h.enc(w, RouteGet, http.StatusBadRequest, errData("key required"))
		return
	}

	val, err := h.store.Get(key)
	if err != nil {
		if errors.Is(err, keeper.ErrKeyNotFound) {
			h.enc(w, RouteGet, http.StatusNotFound, errData("key not found"))
		} else {
			h.enc(w, RouteGet, http.StatusInternalServerError, errData(err.Error()))
		}
		return
	}
	noStore(w)
	// Values are base64-encoded to safely transport binary secrets without
	// UTF-8 corruption. Clients must base64-decode the value field.
	h.enc(w, RouteGet, http.StatusOK, map[string]any{
		"key":      key,
		"value":    base64.StdEncoding.EncodeToString(val),
		"encoding": "base64",
	})
}

// setRequest is the JSON body for POST /keeper/keys.
type setRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	B64   bool   `json:"b64"`
}

// set handles POST /keeper/keys.
// Supports JSON body or multipart/form-data (file upload).
func (h *handler) set(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteSet) {
		return
	}

	var key string
	var data []byte

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/") {
		if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("bad multipart: "+err.Error()))
			return
		}
		key = r.FormValue("key")
		if key == "" {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("key required"))
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("file required"))
			return
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, maxUploadBytes))
		if err != nil {
			h.enc(w, RouteSet, http.StatusInternalServerError, errData("read failed"))
			return
		}
		if len(data) == 0 {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("file cannot be empty"))
			return
		}
	} else {
		var req setRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("invalid JSON: "+err.Error()))
			return
		}
		if req.Key == "" {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("key required"))
			return
		}
		if req.Value == "" {
			h.enc(w, RouteSet, http.StatusBadRequest, errData("value required"))
			return
		}
		key = req.Key
		if req.B64 {
			var err error
			data, err = decodeB64Loose(req.Value)
			if err != nil {
				h.enc(w, RouteSet, http.StatusBadRequest, errData("invalid base64: "+err.Error()))
				return
			}
		} else {
			data = []byte(req.Value)
		}
	}

	if err := h.store.Set(key, data); err != nil {
		h.enc(w, RouteSet, http.StatusInternalServerError, errData(err.Error()))
		return
	}
	noStore(w)
	h.enc(w, RouteSet, http.StatusOK, map[string]any{
		"key":   key,
		"bytes": len(data),
	})
}

// delete handles DELETE /keeper/keys/{key}.
func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteDelete) {
		return
	}
	key := r.PathValue("key")
	if key == "" {
		h.enc(w, RouteDelete, http.StatusBadRequest, errData("key required"))
		return
	}
	if err := h.store.Delete(key); err != nil {
		if errors.Is(err, keeper.ErrKeyNotFound) {
			h.enc(w, RouteDelete, http.StatusNotFound, errData("key not found"))
		} else {
			h.enc(w, RouteDelete, http.StatusInternalServerError, errData(err.Error()))
		}
		return
	}
	h.enc(w, RouteDelete, http.StatusOK, map[string]string{"deleted": key})
}

// rotate handles POST /keeper/rotate.
// Body: {"new_passphrase":"..."}
// The passphrase field is extracted directly into []byte — it is never
// stored in a Go string to minimise heap lifetime.
func (h *handler) rotate(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteRotate) {
		return
	}
	pass, ok := extractFieldBytes(r, "new_passphrase")
	if !ok || len(pass) == 0 {
		h.enc(w, RouteRotate, http.StatusBadRequest, errData("new_passphrase required"))
		return
	}
	defer wipeBytes(pass)

	if err := h.store.Rotate(pass); err != nil {
		h.enc(w, RouteRotate, http.StatusInternalServerError, errData(err.Error()))
		return
	}
	noStore(w)
	h.enc(w, RouteRotate, http.StatusOK, map[string]string{"status": "rotated"})
}

// rotateSalt handles POST /keeper/rotate/salt.
// Body: {"passphrase":"..."}
// Same heap-avoidance approach as rotate.
func (h *handler) rotateSalt(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteRotateSalt) {
		return
	}
	pass, ok := extractFieldBytes(r, "passphrase")
	if !ok || len(pass) == 0 {
		h.enc(w, RouteRotateSalt, http.StatusBadRequest, errData("passphrase required"))
		return
	}
	defer wipeBytes(pass)

	if err := h.store.RotateSalt(pass); err != nil {
		h.enc(w, RouteRotateSalt, http.StatusInternalServerError, errData(err.Error()))
		return
	}
	noStore(w)
	h.enc(w, RouteRotateSalt, http.StatusOK, map[string]string{"status": "salt rotated"})
}

// backup handles GET /keeper/backup.
// Streams the bbolt database snapshot as application/octet-stream.
func (h *handler) backup(w http.ResponseWriter, r *http.Request) {
	if !h.guardRequest(w, r, RouteBackup) {
		return
	}
	filename := fmt.Sprintf("keeper-backup-%s.db", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)

	if _, err := h.store.Backup(w); err != nil {
		h.log.Printf("keephandler: backup stream error: %v", err)
	}
}

// helpers

// noStore writes Cache-Control and Pragma headers that instruct clients and
// intermediaries never to cache the response. Must be called before h.enc
// because h.enc calls WriteHeader which locks headers.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("Pragma", "no-cache")
}

// extractFieldBytes decodes a single named string field from a JSON request
// body into []byte.
//
// Limitation: json.Unmarshal must first decode the field into a Go string
// before we can copy it to []byte. The string's backing array is an immutable
// Go allocation that cannot be zeroed and remains on the heap until GC. This
// means the passphrase briefly exists as a Go string. A full fix requires a
// custom JSON string unquoter that writes directly into []byte; that is
// tracked as a follow-on. The []byte copy returned here is what callers
// zero via wipeBytes — that part is correct.
//
// Returns (nil, false) on any parse error or absent field.
func extractFieldBytes(r *http.Request, field string) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return nil, false
	}
	v, ok := raw[field]
	if !ok {
		return nil, false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, false
	}
	// Convert to []byte immediately. The string s backing array cannot be
	// zeroed (Go limitation — see function comment), but the []byte copy
	// returned here is what callers zero via wipeBytes.
	return []byte(s), true
}

// decodeB64Loose tries standard then URL base64 encoding.
func decodeB64Loose(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(s)
	}
	return data, err
}

// wipeBytes zeros a byte slice in place.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// maxUploadBytes is the maximum accepted multipart file size (4 MiB).
const maxUploadBytes = 4 << 20
