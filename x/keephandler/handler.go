package keephandler

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/agberohq/keeper"
)

// Mount registers all keeper HTTP endpoints on mux under the configured prefix.
// The default prefix is "/keeper". All routes follow Go 1.22+ method+pattern
// syntax so they work with stdlib http.ServeMux directly.
//
// Endpoints registered:
//
//	POST   {prefix}/unlock          — unlock the store with a passphrase
//	POST   {prefix}/lock            — lock the store
//	GET    {prefix}/status          — locked/enabled state (safe to poll)
//	GET    {prefix}/keys            — list all secret keys
//	GET    {prefix}/keys/{key}      — retrieve a secret value
//	POST   {prefix}/keys            — store a secret
//	DELETE {prefix}/keys/{key}      — delete a secret
//	POST   {prefix}/rotate          — rotate the master passphrase
//	POST   {prefix}/rotate/salt     — rotate the KDF salt
//	GET    {prefix}/backup          — stream a database backup
//
// Authentication is entirely the caller's responsibility. Apply middleware to
// mux, or use WithGuard for principal-level checks on built-in routes.
func Mount(mux *http.ServeMux, store *keeper.Keeper, opts ...Option) {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}

	h := &handler{store: store, log: cfg.logger, enc: cfg.encoder, guard: cfg.guard}
	p := cfg.prefix

	route := func(name, pattern string, fn http.HandlerFunc) {
		hook, hasHook := hooksFor(name, cfg.hooks)
		if hasHook {
			fn = hookWrap(fn, hook, h.enc)
		}
		mux.HandleFunc(pattern, fn)
	}

	route(RouteUnlock, "POST "+p+"/unlock", h.unlock)
	route(RouteLock, "POST "+p+"/lock", h.lock)
	route(RouteStatus, "GET "+p+"/status", h.status)
	route(RouteList, "GET "+p+"/keys", h.list)
	route(RouteGet, "GET "+p+"/keys/{key}", h.get)
	route(RouteSet, "POST "+p+"/keys", h.set)
	route(RouteDelete, "DELETE "+p+"/keys/{key}", h.delete)
	route(RouteRotate, "POST "+p+"/rotate", h.rotate)
	route(RouteRotateSalt, "POST "+p+"/rotate/salt", h.rotateSalt)
	route(RouteBackup, "GET "+p+"/backup", h.backup)

	if cfg.extraRoutes != nil {
		cfg.extraRoutes(mux)
	}
}

// handler holds the dependencies shared across all route handlers.
type handler struct {
	store *keeper.Keeper
	log   logger
	enc   ResponseEncoder
	guard GuardFunc
}

// guard returns false and writes the appropriate error response when the store
// is not configured or is locked. If a GuardFunc is configured it is called
// after the locked-check — the GuardFunc is responsible for writing its own
// error response and returning false to abort.
func (h *handler) guardRequest(w http.ResponseWriter, r *http.Request, route string) bool {
	if h.store == nil {
		h.enc(w, route, http.StatusServiceUnavailable, errData("keeper not configured"))
		return false
	}
	if h.store.IsLocked() {
		h.enc(w, route, http.StatusLocked, errData("keeper is locked — POST /keeper/unlock first"))
		return false
	}
	if h.guard != nil {
		return h.guard(w, r, route)
	}
	return true
}

// ── hookWrap ─────────────────────────────────────────────────────────────────

// hookWrap wraps fn with the lifecycle functions in hook.
// The enc parameter is used only to write the internal-error response when
// hook.Before returns a non-nil error.
func hookWrap(fn http.HandlerFunc, hook Hook, enc ResponseEncoder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Before
		if hook.Before != nil {
			allow, err := hook.Before(w, r)
			if err != nil {
				// Before signalled an internal error; it has NOT written to w.
				enc(w, "", http.StatusInternalServerError, errData(err.Error()))
				return
			}
			if !allow {
				// Before has already written the complete response.
				return
			}
		}

		// No After hook and no capture needed — call fn directly.
		if hook.After == nil {
			fn(w, r)
			return
		}

		if hook.CaptureBody {
			// Buffer the response so AfterFunc gets status + body.
			rec := &responseRecorder{
				ResponseWriter: w,
				buf:            &bytes.Buffer{},
				status:         http.StatusOK,
			}
			fn(rec, r)
			// Flush buffered response to the real writer.
			w.WriteHeader(rec.status)
			w.Write(rec.buf.Bytes()) //nolint:errcheck
			hook.After(r, rec.status, rec.buf.Bytes())
		} else {
			// Status-only: wrap just to capture the written status code.
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			fn(sw, r)
			hook.After(r, sw.status, nil)
		}
	}
}

// responseRecorder buffers the full response for AfterFunc when CaptureBody is true.
type responseRecorder struct {
	http.ResponseWriter
	buf    *bytes.Buffer
	status int
}

func (r *responseRecorder) WriteHeader(code int) { r.status = code }
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.buf.Write(b)
}

// statusWriter captures only the status code; it does not buffer the body.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// ── default encoder ───────────────────────────────────────────────────────────

// defaultEncoder writes flat JSON. It is the ResponseEncoder used when the
// caller does not supply WithEncoder.
func defaultEncoder(w http.ResponseWriter, _ string, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

// errData returns the standard error payload used by defaultEncoder.
func errData(msg string) map[string]string {
	return map[string]string{"error": msg}
}

// wipeBytes zeros a byte slice in place.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// maxUploadBytes is the maximum accepted multipart file size (4 MiB).
const maxUploadBytes = 4 << 20
