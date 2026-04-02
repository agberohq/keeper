// Package keephandler provides a router-agnostic HTTP handler that mounts
// keeper secret management endpoints onto any net/http compatible mux.
// Authentication and access control are entirely the caller's responsibility —
// apply middleware or use WithGuard / WithHooks before or after calling Mount.
package keephandler

import (
	"log"
	"net/http"
)

// config holds resolved Mount configuration.
type config struct {
	prefix      string
	logger      logger
	extraRoutes func(mux *http.ServeMux)
	hooks       []Hook
	encoder     ResponseEncoder
	guard       GuardFunc
}

// logger is the minimal logging interface used by the handler.
type logger interface {
	Printf(format string, v ...any)
}

// defaultLogger wraps the stdlib log package.
type defaultLogger struct{}

func (defaultLogger) Printf(format string, v ...any) { log.Printf(format, v...) }

// Option configures the behaviour of Mount.
type Option func(*config)

// WithPrefix sets the URL prefix under which all endpoints are registered.
// Default is "/keeper". The prefix must start with "/" and must not end with "/".
func WithPrefix(prefix string) Option {
	return func(c *config) {
		if prefix != "" {
			c.prefix = prefix
		}
	}
}

// WithLogger attaches a custom logger. If nil the option is ignored.
func WithLogger(l logger) Option {
	return func(c *config) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithRoutes registers additional handlers on the same mux after all built-in
// routes have been registered. Use this to extend the handler with
// application-specific endpoints (e.g. TOTP, webhooks) without reimplementing
// the core routes.
func WithRoutes(fn func(mux *http.ServeMux)) Option {
	return func(c *config) {
		c.extraRoutes = fn
	}
}

// WithHooks attaches Before/After hooks to named built-in routes.
// Multiple calls to WithHooks are additive — hooks are appended in order.
// See Hook for the full contract.
func WithHooks(hooks ...Hook) Option {
	return func(c *config) {
		c.hooks = append(c.hooks, hooks...)
	}
}

// WithEncoder replaces the default JSON response writer with enc.
// enc is called by every route handler instead of the built-in jsonOK / jsonError.
// Use this to add envelope fields, redact values, or change the response shape.
// If enc is nil the option is ignored.
func WithEncoder(enc ResponseEncoder) Option {
	return func(c *config) {
		if enc != nil {
			c.encoder = enc
		}
	}
}

// WithGuard attaches a principal-level access check that runs on every
// protected route (all routes except status and unlock) after the built-in
// locked-check passes. If fn is nil the option is ignored.
func WithGuard(fn GuardFunc) Option {
	return func(c *config) {
		if fn != nil {
			c.guard = fn
		}
	}
}

func defaultConfig() config {
	return config{
		prefix:  "/keeper",
		logger:  defaultLogger{},
		encoder: defaultEncoder,
		guard:   nil,
	}
}

// hooksFor returns the Hook for routeName, or the zero Hook if none registered.
// Only the first Hook registered for a given route name is used.
func hooksFor(routeName string, hooks []Hook) (Hook, bool) {
	for _, h := range hooks {
		if h.Route == routeName {
			return h, true
		}
	}
	return Hook{}, false
}

// Hook

// RouteNames is the set of valid Hook.Route values, one per built-in endpoint.
const (
	RouteUnlock     = "unlock"
	RouteLock       = "lock"
	RouteStatus     = "status"
	RouteList       = "list"
	RouteGet        = "get"
	RouteSet        = "set"
	RouteDelete     = "delete"
	RouteRotate     = "rotate"
	RouteRotateSalt = "rotate-salt"
	RouteBackup     = "backup"
)

// BeforeFunc runs before the built-in handler executes.
//
// Returning (true, nil) lets the request proceed normally.
// Returning (false, nil) aborts the request; the BeforeFunc is responsible for
// writing a complete HTTP response (status + body) before returning.
// Returning (false, err) aborts the request; the handler writes a 500 JSON
// error using err.Error() as the message, so the BeforeFunc must NOT have
// written anything to w yet.
type BeforeFunc func(w http.ResponseWriter, r *http.Request) (allow bool, err error)

// AfterFunc runs after the built-in handler has finished.
//
// If Hook.CaptureBody is true, status and body contain the captured response.
// If Hook.CaptureBody is false, body is always nil and status is always 0
// (the response has already been flushed; capturing is not possible without
// the recorder overhead).
//
// AfterFunc must not write to w — the response has already been sent.
// Use it for audit logging, metrics, or cache invalidation.
type AfterFunc func(r *http.Request, status int, body []byte)

// Hook attaches lifecycle functions to a single named built-in route.
//
//	keephandler.WithHooks(keephandler.Hook{
//	    Route:  keephandler.RouteGet,
//	    Before: func(w http.ResponseWriter, r *http.Request) (bool, error) {
//	        principal := r.Header.Get("X-Principal")
//	        key := r.PathValue("key")
//	        if !acl.Allow(principal, "read", key) {
//	            http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
//	            return false, nil
//	        }
//	        return true, nil
//	    },
//	    After:       func(r *http.Request, status int, body []byte) { audit.Log(r, status) },
//	    CaptureBody: false, // status-only is cheaper; no responseRecorder needed
//	})
type Hook struct {
	// Route is one of the RouteXxx constants (e.g. RouteGet, RouteSet).
	Route string

	// Before is called before the built-in handler. May be nil.
	Before BeforeFunc

	// After is called after the built-in handler. May be nil.
	After AfterFunc

	// CaptureBody controls whether the response body is buffered so that
	// AfterFunc receives it. Buffering costs one allocation and a copy per
	// request — set this to false (the default) when only the status code
	// is needed in AfterFunc.
	CaptureBody bool
}

// ResponseEncoder

// ResponseEncoder writes the HTTP response for a route. It is called by every
// route handler instead of the built-in jsonOK / jsonError.
//
//   - route is one of the RouteXxx constants.
//   - status is the intended HTTP status code.
//   - data is the payload; for errors it is map[string]string{"error": msg}.
//
// The encoder is responsible for setting Content-Type, writing the status
// code, and writing the body. The default encoder writes flat JSON.
type ResponseEncoder func(w http.ResponseWriter, route string, status int, data any)

// GuardFunc

// GuardFunc is an optional access-control function injected via WithGuard.
// It is called on every protected route after the built-in locked-check passes,
// before the route handler body executes.
//
// Returning true allows the request to proceed.
// Returning false signals that the GuardFunc has already written a complete
// HTTP response (status + body) and the route handler must abort.
//
// route is one of the RouteXxx constants so the guard can apply per-route
// logic (e.g. allow list but deny get for a read-restricted principal).
type GuardFunc func(w http.ResponseWriter, r *http.Request, route string) bool
