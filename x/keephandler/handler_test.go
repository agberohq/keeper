package keephandler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agberohq/keeper"
	"github.com/agberohq/keeper/x/keephandler"
)

// ── test server helpers ───────────────────────────────────────────────────────

// newTestServer creates an httptest.Server with a fresh unlocked keeper store
// mounted at /keeper. The store is closed when the test ends.
func newTestServer(t *testing.T, opts ...keephandler.Option) (*httptest.Server, *keeper.Keeper) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("keeper.New: %v", err)
	}
	if err := store.Unlock([]byte("testpass")); err != nil {
		store.Close()
		t.Fatalf("Unlock: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	mux := http.NewServeMux()
	keephandler.Mount(mux, store, opts...)
	return httptest.NewServer(mux), store
}

// newLockedServer creates a server whose store has been unlocked once with
// "testpass" to write the verification hash, then locked again.
// A brand-new keeper store with no verification hash accepts any passphrase on
// first unlock, so we must establish the hash before testing wrong-passphrase rejection.
func newLockedServer(t *testing.T, opts ...keephandler.Option) *httptest.Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "locked.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("keeper.New: %v", err)
	}
	if err := store.Unlock([]byte("testpass")); err != nil {
		store.Close()
		t.Fatalf("initial unlock: %v", err)
	}
	if err := store.Lock(); err != nil {
		store.Close()
		t.Fatalf("lock: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	mux := http.NewServeMux()
	keephandler.Mount(mux, store, opts...)
	return httptest.NewServer(mux)
}

func do(t *testing.T, srv *httptest.Server, method, path, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return m
}

// ── status ────────────────────────────────────────────────────────────────────

func TestStatus_Unlocked(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/status", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	if m["locked"] != false {
		t.Errorf("locked: want false, got %v", m["locked"])
	}
	if m["enabled"] != true {
		t.Errorf("enabled: want true, got %v", m["enabled"])
	}
}

func TestStatus_Locked(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/status", "")
	m := readJSON(t, resp)
	if m["locked"] != true {
		t.Errorf("locked: want true, got %v", m["locked"])
	}
}

// ── unlock / lock ─────────────────────────────────────────────────────────────

func TestUnlock_ValidPassphrase(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/unlock", `{"passphrase":"testpass"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock: want 200, got %d", resp.StatusCode)
	}
}

func TestUnlock_WrongPassphrase(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/unlock", `{"passphrase":"wrong"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unlock wrong: want 401, got %d", resp.StatusCode)
	}
}

func TestUnlock_MissingPassphrase(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/unlock", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unlock empty: want 400, got %d", resp.StatusCode)
	}
}

func TestLock(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/lock", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("lock: want 200, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	if m["status"] != "locked" {
		t.Errorf("status: want locked, got %v", m["status"])
	}
}

// ── list ──────────────────────────────────────────────────────────────────────

func TestList_Empty(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list empty: want 200, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	keys, ok := m["keys"].([]any)
	if !ok {
		t.Fatalf("keys field missing or wrong type: %v", m)
	}
	if len(keys) != 0 {
		t.Errorf("expected empty list, got %v", keys)
	}
}

func TestList_AfterSet(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	do(t, srv, "POST", "/keeper/keys", `{"key":"k1","value":"v1"}`)
	do(t, srv, "POST", "/keeper/keys", `{"key":"k2","value":"v2"}`)

	resp := do(t, srv, "GET", "/keeper/keys", "")
	m := readJSON(t, resp)
	keys := m["keys"].([]any)
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestList_WhenLocked(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("list locked: want 423, got %d", resp.StatusCode)
	}
}

// ── get ───────────────────────────────────────────────────────────────────────

func TestGet_Existing(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	do(t, srv, "POST", "/keeper/keys", `{"key":"mykey","value":"mysecret"}`)

	resp := do(t, srv, "GET", "/keeper/keys/mykey", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: want 200, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	if m["value"] != "mysecret" {
		t.Errorf("value: want mysecret, got %v", m["value"])
	}
}

func TestGet_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys/nonexistent", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get missing: want 404, got %d", resp.StatusCode)
	}
}

func TestGet_WhenLocked(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys/k", "")
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("get locked: want 423, got %d", resp.StatusCode)
	}
}

// ── set ───────────────────────────────────────────────────────────────────────

func TestSet_JSON(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/keys", `{"key":"setkey","value":"setval"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set: want 200, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	if m["key"] != "setkey" {
		t.Errorf("key: want setkey, got %v", m["key"])
	}
}

func TestSet_Base64(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	// "hello" → aGVsbG8=
	resp := do(t, srv, "POST", "/keeper/keys", `{"key":"b64key","value":"aGVsbG8=","b64":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set b64: want 200, got %d", resp.StatusCode)
	}
}

func TestSet_MissingKey(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/keys", `{"value":"val"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("set no key: want 400, got %d", resp.StatusCode)
	}
}

func TestSet_MissingValue(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/keys", `{"key":"k"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("set no value: want 400, got %d", resp.StatusCode)
	}
}

func TestSet_Multipart(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("key", "mpkey")
	fw, _ := w.CreateFormFile("file", "secret.txt")
	fw.Write([]byte("multipart-value"))
	w.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/keeper/keys", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("multipart request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set multipart: want 200, got %d", resp.StatusCode)
	}
}

func TestSet_WhenLocked(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/keys", `{"key":"k","value":"v"}`)
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("set locked: want 423, got %d", resp.StatusCode)
	}
}

// ── delete ────────────────────────────────────────────────────────────────────

func TestDelete_Existing(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	do(t, srv, "POST", "/keeper/keys", `{"key":"delkey","value":"val"}`)

	resp := do(t, srv, "DELETE", "/keeper/keys/delkey", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: want 200, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	if m["deleted"] != "delkey" {
		t.Errorf("deleted: want delkey, got %v", m["deleted"])
	}

	getResp := do(t, srv, "GET", "/keeper/keys/delkey", "")
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("after delete: want 404, got %d", getResp.StatusCode)
	}
}

func TestDelete_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "DELETE", "/keeper/keys/ghost", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing: want 404, got %d", resp.StatusCode)
	}
}

func TestDelete_WhenLocked(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "DELETE", "/keeper/keys/k", "")
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("delete locked: want 423, got %d", resp.StatusCode)
	}
}

// ── rotate ────────────────────────────────────────────────────────────────────

func TestRotate(t *testing.T) {
	srv, store := newTestServer(t)
	defer srv.Close()

	store.Set("rk", []byte("rv"))

	resp := do(t, srv, "POST", "/keeper/rotate", `{"new_passphrase":"newpass"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate: want 200, got %d", resp.StatusCode)
	}
}

func TestRotate_MissingPassphrase(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/rotate", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("rotate no pass: want 400, got %d", resp.StatusCode)
	}
}

// ── backup ────────────────────────────────────────────────────────────────────

func TestBackup(t *testing.T) {
	srv, store := newTestServer(t)
	defer srv.Close()

	store.Set("bk", []byte("bv"))

	resp := do(t, srv, "GET", "/keeper/backup", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backup: want 200, got %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content-type: want application/octet-stream, got %s", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "keeper-backup") {
		t.Errorf("content-disposition missing backup filename: %s", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("backup body is empty")
	}
}

func TestBackup_WhenLocked(t *testing.T) {
	srv := newLockedServer(t)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/backup", "")
	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("backup locked: want 423, got %d", resp.StatusCode)
	}
}

// ── custom prefix ─────────────────────────────────────────────────────────────

func TestMount_CustomPrefix(t *testing.T) {
	srv, _ := newTestServer(t, keephandler.WithPrefix("/api/v1/secrets"))
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/api/v1/secrets/status")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom prefix status: want 200, got %d", resp.StatusCode)
	}
}

// ── WithRoutes extension ──────────────────────────────────────────────────────

func TestMount_WithRoutes(t *testing.T) {
	srv, _ := newTestServer(t, keephandler.WithRoutes(func(m *http.ServeMux) {
		m.HandleFunc("GET /keeper/custom", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
	}))
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/keeper/custom")
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("custom route: want 418, got %d", resp.StatusCode)
	}
}

// ── nil store ─────────────────────────────────────────────────────────────────

func TestMount_NilStore(t *testing.T) {
	mux := http.NewServeMux()
	keephandler.Mount(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/keeper/status", http.StatusOK},
		{"/keeper/keys", http.StatusServiceUnavailable},
	} {
		resp, _ := http.Get(srv.URL + tc.path)
		if resp.StatusCode != tc.want {
			t.Errorf("%s: want %d, got %d", tc.path, tc.want, resp.StatusCode)
		}
	}
}

// ── round-trip ────────────────────────────────────────────────────────────────

func TestRoundTrip_SetGetDelete(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("rt-key-%d", i)
		val := fmt.Sprintf("rt-val-%d", i)

		setResp := do(t, srv, "POST", "/keeper/keys",
			fmt.Sprintf(`{"key":%q,"value":%q}`, key, val))
		if setResp.StatusCode != http.StatusOK {
			t.Fatalf("set %s: %d", key, setResp.StatusCode)
		}

		getResp := do(t, srv, "GET", "/keeper/keys/"+key, "")
		m := readJSON(t, getResp)
		if m["value"] != val {
			t.Errorf("get %s: want %s, got %v", key, val, m["value"])
		}

		delResp := do(t, srv, "DELETE", "/keeper/keys/"+key, "")
		if delResp.StatusCode != http.StatusOK {
			t.Fatalf("delete %s: %d", key, delResp.StatusCode)
		}
	}
}

// ── WithHooks — Before ────────────────────────────────────────────────────────

// TestHook_Before_Allow verifies that a Before hook returning (true, nil)
// lets the request proceed and the real handler response is returned.
func TestHook_Before_Allow(t *testing.T) {
	var called atomic.Bool
	hook := keephandler.Hook{
		Route: keephandler.RouteGet,
		Before: func(w http.ResponseWriter, r *http.Request) (bool, error) {
			called.Store(true)
			return true, nil // allow
		},
	}

	srv, _ := newTestServer(t, keephandler.WithHooks(hook))
	defer srv.Close()

	do(t, srv, "POST", "/keeper/keys", `{"key":"hk","value":"hv"}`)
	resp := do(t, srv, "GET", "/keeper/keys/hk", "")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !called.Load() {
		t.Error("Before hook was not called")
	}
}

// TestHook_Before_Deny verifies that a Before hook returning (false, nil)
// aborts the request with whatever the hook wrote — here 403.
func TestHook_Before_Deny(t *testing.T) {
	hook := keephandler.Hook{
		Route: keephandler.RouteGet,
		Before: func(w http.ResponseWriter, r *http.Request) (bool, error) {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return false, nil
		},
	}

	srv, _ := newTestServer(t, keephandler.WithHooks(hook))
	defer srv.Close()

	do(t, srv, "POST", "/keeper/keys", `{"key":"denied","value":"secret"}`)
	resp := do(t, srv, "GET", "/keeper/keys/denied", "")

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestHook_Before_Error verifies that a Before hook returning (false, err)
// causes a 500 JSON response without the hook having written anything.
func TestHook_Before_Error(t *testing.T) {
	hook := keephandler.Hook{
		Route: keephandler.RouteList,
		Before: func(w http.ResponseWriter, r *http.Request) (bool, error) {
			return false, fmt.Errorf("auth service unavailable")
		},
	}

	srv, _ := newTestServer(t, keephandler.WithHooks(hook))
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", resp.StatusCode)
	}
	m := readJSON(t, resp)
	if !strings.Contains(fmt.Sprint(m["error"]), "auth service unavailable") {
		t.Errorf("error message missing: %v", m)
	}
}

// TestHook_Before_OnlyTargetRoute verifies that a hook on RouteGet does NOT
// intercept requests to other routes (e.g. list).
func TestHook_Before_OnlyTargetRoute(t *testing.T) {
	var getCalled atomic.Bool
	hook := keephandler.Hook{
		Route: keephandler.RouteGet,
		Before: func(w http.ResponseWriter, r *http.Request) (bool, error) {
			getCalled.Store(true)
			return true, nil
		},
	}

	srv, _ := newTestServer(t, keephandler.WithHooks(hook))
	defer srv.Close()

	// list should not trigger the get hook
	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: want 200, got %d", resp.StatusCode)
	}
	if getCalled.Load() {
		t.Error("get hook fired on list request")
	}
}

// ── WithHooks — After (status-only) ──────────────────────────────────────────

// TestHook_After_StatusOnly verifies that After receives the correct status
// code when CaptureBody is false.
func TestHook_After_StatusOnly(t *testing.T) {
	var capturedStatus atomic.Int32
	hook := keephandler.Hook{
		Route:       keephandler.RouteSet,
		CaptureBody: false,
		After: func(r *http.Request, status int, body []byte) {
			capturedStatus.Store(int32(status))
			if body != nil {
				panic("body should be nil when CaptureBody is false")
			}
		},
	}

	srv, _ := newTestServer(t, keephandler.WithHooks(hook))
	defer srv.Close()

	resp := do(t, srv, "POST", "/keeper/keys", `{"key":"ak","value":"av"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("set: want 200, got %d", resp.StatusCode)
	}
	if got := int(capturedStatus.Load()); got != http.StatusOK {
		t.Errorf("After status: want 200, got %d", got)
	}
}

// ── WithHooks — After (capture body) ─────────────────────────────────────────

// TestHook_After_CaptureBody verifies that After receives the full response
// body when CaptureBody is true, and that the client also receives it.
func TestHook_After_CaptureBody(t *testing.T) {
	var capturedStatus atomic.Int32
	var capturedBody atomic.Value // stores []byte

	hook := keephandler.Hook{
		Route:       keephandler.RouteGet,
		CaptureBody: true,
		After: func(r *http.Request, status int, body []byte) {
			capturedStatus.Store(int32(status))
			cp := make([]byte, len(body))
			copy(cp, body)
			capturedBody.Store(cp)
		},
	}

	srv, _ := newTestServer(t, keephandler.WithHooks(hook))
	defer srv.Close()

	do(t, srv, "POST", "/keeper/keys", `{"key":"ck","value":"cv"}`)
	resp := do(t, srv, "GET", "/keeper/keys/ck", "")

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: want 200, got %d", resp.StatusCode)
	}
	// Client should receive the full body.
	clientBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(clientBody), "cv") {
		t.Errorf("client body missing value: %s", clientBody)
	}
	// AfterFunc should have received the same body.
	if got := int(capturedStatus.Load()); got != http.StatusOK {
		t.Errorf("After status: want 200, got %d", got)
	}
	b, _ := capturedBody.Load().([]byte)
	if !strings.Contains(string(b), "cv") {
		t.Errorf("After body missing value: %s", b)
	}
}

// ── WithEncoder ───────────────────────────────────────────────────────────────

// TestWithEncoder_CustomEnvelope verifies that a custom ResponseEncoder can
// wrap responses in an application-specific envelope.
func TestWithEncoder_CustomEnvelope(t *testing.T) {
	enc := func(w http.ResponseWriter, route string, status int, data any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":    status < 400,
			"route": route,
			"data":  data,
		})
	}

	srv, _ := newTestServer(t, keephandler.WithEncoder(enc))
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/status", "")
	m := readJSON(t, resp)

	if m["ok"] != true {
		t.Errorf("envelope ok: want true, got %v", m["ok"])
	}
	if m["route"] != keephandler.RouteStatus {
		t.Errorf("envelope route: want %q, got %v", keephandler.RouteStatus, m["route"])
	}
	if _, hasData := m["data"]; !hasData {
		t.Error("envelope missing data field")
	}
}

// TestWithEncoder_ErrorShape verifies that the custom encoder also receives
// error payloads (4xx/5xx), allowing uniform error formatting.
func TestWithEncoder_ErrorShape(t *testing.T) {
	var lastStatus atomic.Int32
	enc := func(w http.ResponseWriter, route string, status int, data any) {
		lastStatus.Store(int32(status))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(data)
	}

	srv := newLockedServer(t, keephandler.WithEncoder(enc))
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	resp.Body.Close()

	if resp.StatusCode != http.StatusLocked {
		t.Fatalf("want 423, got %d", resp.StatusCode)
	}
	if got := int(lastStatus.Load()); got != http.StatusLocked {
		t.Errorf("encoder saw status %d, want 423", got)
	}
}

// ── WithGuard ─────────────────────────────────────────────────────────────────

// TestWithGuard_Allow verifies that a GuardFunc returning true lets
// the request proceed normally.
func TestWithGuard_Allow(t *testing.T) {
	var guardCalled atomic.Bool
	guard := func(w http.ResponseWriter, r *http.Request, route string) bool {
		guardCalled.Store(true)
		return true
	}

	srv, _ := newTestServer(t, keephandler.WithGuard(guard))
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !guardCalled.Load() {
		t.Error("guard was not called")
	}
}

// TestWithGuard_Deny verifies that a GuardFunc returning false aborts the
// request and the handler body does not execute.
func TestWithGuard_Deny(t *testing.T) {
	guard := func(w http.ResponseWriter, r *http.Request, route string) bool {
		http.Error(w, `{"error":"principal not allowed"}`, http.StatusForbidden)
		return false
	}

	srv, _ := newTestServer(t, keephandler.WithGuard(guard))
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestWithGuard_RouteAware verifies that the GuardFunc receives the correct
// route name so it can apply per-route policy.
func TestWithGuard_RouteAware(t *testing.T) {
	var seenRoutes []string
	guard := func(w http.ResponseWriter, r *http.Request, route string) bool {
		seenRoutes = append(seenRoutes, route)
		return true
	}

	srv, _ := newTestServer(t, keephandler.WithGuard(guard))
	defer srv.Close()

	do(t, srv, "GET", "/keeper/keys", "")
	do(t, srv, "POST", "/keeper/keys", `{"key":"gk","value":"gv"}`)
	do(t, srv, "GET", "/keeper/keys/gk", "")

	want := []string{keephandler.RouteList, keephandler.RouteSet, keephandler.RouteGet}
	for i, w := range want {
		if i >= len(seenRoutes) {
			t.Fatalf("guard called only %d times, want %d", len(seenRoutes), len(want))
		}
		if seenRoutes[i] != w {
			t.Errorf("guard route[%d]: want %q, got %q", i, w, seenRoutes[i])
		}
	}
}

// TestWithGuard_NotCalledOnStatus verifies that status (an unguarded route)
// does not invoke the GuardFunc — status must always be safe to poll.
func TestWithGuard_NotCalledOnStatus(t *testing.T) {
	var guardCalled atomic.Bool
	guard := func(w http.ResponseWriter, r *http.Request, route string) bool {
		guardCalled.Store(true)
		return true
	}

	srv, _ := newTestServer(t, keephandler.WithGuard(guard))
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/status", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
	if guardCalled.Load() {
		t.Error("guard must not be called for /status")
	}
}

// TestWithGuard_AndHook_Composition verifies that WithGuard and WithHooks can
// coexist on the same route: the Hook.Before fires, then the route handler
// (which calls guardRequest internally) executes if Before allowed it.
func TestWithGuard_AndHook_Composition(t *testing.T) {
	var hookFired, guardFired atomic.Bool

	hook := keephandler.Hook{
		Route: keephandler.RouteList,
		Before: func(w http.ResponseWriter, r *http.Request) (bool, error) {
			hookFired.Store(true)
			return true, nil
		},
	}
	guard := func(w http.ResponseWriter, r *http.Request, route string) bool {
		guardFired.Store(true)
		return true
	}

	srv, _ := newTestServer(t,
		keephandler.WithHooks(hook),
		keephandler.WithGuard(guard),
	)
	defer srv.Close()

	resp := do(t, srv, "GET", "/keeper/keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if !hookFired.Load() {
		t.Error("Before hook was not fired")
	}
	if !guardFired.Load() {
		t.Error("GuardFunc was not fired")
	}
}
