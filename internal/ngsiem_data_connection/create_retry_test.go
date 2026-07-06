package ngsiemdataconnection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/go-openapi/runtime"
)

// isRetryableCreateError must mirror decodeTokenResponse's retryable set on the create path: 429 and any
// 5xx are transient and retried; deterministic 4xx fails fast; a status-less transport error is retried
// (behind the duplicate guard); context cancellation and nil are never retried. The classification is the
// hinge of the retry loop, so it's pinned here at the unit level.
func TestIsRetryableCreateError(t *testing.T) {
	// runtime.APIError covers the codes gofalcon's create reader funnels through its default case
	// (e.g. 502/503/504); the 403/429/500 cases also have generated typed responses, exercised below.
	for _, tc := range []struct {
		status int
		want   bool
	}{
		{http.StatusInternalServerError, true}, // 500
		{http.StatusBadGateway, true},          // 502
		{http.StatusServiceUnavailable, true},  // 503
		{http.StatusGatewayTimeout, true},      // 504
		{http.StatusTooManyRequests, true},     // 429
		{http.StatusBadRequest, false},         // 400
		{http.StatusForbidden, false},          // 403
		{http.StatusNotFound, false},           // 404
		{http.StatusConflict, false},           // 409
		{http.StatusCreated, false},            // 201 (not an error path, but must not be "retryable")
		{http.StatusOK, false},                 // 200
	} {
		t.Run(fmt.Sprintf("status %d", tc.status), func(t *testing.T) {
			err := runtime.NewAPIError("ExternalCreateDataConnection", nil, tc.status)
			if got := isRetryableCreateError(err); got != tc.want {
				t.Fatalf("isRetryableCreateError(status %d) = %v, want %v", tc.status, got, tc.want)
			}
		})
	}

	// The generated typed responses gofalcon actually returns for 403/429/500 must classify the same as
	// the runtime.APIError codes above — they all implement runtime.ClientResponseStatus.
	t.Run("typed 500 is retryable", func(t *testing.T) {
		if !isRetryableCreateError(ngsiem.NewExternalCreateDataConnectionInternalServerError()) {
			t.Fatal("typed 500 should be retryable")
		}
	})
	t.Run("typed 429 is retryable", func(t *testing.T) {
		if !isRetryableCreateError(ngsiem.NewExternalCreateDataConnectionTooManyRequests()) {
			t.Fatal("typed 429 should be retryable")
		}
	})
	t.Run("typed 403 fails fast", func(t *testing.T) {
		if isRetryableCreateError(ngsiem.NewExternalCreateDataConnectionForbidden()) {
			t.Fatal("typed 403 should fail fast")
		}
	})

	t.Run("nil is not retryable", func(t *testing.T) {
		if isRetryableCreateError(nil) {
			t.Fatal("nil error should not be retryable")
		}
	})
	t.Run("transport error is retryable", func(t *testing.T) {
		if !isRetryableCreateError(errors.New("dial tcp 1.2.3.4:443: connect: connection reset by peer")) {
			t.Fatal("a status-less transport error should be retryable")
		}
	})
	for _, ctxErr := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run("context error "+ctxErr.Error()+" is not retryable", func(t *testing.T) {
			if isRetryableCreateError(ctxErr) {
				t.Fatalf("%v should not be retryable", ctxErr)
			}
			// also when wrapped, as the SDK transport surfaces it
			if isRetryableCreateError(fmt.Errorf("Post %q: %w", "https://x", ctxErr)) {
				t.Fatalf("wrapped %v should not be retryable", ctxErr)
			}
		})
	}
}

// createErrorMayHaveCreated gates the duplicate guard: only errors that could have created a resource
// (5xx, transport) trigger the list-by-name check. A 429 is rejected before processing, so it never
// creates and skips the guard.
func TestCreateErrorMayHaveCreated(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"500 may have created", runtime.NewAPIError("op", nil, http.StatusInternalServerError), true},
		{"503 may have created", runtime.NewAPIError("op", nil, http.StatusServiceUnavailable), true},
		{"typed 500 may have created", ngsiem.NewExternalCreateDataConnectionInternalServerError(), true},
		{"429 cannot have created", runtime.NewAPIError("op", nil, http.StatusTooManyRequests), false},
		{"typed 429 cannot have created", ngsiem.NewExternalCreateDataConnectionTooManyRequests(), false},
		{"transport may have created", errors.New("connection reset"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := createErrorMayHaveCreated(tc.err); got != tc.want {
				t.Fatalf("createErrorMayHaveCreated(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// newConnectionIDs is the core of the duplicate guard: only IDs that appeared AFTER the pre-POST snapshot
// are candidates for "created despite the error". Pre-existing same-named connections (in before) must
// never be adopted.
func TestNewConnectionIDs(t *testing.T) {
	set := func(ids ...string) map[string]struct{} {
		m := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			m[id] = struct{}{}
		}
		return m
	}
	for _, tc := range []struct {
		name          string
		before, after map[string]struct{}
		want          []string
	}{
		{"one new appeared", set("a", "b"), set("a", "b", "c"), []string{"c"}},
		{"created from empty baseline", set(), set("a"), []string{"a"}},
		{"nothing new", set("a"), set("a"), nil},
		{"pre-existing not adopted", set("a", "b"), set("a", "b"), nil},
		{"two new is ambiguous", set("a"), set("a", "c", "d"), []string{"c", "d"}},
		{"disappeared id ignored", set("a", "b"), set("a"), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := newConnectionIDs(tc.before, tc.after)
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("newConnectionIDs = %v, want %v", got, want)
			}
		})
	}
}

// TestCreateConnectionWithRetry drives the retry loop end-to-end against a fake create+list endpoint —
// the riskiest new path: a transient 500 must be retried, and a 500 returned AFTER the connection was
// created server-side must adopt that connection rather than re-POST a duplicate. It mirrors
// TestWaitForIngestTokenPollsUntilReady's poll-loop-against-httptest pattern.
func TestCreateConnectionWithRetry(t *testing.T) {
	orig := createRetryBaseDelay
	createRetryBaseDelay = time.Millisecond
	t.Cleanup(func() { createRetryBaseDelay = orig })

	const name = "tf-acc-test-conn"
	const (
		createPath = "/ngsiem/entities/connections/v1"
		listPath   = "/ngsiem/combined/connections/v1"
	)
	body := &createDataConnectionBody{ConnectorID: "connector-1", Name: name, Parser: "p"}

	t.Run("retries past a 500 then succeeds when nothing was created", func(t *testing.T) {
		var posts int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && r.URL.Path == createPath:
				if atomic.AddInt32(&posts, 1) == 1 {
					w.WriteHeader(http.StatusInternalServerError) // first POST: transient 500, nothing created
					return
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"resources":[{"id":"conn-created"}]}`))
			case r.Method == http.MethodGet && r.URL.Path == listPath:
				_, _ = w.Write([]byte(`{"resources":[]}`)) // guard: no same-named connection exists
			default:
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
		}))
		defer srv.Close()

		res := &ngsiemDataConnectionResource{client: newTestClient(t, srv.URL)}
		id, diag := res.createConnectionWithRetry(context.Background(), body, name)
		if diag != nil {
			t.Fatalf("unexpected diagnostic: %s — %s", diag.Summary(), diag.Detail())
		}
		if id != "conn-created" {
			t.Fatalf("id = %q, want conn-created", id)
		}
		if n := atomic.LoadInt32(&posts); n != 2 {
			t.Fatalf("expected the POST to be retried exactly once (2 calls), got %d", n)
		}
	})

	t.Run("adopts the connection created server-side despite a 500 instead of duplicating it", func(t *testing.T) {
		var posts, created int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && r.URL.Path == createPath:
				atomic.AddInt32(&posts, 1)
				atomic.StoreInt32(&created, 1) // the row IS written, then the response 500s
				w.WriteHeader(http.StatusInternalServerError)
			case r.Method == http.MethodGet && r.URL.Path == listPath:
				if atomic.LoadInt32(&created) == 1 {
					_, _ = w.Write([]byte(`{"resources":[{"id":"conn-adopted","name":"` + name + `"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"resources":[]}`)) // pre-POST snapshot: empty
			default:
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
		}))
		defer srv.Close()

		res := &ngsiemDataConnectionResource{client: newTestClient(t, srv.URL)}
		id, diag := res.createConnectionWithRetry(context.Background(), body, name)
		if diag != nil {
			t.Fatalf("unexpected diagnostic: %s — %s", diag.Summary(), diag.Detail())
		}
		if id != "conn-adopted" {
			t.Fatalf("id = %q, want conn-adopted (the connection created despite the 500)", id)
		}
		if n := atomic.LoadInt32(&posts); n != 1 {
			t.Fatalf("expected NO re-POST after adopting (1 call), got %d — a retry here would duplicate", n)
		}
	})

	t.Run("a non-retryable 4xx fails fast without retrying", func(t *testing.T) {
		var posts int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && r.URL.Path == createPath:
				atomic.AddInt32(&posts, 1)
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":[{"code":403,"message":"forbidden"}]}`))
			case r.Method == http.MethodGet && r.URL.Path == listPath:
				_, _ = w.Write([]byte(`{"resources":[]}`))
			default:
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
		}))
		defer srv.Close()

		res := &ngsiemDataConnectionResource{client: newTestClient(t, srv.URL)}
		if _, diag := res.createConnectionWithRetry(context.Background(), body, name); diag == nil {
			t.Fatal("expected a diagnostic for a 403")
		}
		if n := atomic.LoadInt32(&posts); n != 1 {
			t.Fatalf("403 must not be retried (1 POST), got %d", n)
		}
	})
}

// createRetryDelay grows the backoff exponentially from createRetryBaseDelay and caps it at
// createRetryMaxDelay; it never returns a non-positive delay (which would busy-loop the retry).
func TestCreateRetryDelay(t *testing.T) {
	orig := createRetryBaseDelay
	createRetryBaseDelay = time.Second
	t.Cleanup(func() { createRetryBaseDelay = orig })

	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, createRetryMaxDelay}, // 16s capped to 8s
		{10, createRetryMaxDelay},
	} {
		t.Run(fmt.Sprintf("attempt %d", tc.attempt), func(t *testing.T) {
			got := createRetryDelay(tc.attempt)
			if got != tc.want {
				t.Fatalf("createRetryDelay(%d) = %s, want %s", tc.attempt, got, tc.want)
			}
			if got <= 0 {
				t.Fatalf("createRetryDelay(%d) must be positive, got %s", tc.attempt, got)
			}
		})
	}
}
