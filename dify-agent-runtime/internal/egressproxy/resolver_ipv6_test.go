package egressproxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/langgenius/dify/dify-agent-runtime/internal/providers/simple"
)

// An IPv6 literal is a valid host in an allowlist entry and in a request URL.
// req.URL.Hostname() already strips the port, so nothing else needs removing:
// truncating at the last colon turns "::1" into ":" and the pattern can never
// match, which silently disables injection for that host.
func TestInjectHeadersForIPv6LiteralHost(t *testing.T) {
	r := NewResolver()
	r.SetSystemCredentials(map[string]*StoredCredential{
		"internal/key": {
			Value: "s3cret",
			Inject: &simple.Policy{
				HeaderName: "X-Api-Key",
				Domains_:   []string{"::1"},
				Expr:       "{{.Value}}",
			},
		},
	})

	req, err := http.NewRequest("GET", "http://[::1]:8080/a2a", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	r.InjectHeadersFor("", req)

	if got := req.Header.Get("X-Api-Key"); got != "s3cret" {
		t.Fatalf("IPv6 literal host: header %q, want %q (URL.Hostname() = %q)",
			got, "s3cret", req.URL.Hostname())
	}
}

// Same literal with a non-matching pattern must still be refused, so the fix
// above cannot be satisfied by injecting into everything.
func TestInjectHeadersForIPv6LiteralHostNonMatch(t *testing.T) {
	r := NewResolver()
	r.SetSystemCredentials(map[string]*StoredCredential{
		"internal/key": {
			Value: "s3cret",
			Inject: &simple.Policy{
				HeaderName: "X-Api-Key",
				Domains_:   []string{"::2"},
				Expr:       "{{.Value}}",
			},
		},
	})

	req, err := http.NewRequest("GET", "http://[::1]:8080/a2a", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	r.InjectHeadersFor("", req)

	if got := req.Header.Get("X-Api-Key"); got != "" {
		t.Fatalf("non-matching IPv6 pattern: header %q, want empty", got)
	}
}

// The port strip exists for the req.Host fallback, where the host can arrive as
// "name:port". Keep that branch working while the URL path stops mangling
// literals.
func TestInjectHeadersForHostFallbackWithPort(t *testing.T) {
	r := NewResolver()
	r.SetSystemCredentials(map[string]*StoredCredential{
		"internal/key": {
			Value: "s3cret",
			Inject: &simple.Policy{
				HeaderName: "X-Api-Key",
				Domains_:   []string{"api.internal.example"},
				Expr:       "{{.Value}}",
			},
		},
	})

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http"},
		Host:   "api.internal.example:8443",
		Header: http.Header{},
	}
	r.InjectHeadersFor("", req)

	if got := req.Header.Get("X-Api-Key"); got != "s3cret" {
		t.Fatalf("Host fallback with port: header %q, want %q", got, "s3cret")
	}
}
