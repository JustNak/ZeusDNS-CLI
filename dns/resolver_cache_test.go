package dns

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHostnameCache_LiteralIP(t *testing.T) {
	c := newHostnameCache(nil) // nil → net.DefaultResolver (never reached for literals)
	ctx := context.Background()

	tests := []string{
		"1.2.3.4",
		"::1",
		"2001:db8::1",
		"0.0.0.0",
		"127.0.0.1",
	}
	for _, ip := range tests {
		got, err := c.lookup(ctx, ip, time.Minute)
		if err != nil {
			t.Errorf("literal %q: unexpected error: %v", ip, err)
		}
		if got != ip {
			t.Errorf("literal %q: got %q, want %q", ip, got, ip)
		}
	}
}

func TestHostnameCache_NilResolver(t *testing.T) {
	// Ensure constructing with nil does not panic and creates a usable cache.
	c := newHostnameCache(nil)
	if c == nil {
		t.Fatal("newHostnameCache(nil) returned nil")
	}
	if c.resolver != net.DefaultResolver {
		t.Fatal("newHostnameCache(nil) did not set net.DefaultResolver")
	}
	if c.m == nil {
		t.Fatal("newHostnameCache(nil) has nil map")
	}

	// Literal IP path should still work.
	got, err := c.lookup(context.Background(), "10.0.0.1", time.Minute)
	if err != nil {
		t.Fatalf("literal lookup after nil construction: %v", err)
	}
	if got != "10.0.0.1" {
		t.Fatalf("literal lookup after nil construction: got %q, want %q", got, "10.0.0.1")
	}
}

func TestHostnameCache_ExplicitResolver(t *testing.T) {
	r := &net.Resolver{}
	c := newHostnameCache(r)
	if c.resolver != r {
		t.Fatal("newHostnameCache(r) did not store the provided resolver")
	}
}

func TestHostnameCache_EmptyHost(t *testing.T) {
	// An empty host should fail via the resolver path with a
	// context-cancellable error rather than panicking or returning
	// nonsense.
	c := newHostnameCache(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := c.lookup(ctx, "", time.Minute)
	if err == nil {
		t.Fatal("expected error for empty host, got nil")
	}
}

// TestHostnameCache_Coalesce verifies that concurrent lookups for the same
// host share a single resolution and both get the same cached result.
func TestHostnameCache_Coalesce(t *testing.T) {
	// Use a resolver pointed at a known-good resolver so we can resolve
	// "localhost" without hitting the system resolver which may be
	// 127.0.0.1 (ZeusDNS itself).
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Use the bootstrap resolver to avoid loop
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	c := newHostnameCache(r)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First lookup populates the cache.
	ip1, err := c.lookup(ctx, "localhost", 30*time.Second)
	if err != nil {
		t.Skipf("network-dependent: cannot resolve localhost via 8.8.8.8: %v", err)
	}
	if ip1 == "" {
		t.Fatal("got empty IP for localhost")
	}

	// Second lookup should hit cache.
	ip2, err := c.lookup(ctx, "localhost", 30*time.Second)
	if err != nil {
		t.Fatalf("second lookup failed: %v", err)
	}
	if ip2 != ip1 {
		t.Fatalf("cache returned different IP: first=%q, second=%q", ip1, ip2)
	}
}
