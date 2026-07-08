package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultHostnameTTL is how long a resolved upstream hostname IP is cached
// before re-resolution. Long enough to avoid per-dial DNS tax, short enough
// to pick up upstream IP changes.
const DefaultHostnameTTL = 5 * time.Minute

// hostnameCache caches resolved IPs per hostname with a TTL so DoT/DoH clients
// do not re-resolve the upstream hostname on every connection dial.
type hostnameCache struct {
	resolver *net.Resolver
	mu       sync.Mutex
	m        map[string]cachedIPs
	sf       singleflight.Group
}

type cachedIPs struct {
	ips []string
	exp time.Time
}

// newHostnameCache creates a cache wrapping the given resolver. If r is nil,
// net.DefaultResolver is used instead.
func newHostnameCache(r *net.Resolver) *hostnameCache {
	if r == nil {
		r = net.DefaultResolver
	}
	return &hostnameCache{
		resolver: r,
		m:        make(map[string]cachedIPs),
	}
}

// lookup returns an IP string for host. It uses the cached value if fresh;
// on miss or expiry it performs one LookupHost through the resolver and
// caches the result for the specified TTL. On resolution failure it returns
// the error and does NOT poison the cache. If host is a literal IP address
// it is returned immediately without consulting the cache or resolver.
func (h *hostnameCache) lookup(ctx context.Context, host string, ttl time.Duration) (string, error) {
	// Literal IP — short circuit.
	if net.ParseIP(host) != nil {
		return host, nil
	}
	// Fast path: fresh cache hit under a brief lock (no I/O).
	h.mu.Lock()
	if c, ok := h.m[host]; ok && time.Now().Before(c.exp) {
		h.mu.Unlock()
		return c.ips[0], nil
	}
	h.mu.Unlock()
	// Slow path: coalesce concurrent same-host lookups; the map lock is
	// NOT held during the network resolve, so a slow host-A resolve can't
	// block a concurrent host-B resolve. The leader uses a
	// caller-cancellation-surviving context so that waiters with still-valid
	// contexts are not poisoned by a cancelled leader. After the singleflight
	// returns, we check the ORIGINAL caller context before using the cached
	// result.
	v, err, _ := h.sf.Do(host, func() (interface{}, error) {
		// Use a context that survives the leader's cancellation so
		// concurrent waiters with valid contexts get the cached result.
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		ips, lerr := h.resolver.LookupHost(resolveCtx, host)
		if lerr != nil || len(ips) == 0 {
			if lerr == nil {
				lerr = fmt.Errorf("no addresses for %s", host)
			}
			return nil, lerr // do NOT poison the cache on error
		}
		h.mu.Lock()
		h.m[host] = cachedIPs{ips: ips, exp: time.Now().Add(ttl)}
		h.mu.Unlock()
		return ips[0], nil
	})
	if err != nil {
		return "", err
	}
	// Check the ORIGINAL caller context: if this caller cancelled
	// while the leader was resolving, return the cancellation error
	// rather than the cached IP.
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return v.(string), nil
}
