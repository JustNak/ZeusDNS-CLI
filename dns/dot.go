package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// dotPoolSize caps how many warm TLS connections are kept per upstream, and
// also bounds concurrent in-flight exchanges. A small bounded pool avoids
// stampeding the upstream during a thundering-herd spike while still allowing
// dotPoolSize concurrent queries (vs the previous single-conn serialization).
const dotPoolSize = 8

const dotPerQueryTimeout = 5 * time.Second

// dotClient is a DoT (RFC 7858) client that maintains a small pool of warm
// TLS connections per upstream. Each Exchange acquires a connection from the
// pool (or dials a fresh one), performs a synchronous write+read, then returns
// the healthy connection to the pool (or closes it on error). A concurrency
// semaphore bounds simultaneous in-flight exchanges so a spike cannot exhaust
// file descriptors.
type dotClient struct {
	host string
	port string
	tls  *tls.Config
	hc   *hostnameCache // upstream IP cache (nil-in → DefaultResolver-backed)
	pool chan *dns.Conn
	sem  chan struct{}
}

func newDoTClient(u *Upstream, r *net.Resolver) (*dotClient, error) {
	host, port, err := net.SplitHostPort(u.Server)
	if err != nil {
		return nil, fmt.Errorf("bad DoT server %q: %w", u.Server, err)
	}
	return &dotClient{
		host: host,
		port: port,
		tls:  &tls.Config{ServerName: u.Host, MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(32)},
		hc:   newHostnameCache(r),
		pool: make(chan *dns.Conn, dotPoolSize),
		sem:  make(chan struct{}, dotPoolSize),
	}, nil
}

// dial connects to the upstream and returns the new *dns.Conn. The upstream
// hostname is resolved through the bootstrap resolver (hc) — never the system
// DNS, which after takeover is 127.0.0.1 = us and would loop. hc is always
// non-nil: when constructed with a nil resolver it wraps net.DefaultResolver
// (system resolver), used by the wizard/configure test path before takeover;
// post-takeover it wraps the bootstrap resolver that dials the saved DNS IPs directly.
func (c *dotClient) dial(ctx context.Context) (*dns.Conn, error) {
	addr := c.host
	if net.ParseIP(c.host) == nil && c.hc != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ip, err := c.hc.lookup(ctx, c.host, DefaultHostnameTTL)
		if err != nil {
			return nil, fmt.Errorf("bootstrap resolve %s: %w", c.host, err)
		}
		addr = ip
	}
	cl := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: c.tls,
		Timeout:   10 * time.Second,
		Dialer:    &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second},
	}
	return cl.Dial(net.JoinHostPort(addr, c.port))
}

// getConn returns a reusable connection from the pool, or dials a fresh one
// when the pool is empty.
func (c *dotClient) getConn(ctx context.Context) (*dns.Conn, error) {
	select {
	case conn := <-c.pool:
		return conn, nil
	default:
		return c.dial(ctx)
	}
}

// putConn returns a healthy connection to the pool for reuse. If the pool is
// full the connection is closed instead.
func (c *dotClient) putConn(conn *dns.Conn) {
	select {
	case c.pool <- conn:
	default:
		_ = conn.Close()
	}
}

// WarmPool best-effort pre-fills the connection pool up to dotPoolSize.
// Used by startup PreWarm so a burst right after start doesn't cold-dial
// dotPoolSize-1 TLS handshakes. Errors are non-fatal.
func (c *dotClient) WarmPool(ctx context.Context) error {
	for i := 0; i < cap(c.pool); i++ {
		if ctx.Err() != nil {
			return nil
		}
		conn, err := c.dial(ctx)
		if err != nil {
			continue
		}
		c.putConn(conn)
	}
	return nil
}

// exchangeOnConn performs a single write+read cycle on an owned connection.
// The caller must Close the conn on error and putConn on success.
func (c *dotClient) exchangeOnConn(deadline time.Time, conn *dns.Conn, msg *dns.Msg) (*dns.Msg, error) {
	_ = conn.SetDeadline(deadline)
	if err := conn.WriteMsg(msg); err != nil {
		return nil, err
	}
	return conn.ReadMsg()
}

// Exchange sends msg to the upstream and returns the response. It is safe for
// concurrent use: up to dotPoolSize goroutines may call Exchange
// simultaneously. A ctx-cancellable semaphore bounds concurrency; each
// call acquires its own connection from the pool (or dials fresh), performs a
// synchronous I/O cycle, and returns the healthy connection to the pool. On
// I/O error the connection is closed and one automatic retry is made with a
// fresh conn (both attempts share the single per-query deadline computed
// above, so a retry cannot extend the timeout window).
func (c *dotClient) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(dotPerQueryTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	// Acquire concurrency slot, ctx-cancellable.
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		conn, derr := c.getConn(ctx)
		if derr != nil {
			lastErr = derr
			continue
		}
		resp, err := c.exchangeOnConn(deadline, conn, msg)
		if err == nil {
			c.putConn(conn)
			return resp, nil
		}
		_ = conn.Close()
		lastErr = err
	}
	return nil, fmt.Errorf("DoT %s: %w", net.JoinHostPort(c.host, c.port), lastErr)
}
