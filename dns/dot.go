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
const dotPoolSize = 4

// dotClient is a DoT (RFC 7858) client that maintains a small pool of warm
// TLS connections per upstream. Each Exchange acquires a connection from the
// pool (or dials a fresh one), performs a synchronous write+read, then returns
// the healthy connection to the pool (or closes it on error). A concurrency
// semaphore bounds simultaneous in-flight exchanges so a spike cannot exhaust
// file descriptors.
type dotClient struct {
	host     string
	port     string
	tls      *tls.Config
	resolver *net.Resolver // bootstrap resolver (nil → system resolver)
	pool     chan *dns.Conn
	sem      chan struct{}
}

func newDoTClient(u *Upstream, r *net.Resolver) (*dotClient, error) {
	host, port, err := net.SplitHostPort(u.Server)
	if err != nil {
		return nil, fmt.Errorf("bad DoT server %q: %w", u.Server, err)
	}
	return &dotClient{
		host:     host,
		port:     port,
		tls:      &tls.Config{ServerName: u.Host, MinVersion: tls.VersionTLS12},
		resolver: r,
		pool:     make(chan *dns.Conn, dotPoolSize),
		sem:      make(chan struct{}, dotPoolSize),
	}, nil
}

// dial connects to the upstream and returns the new *dns.Conn. When a
// bootstrap resolver is set, the host is resolved through it (not the system
// DNS, which is 127.0.0.1 = us); otherwise miekg/dns falls back to the system
// resolver, used by the wizard/configure test path before ZeusDNS takes over
// the system DNS.
func (c *dotClient) dial(ctx context.Context) (*dns.Conn, error) {
	addr := c.host
	if net.ParseIP(c.host) == nil && c.resolver != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ips, err := c.resolver.LookupHost(ctx, c.host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("bootstrap resolve %s: %w", c.host, err)
		}
		addr = ips[0]
	}
	cl := &dns.Client{Net: "tcp-tls", TLSConfig: c.tls, Timeout: 10 * time.Second}
	return cl.Dial(net.JoinHostPort(addr, c.port))
}

// reconnectDeadline computes a fresh deadline for a reconnection attempt.
// The original deadline may be nearly spent after a failed I/O, so cap it
// at now+8s while never exceeding the context's overall deadline.
func (c *dotClient) reconnectDeadline(ctx context.Context, orig time.Time) time.Time {
	deadline := orig
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	if newDL := time.Now().Add(8 * time.Second); newDL.Before(deadline) {
		deadline = newDL
	}
	return deadline
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
// fresh conn and deadline.
func (c *dotClient) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(8 * time.Second)
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
		if attempt == 1 {
			deadline = c.reconnectDeadline(ctx, deadline)
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
