package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dotClient is a DoT (RFC 7858) client that keeps one pooled TLS connection
// per upstream and reconnects on failure. A per-call deadline bounds the
// underlying read/write so a dead server cannot pin the goroutine.
type dotClient struct {
	host     string
	port     string
	tls      *tls.Config
	resolver *net.Resolver // bootstrap resolver (nil → system resolver)
	// A single pooled *dns.Conn per upstream is intentional; queries are
	// serialized via mu because miekg/dns's Conn is not safe for concurrent
	// interleaved WriteMsg/ReadMsg. A connection pool is the future path to
	// concurrency.
	mu   sync.Mutex
	conn *dns.Conn
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
	}, nil
}

// dial connects to the upstream. When a bootstrap resolver is set, the host
// is resolved through it (not the system DNS, which is 127.0.0.1 = us);
// otherwise miekg/dns falls back to the system resolver, used by the
// wizard/configure test path before ZeusDNS takes over the system DNS.
func (c *dotClient) dial(ctx context.Context) error {
	addr := c.host
	if net.ParseIP(c.host) == nil && c.resolver != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		ips, err := c.resolver.LookupHost(ctx, c.host)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("bootstrap resolve %s: %w", c.host, err)
		}
		addr = ips[0]
	}
	cl := &dns.Client{Net: "tcp-tls", TLSConfig: c.tls, Timeout: 10 * time.Second}
	conn, err := cl.Dial(net.JoinHostPort(addr, c.port))
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *dotClient) close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
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

// exchange sends msg over the pooled connection, reconnecting once on error.
func (c *dotClient) exchange(ctx context.Context, deadline time.Time, msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		if err := c.dial(ctx); err != nil {
			return nil, err
		}
	}
	_ = c.conn.SetDeadline(deadline)

	if err := c.conn.WriteMsg(msg); err != nil {
		c.close()
		deadline = c.reconnectDeadline(ctx, deadline)
		if err := c.dial(ctx); err != nil {
			return nil, err
		}
		_ = c.conn.SetDeadline(deadline)
		if err := c.conn.WriteMsg(msg); err != nil {
			c.close()
			return nil, err
		}
	}
	r, err := c.conn.ReadMsg()
	if err != nil {
		c.close()
		deadline = c.reconnectDeadline(ctx, deadline)
		if err := c.dial(ctx); err != nil {
			return nil, err
		}
		_ = c.conn.SetDeadline(deadline)
		if err := c.conn.WriteMsg(msg); err != nil {
			c.close()
			return nil, err
		}
		r, err = c.conn.ReadMsg()
		if err != nil {
			c.close()
			return nil, err
		}
	}
	return r, nil
}

func (c *dotClient) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(8 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	type result struct {
		r   *dns.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		r, err := c.exchange(ctx, deadline, msg)
		ch <- result{r, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-ch:
		if got.err != nil {
			return nil, fmt.Errorf("DoT %s: %w", net.JoinHostPort(c.host, c.port), got.err)
		}
		return got.r, nil
	}
}
