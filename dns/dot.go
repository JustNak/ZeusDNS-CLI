package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dotClient is a DoT (RFC 7858) client that keeps one pooled TLS connection
// per upstream and reconnects on failure. A per-call deadline bounds the
// underlying read/write so a dead server cannot pin the goroutine.
type dotClient struct {
	server string
	tls    *tls.Config
	mu     sync.Mutex
	conn   *dns.Conn
}

func newDoTClient(u *Upstream) (*dotClient, error) {
	return &dotClient{
		server: u.Server,
		tls:    &tls.Config{ServerName: u.Host, MinVersion: tls.VersionTLS12},
	}, nil
}

func (c *dotClient) dial() error {
	cl := &dns.Client{Net: "tcp-tls", TLSConfig: c.tls, Timeout: 10 * time.Second}
	conn, err := cl.Dial(c.server)
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

// exchange sends msg over the pooled connection, reconnecting once on error.
func (c *dotClient) exchange(deadline time.Time, msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		if err := c.dial(); err != nil {
			return nil, err
		}
	}
	_ = c.conn.SetDeadline(deadline)

	if err := c.conn.WriteMsg(msg); err != nil {
		c.close()
		if err := c.dial(); err != nil {
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
		if err := c.dial(); err != nil {
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
		r, err := c.exchange(deadline, msg)
		ch <- result{r, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-ch:
		if got.err != nil {
			return nil, fmt.Errorf("DoT %s: %w", c.server, got.err)
		}
		return got.r, nil
	}
}
