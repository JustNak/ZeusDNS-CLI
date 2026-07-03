package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// dohClient is a DoH (RFC 8484) client. It relies on net/http's transport for
// connection pooling, TLS, and HTTP/2 negotiation.
type dohClient struct {
	url    string
	client *http.Client
}

func newDoHClient(u *Upstream, r *net.Resolver) (*dohClient, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// When a bootstrap resolver is set, resolve the upstream hostname through
	// it instead of the system resolver. Once ZeusDNS sets the system DNS to
	// 127.0.0.1, the system resolver IS ZeusDNS, so a normal lookup of the
	// DoH host loops back to us and every query times out.
	if r != nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return d.DialContext(ctx, network, addr)
			}
			if net.ParseIP(host) != nil { // literal IP — dial directly
				return d.DialContext(ctx, network, addr)
			}
			ips, err := r.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("bootstrap resolve %s: %w", host, err)
			}
			var lastErr error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
	}
	return &dohClient{
		url:    u.URL,
		client: &http.Client{Timeout: 10 * time.Second, Transport: transport},
	}, nil
}

func (c *dohClient) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return r, nil
}
