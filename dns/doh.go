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
	hc     *hostnameCache
}

func newDoHClient(u *Upstream, r *net.Resolver) (*dohClient, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 16
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second
	// DoH dials each upstream's resolved IP directly via the bootstrap resolver.
	// HTTP proxy support is intentionally disabled: an HTTP_PROXY hostname would
	// be resolved through the (system-bypassing) bootstrap resolver and likely
	// fail, and DNS traffic should not be tunneled through an HTTP proxy.
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = true
	// When a bootstrap resolver is set, resolve the upstream hostname through
	// it instead of the system resolver. Once ZeusDNS sets the system DNS to
	// 127.0.0.1, the system resolver IS ZeusDNS, so a normal lookup of the
	// DoH host loops back to us and every query times out.
	var hc *hostnameCache
	if r != nil {
		hc = newHostnameCache(r)
		d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return d.DialContext(ctx, network, addr)
			}
			if net.ParseIP(host) != nil { // literal IP — dial directly
				return d.DialContext(ctx, network, addr)
			}
			ip, err := hc.lookup(ctx, host, DefaultHostnameTTL)
			if err != nil {
				return nil, fmt.Errorf("bootstrap resolve %s: %w", host, err)
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		}
	}
	return &dohClient{
		url:    u.URL,
		client: &http.Client{Timeout: 6 * time.Second, Transport: transport},
		hc:     hc,
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
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		return nil, fmt.Errorf("DoH unexpected Content-Type: %q", ct)
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
