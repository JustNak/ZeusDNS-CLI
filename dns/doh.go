package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

func newDoHClient(u *Upstream) (*dohClient, error) {
	return &dohClient{
		url: u.URL,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
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
