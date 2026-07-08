// Package dns implements the local DNS server and the DoH/DoT upstream clients.
//
// Upstreams are an ordered list: the first that answers wins, failures fail
// over to the next. Only DoH (https://) and DoT (tls://) are supported.
package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Protocol identifies an upstream transport.
type Protocol string

const (
	DoH Protocol = "DoH"
	DoT Protocol = "DoT"
)

// Upstream is a parsed, validated resolver endpoint.
type Upstream struct {
	Raw    string   // original user input
	Proto  Protocol // DoH or DoT
	Server string   // host:port to dial
	Host   string   // hostname for TLS SNI / HTTP Host
	URL    string   // full DoH URL (DoH only)
}

// ParseUpstream turns a user string into an Upstream.
// Accepted forms: https://host/path (DoH), tls://host[:853] or dot://host[:853] (DoT).
func ParseUpstream(raw string) (*Upstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty resolver")
	}
	low := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(low, "https://"):
		return parseDoH(raw)
	case strings.HasPrefix(low, "tls://"), strings.HasPrefix(low, "dot://"):
		return parseDoT(raw)
	default:
		return nil, fmt.Errorf("unsupported resolver %q: use https:// (DoH) or tls:// (DoT)", raw)
	}
}

func parseDoH(raw string) (*Upstream, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bad DoH url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("DoH resolver must use https://")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("DoH resolver missing host")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return &Upstream{
		Raw:    raw,
		Proto:  DoH,
		Server: net.JoinHostPort(host, port),
		Host:   host,
		URL:    raw,
	}, nil
}

func parseDoT(raw string) (*Upstream, error) {
	var rest string
	switch {
	case strings.HasPrefix(strings.ToLower(raw), "tls://"):
		rest = raw[len("tls://"):]
	default:
		rest = raw[len("dot://"):]
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil {
		host = rest
		port = "853"
	}
	if host == "" {
		return nil, fmt.Errorf("bad DoT address")
	}
	return &Upstream{
		Raw:    raw,
		Proto:  DoT,
		Server: net.JoinHostPort(host, port),
		Host:   host,
	}, nil
}

// Exchanger sends a DNS message and returns the response.
type Exchanger interface {
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

// Exchanger returns a client for this upstream's protocol. The resolver (if
// non-nil) resolves the upstream hostname, bypassing the system DNS — once
// ZeusDNS sets the system DNS to 127.0.0.1, resolving the upstream host via
// the system resolver would loop back to ZeusDNS itself and time out. Pass
// nil for the wizard/configure test path (system DNS not yet taken over).
func (u *Upstream) Exchanger(r *net.Resolver) (Exchanger, error) {
	switch u.Proto {
	case DoH:
		return newDoHClient(u, r)
	case DoT:
		return newDoTClient(u, r)
	default:
		return nil, fmt.Errorf("unknown protocol %q", u.Proto)
	}
}

// NewBootstrapResolver returns a *net.Resolver that resolves hostnames by
// sending plain DNS directly to the given bootstrap server IPs (port 53),
// bypassing the system resolver entirely. This breaks the loop where the
// system DNS (127.0.0.1 = ZeusDNS) would be asked to resolve the DoH/DoT
// upstream host. If bootstrap is empty, nil is returned and the caller uses
// the normal system resolver.
func NewBootstrapResolver(bootstrap []string) *net.Resolver {
	if len(bootstrap) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var lastErr error
			for _, ip := range bootstrap {
				c, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "53"))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// Validate checks that the upstream address is not a loopback, link-local,
// multicast, or unspecified address, and that it does not equal the local
// listener address (self-referential loop). Hostnames are not IP-checked
// (they resolve at runtime via the bootstrap resolver) but are still checked
// for self-reference.
func (u *Upstream) Validate(listenerAddr string) error {
	host, _, err := net.SplitHostPort(u.Server)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip != nil {
		switch {
		case ip.IsLoopback():
			return fmt.Errorf("loopback address %q not allowed", host)
		case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
			return fmt.Errorf("link-local address %q not allowed", host)
		case ip.IsMulticast():
			return fmt.Errorf("multicast address %q not allowed", host)
		case ip.IsUnspecified():
			return fmt.Errorf("unspecified address %q not allowed", host)
		}
	}
	if u.Server == listenerAddr {
		return fmt.Errorf("self-referential address (listener %q) not allowed", listenerAddr)
	}
	return nil
}

// Display is a short human label for menus and logs.
func (u *Upstream) Display() string { return fmt.Sprintf("%s   (%s)", u.Raw, u.Proto) }

// Check sends a test A query for example.com. and returns nil if the upstream
// answers with NOERROR. Used by the wizard and the `configure` test action.
func (u *Upstream) Check(ctx context.Context) error {
	ex, err := u.Exchanger(nil)
	if err != nil {
		return err
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.RecursionDesired = true
	r, err := ex.Exchange(ctx, q)
	if err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("no response")
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("resolver returned %s", dns.RcodeToString[r.Rcode])
	}
	return nil
}

// CheckTimeout is the per-resolver deadline used during health checks.
const CheckTimeout = 6 * time.Second
