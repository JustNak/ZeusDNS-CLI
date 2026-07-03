package dns

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miekg/dns"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
)

// perQueryTimeout caps how long a single upstream may take before failover.
const perQueryTimeout = 5 * time.Second

// Server is the local DNS listener that forwards to the ordered upstream list.
type Server struct {
	cfg        *config.Config
	log        *internal.Logger
	upstreams  []*Upstream
	exchangers []Exchanger
	cache      *Cache
	queryLog   bool

	udp *dns.Server
	tcp *dns.Server
}

// NewServer parses the configured upstreams and prepares the local server.
func NewServer(cfg *config.Config, log *internal.Logger) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		log:       log,
		cache:     NewCache(cfg.Cache.Size),
		queryLog:  cfg.Log.Level == "verbose" || cfg.Log.Level == "debug",
		upstreams: make([]*Upstream, 0, len(cfg.Upstreams)),
	}
	for _, raw := range cfg.Upstreams {
		u, err := ParseUpstream(raw)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", raw, err)
		}
		ex, err := u.Exchanger()
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", raw, err)
		}
		s.upstreams = append(s.upstreams, u)
		s.exchangers = append(s.exchangers, ex)
	}
	if len(s.exchangers) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}
	return s, nil
}

// Start binds UDP and TCP listeners and blocks until ctx is done or a fatal
// error occurs. It returns nil on a clean shutdown.
func (s *Server) Start(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	addr := s.cfg.Addr()
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: mux, UDPSize: 4096}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: mux}

	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	s.log.Info("dns server listening", "addr", addr, "upstreams", len(s.upstreams))
	for i, u := range s.upstreams {
		s.log.Info("upstream", "index", i+1, "resolver", u.Raw, "proto", u.Proto)
	}

	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		_ = s.Stop()
		return err
	}
}

// Stop shuts both listeners without canceling in-flight replies.
func (s *Server) Stop() error {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
	s.log.Info("dns server stopped")
	return nil
}

// ServeDNS handles one query: cache lookup, then ordered upstream failover.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) > 0 {
		if s.queryLog {
			q := r.Question[0]
			s.log.Info("query", "name", q.Name, "type", dns.TypeToString[q.Qtype], "from", w.RemoteAddr())
		}
	}

	if cached, ok := s.cache.Get(r); ok {
		_ = w.WriteMsg(cached)
		return
	}

	r.RecursionDesired = true
	for i, ex := range s.exchangers {
		ctx, cancel := context.WithTimeout(context.Background(), perQueryTimeout)
		resp, err := ex.Exchange(ctx, r)
		cancel()
		if err != nil {
			s.log.Warn("upstream failed", "resolver", s.upstreams[i].Raw, "err", err)
			continue
		}
		if resp == nil {
			s.log.Warn("upstream empty response", "resolver", s.upstreams[i].Raw)
			continue
		}
		s.cache.Put(r, resp)
		if s.queryLog {
			s.log.Info("answered", "resolver", s.upstreams[i].Raw, "rcode", dns.RcodeToString[resp.Rcode], slog.Duration("level", 0))
		}
		_ = w.WriteMsg(resp)
		return
	}

	// All upstreams failed: return SERVFAIL.
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}
