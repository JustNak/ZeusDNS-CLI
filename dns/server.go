package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
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
// resolver (if non-nil) is used to resolve upstream hostnames, bypassing the
// system DNS once ZeusDNS takes it over; pass nil for pre-service test paths.
func NewServer(cfg *config.Config, log *internal.Logger, resolver *net.Resolver) (*Server, error) {
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
		ex, err := u.Exchanger(resolver)
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

// Listen binds UDP and TCP ports and prepares the dns.Server objects without
// starting serving. Call Serve() to begin handling queries.
func (s *Server) Listen() error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	addr := s.cfg.Addr()

	// Bind UDP port.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp bind: %w", err)
	}

	// Bind TCP port. If it fails, close the UDP listener first.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("tcp bind: %w", err)
	}

	s.udp = &dns.Server{
		PacketConn: pc,
		Net:        "udp",
		Handler:    mux,
		UDPSize:    4096,
	}
	s.tcp = &dns.Server{
		Listener: listener,
		Net:      "tcp",
		Handler:  mux,
	}

	s.log.Info("dns server listening", "addr", addr, "upstreams", len(s.upstreams))
	for i, u := range s.upstreams {
		s.log.Info("upstream", "index", i+1, "resolver", u.Raw, "proto", u.Proto)
	}
	return nil
}

// Serve blocks until ctx is done or a fatal error occurs. It returns nil on
// a clean shutdown. Listen() must be called before Serve().
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ActivateAndServe() }()
	go func() { errCh <- s.tcp.ActivateAndServe() }()

	select {
	case <-ctx.Done():
		return s.Stop()
	case err := <-errCh:
		_ = s.Stop()
		return err
	}
}

// PreWarm sends one warm-up A query to each upstream in parallel, warming TLS
// sessions and DNS caches while the system DNS is still live (before it is
// flipped to 127.0.0.1). Non-fatal: errors are logged but not propagated.
func (s *Server) PreWarm(ctx context.Context) {
	prewarmCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := range s.exchangers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			q.RecursionDesired = true

			resp, err := s.exchangers[i].Exchange(prewarmCtx, q)
			if err != nil {
				s.log.Warn("prewarm failed", "resolver", s.upstreams[i].Raw, "err", err)
				return
			}
			if resp == nil {
				s.log.Warn("prewarm failed", "resolver", s.upstreams[i].Raw, "err", "nil response")
				return
			}
			s.log.Info("prewarm ok", "resolver", s.upstreams[i].Raw)
		}(i)
	}
	wg.Wait()
}

// Start is a thin back-compat wrapper around Listen+Serve. Prefer calling
// Listen()+PreWarm()+Serve() directly for fine-grained startup control.
func (s *Server) Start(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
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
	start := time.Now()
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
			s.log.Info("answered", "resolver", s.upstreams[i].Raw, "rcode", dns.RcodeToString[resp.Rcode], slog.Duration("duration", time.Since(start)))
		}
		_ = w.WriteMsg(resp)
		return
	}

	// All upstreams failed: return SERVFAIL.
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}
