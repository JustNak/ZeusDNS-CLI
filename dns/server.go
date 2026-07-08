package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/JustNak/ZeusDNS-CLI/config"
	"github.com/JustNak/ZeusDNS-CLI/internal"
)

// perQueryTimeout caps how long a single upstream may take before failover.
const perQueryTimeout = 5 * time.Second

// maxAcceptedMsgSize caps the incoming DNS message wire length. Queries larger
// than this are rejected with a FormatError before any processing.
const maxAcceptedMsgSize = 4096

// ipRateLimiter implements a per-IP sliding-window rate limiter used to
// mitigate abuse when the server is exposed to non-loopback interfaces.
type ipRateLimiter struct {
	sync.Mutex
	ips    map[string]*ipCounter
	limit  int
	window time.Duration
	lastGC time.Time
}

type ipCounter struct {
	n    int
	seen time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		ips:    make(map[string]*ipCounter),
		limit:  limit,
		window: window,
		lastGC: time.Now(),
	}
}

// Allow reports whether ip may make another request under the rate limit.
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.Lock()
	defer rl.Unlock()
	now := time.Now()
	if len(rl.ips) > 10000 && now.Sub(rl.lastGC) > 30*time.Second {
		for k, v := range rl.ips {
			if now.Sub(v.seen) > rl.window {
				delete(rl.ips, k)
			}
		}
		rl.lastGC = now
	}
	c, ok := rl.ips[ip]
	if !ok || now.Sub(c.seen) > rl.window {
		rl.ips[ip] = &ipCounter{n: 1, seen: now}
		return true
	}
	c.n++
	return c.n <= rl.limit
}

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

	serveCtx    context.Context
	serveCancel context.CancelFunc

	sf singleflight.Group

	lifeMu   sync.Mutex
	stopOnce sync.Once
	rateL    *ipRateLimiter
}

// NewServer parses the configured upstreams and prepares the local server.
// resolver (if non-nil) is used to resolve upstream hostnames, bypassing the
// system DNS once ZeusDNS takes it over; pass nil for pre-service test paths.
func NewServer(cfg *config.Config, log *internal.Logger, resolver *net.Resolver) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		log:       log,
		cache:     NewCache(cfg.Cache.Size),
		rateL:     newIPRateLimiter(100, 1*time.Second),
		queryLog:  cfg.Log.Level == "verbose" || cfg.Log.Level == "debug",
		upstreams: make([]*Upstream, 0, len(cfg.Upstreams)),
	}
	for _, raw := range cfg.Upstreams {
		u, err := ParseUpstream(raw)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", raw, err)
		}
		if err := u.Validate(cfg.Addr()); err != nil {
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
	s.lifeMu.Lock()
	s.serveCtx, s.serveCancel = context.WithCancel(ctx)
	s.lifeMu.Unlock()
	defer s.serveCancel()

	// Warn if the resolver is bound to a non-loopback address.
	s.checkExposed()

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
			ex := s.exchangers[i]

			// If the exchanger implements WarmPool, use that instead of a
			// single query warm (e.g. DoT connection pool pre-warming).
			if warmer, ok := ex.(interface{ WarmPool(context.Context) error }); ok {
				if err := warmer.WarmPool(prewarmCtx); err != nil {
					s.log.Warn("prewarm warm pool failed", "resolver", s.upstreams[i].Raw, "err", err)
				} else {
					s.log.Info("prewarm ok", "resolver", s.upstreams[i].Raw)
				}
				return
			}

			// Fallback: single-query warm.
			q := new(dns.Msg)
			q.SetQuestion("example.com.", dns.TypeA)
			q.RecursionDesired = true

			resp, err := ex.Exchange(prewarmCtx, q)
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

// Stop shuts both listeners without canceling in-flight replies. It is
// idempotent (safe to call repeatedly and concurrently) and also drains
// DoT connection pools before closing the listeners.
func (s *Server) Stop() error {
	s.stopOnce.Do(func() {
		// Drain DoT pools first, so that in-flight TLS exchanges on pool
		// connections have a chance to finish before the listeners close.
		for _, ex := range s.exchangers {
			if dot, ok := ex.(*dotClient); ok {
				_ = dot.Close()
			}
		}
		s.lifeMu.Lock()
		if s.serveCancel != nil {
			s.serveCancel()
		}
		if s.udp != nil {
			_ = s.udp.Shutdown()
		}
		if s.tcp != nil {
			_ = s.tcp.Shutdown()
		}
		s.lifeMu.Unlock()
		s.log.Info("dns server stopped")
	})
	return nil
}

// ServeDNS handles one query: cache lookup, then coalesced upstream racing.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()

	// Reject oversized messages before any processing (amplification defence).
	if r.Len() > maxAcceptedMsgSize {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	// Per-source rate limiting.
	if s.rateL != nil {
		if addr := w.RemoteAddr(); addr != nil {
			host, _, err := net.SplitHostPort(addr.String())
			if err == nil && host != "" && !s.rateL.Allow(host) {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				if s.queryLog {
					s.log.Warn("rate limited", "from", host)
				}
				return
			}
		}
	}

	if len(r.Question) > 0 {
		if s.queryLog {
			q := r.Question[0]
			s.log.Info("query", "name", q.Name, "type", dns.TypeToString[q.Qtype], "from", w.RemoteAddr())
		}
	}

	// Reject queries with no question section — they bypass singleflight
	// dedup and risk amplification.
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	if cached, ok := s.cache.Get(r); ok {
		applyEDNSTruncation(r, cached)
		_ = w.WriteMsg(cached)
		if s.queryLog {
			s.log.Info("served", slog.Duration("dur", time.Since(start)), "cached", true)
		}
		return
	}

	r.RecursionDesired = true

	// cacheKey is guaranteed ok after the empty-question check above.
	key, _ := cacheKey(r)

	v, err, _ := s.sf.Do(key, func() (interface{}, error) {
		return s.resolveRace(r)
	})
	if err != nil || v == nil {
		// All upstreams failed: return SERVFAIL.
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	resp := v.(*dns.Msg)
	// Id-safety: copy before writing (coalesced callers share resp).
	out := resp.Copy()
	out.Id = r.Id
	applyEDNSTruncation(r, out)
	_ = w.WriteMsg(out)
	if s.queryLog {
		s.log.Info("served", slog.Duration("dur", time.Since(start)), "cached", false)
	}
}

// resolveRace sends r to all upstreams concurrently and returns the first
// successful (non-SERVFAIL) response, canceling the losers.
func (s *Server) resolveRace(r *dns.Msg) (*dns.Msg, error) {
	type raceResult struct {
		resp *dns.Msg
		err  error
		idx  int
	}

	rctx := s.serveCtx
	if rctx == nil {
		rctx = context.Background()
	}
	rctx, rcancel := context.WithCancel(rctx)
	defer rcancel()

	ch := make(chan raceResult, len(s.exchangers))
	for i, ex := range s.exchangers {
		i, ex := i, ex
		go func() {
			ctx, cancel := context.WithTimeout(rctx, perQueryTimeout)
			defer cancel()
			resp, err := ex.Exchange(ctx, r)
			ch <- raceResult{resp: resp, err: err, idx: i}
		}()
	}

	start := time.Now()
	var firstErr error
	for i := 0; i < len(s.exchangers); i++ {
		res := <-ch
		if res.err != nil {
			s.log.Warn("upstream failed", "resolver", s.upstreams[res.idx].Raw, "err", res.err)
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		if res.resp == nil {
			s.log.Warn("upstream empty response", "resolver", s.upstreams[res.idx].Raw)
			continue
		}
		if res.resp.Rcode == dns.RcodeServerFailure {
			s.log.Warn("upstream server failure", "resolver", s.upstreams[res.idx].Raw, "rcode", dns.RcodeToString[res.resp.Rcode])
			continue
		}
		// First real success — cancel everyone else.
		rcancel()
		s.cache.Put(r, res.resp)
		if s.queryLog {
			s.log.Info("answered", "resolver", s.upstreams[res.idx].Raw, "rcode", dns.RcodeToString[res.resp.Rcode], slog.Duration("duration", time.Since(start)))
		}
		return res.resp, nil
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("all upstreams returned empty or SERVFAIL responses")
}

// checkExposed logs a prominent warning when the listener is bound to a
// non-loopback address, indicating this instance is reachable as an open
// resolver from other hosts.
func (s *Server) checkExposed() {
	ip := net.ParseIP(s.cfg.Listener.IP)
	if ip != nil && !ip.IsLoopback() {
		s.log.Warn("═══════════════════════════════════════════════════════")
		s.log.Warn("RESOLVER EXPOSED — listener bound to non-loopback address", "addr", s.cfg.Addr())
		s.log.Warn("This instance is reachable from other hosts on the network.")
		s.log.Warn("Ensure this is intentional — you are running an open resolver.")
		s.log.Warn("═══════════════════════════════════════════════════════")
	}
}

// applyEDNSTruncation checks the client's EDNS0 UDP payload size (or the 512
// byte default when no OPT record is present) and sets the TC (truncation) bit
// if the response exceeds it. This signals the client to retry over TCP for
// the full response. The Extra section is cleared to reduce wire size.
func applyEDNSTruncation(query, resp *dns.Msg) {
	udpSize := 512 // RFC 1035 default
	if opt := query.IsEdns0(); opt != nil {
		if s := int(opt.UDPSize()); s > udpSize {
			udpSize = s
		}
	}
	if resp.Len() > udpSize {
		resp.Truncated = true
		resp.Extra = nil
	}
}
