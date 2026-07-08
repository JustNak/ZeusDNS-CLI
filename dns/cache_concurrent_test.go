package dns

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestCacheConcurrentStress hammers Get/Put from many goroutines on overlapping
// keys. With the old RLock+MoveToFront bug this corrupts the LRU list and
// panics (nil deref / loop) under concurrency. A clean run here corroborates
// the write-lock fix; the -race detector is the gold standard but requires a
// C compiler (not available in this build env), so this stress + code
// inspection (Get holds Lock across MoveToFront) is the verification here.
func TestCacheConcurrentStress(t *testing.T) {
	const workers = 16
	const ops = 2000
	c := NewCache(64)

	// Seed shared keys so reads hit the hot Get path (the old race site).
	mk := func(i int) (*dns.Msg, *dns.Msg) {
		q := new(dns.Msg)
		q.SetQuestion(mustName(i), dns.TypeA)
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: mustName(i), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   netIP(),
		})
		return q, r
	}
	// Pre-populate.
	for i := 0; i < 32; i++ {
		q, r := mk(i)
		c.Put(q, r)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < ops; i++ {
				key := (w + i) % 32
				q, r := mk(key)
				if i&1 == 0 {
					c.Put(q, r)
				}
				if got, ok := c.Get(q); ok {
					if got.Id != q.Id {
						t.Errorf("id mismatch: got %d want %d", got.Id, q.Id)
						return
					}
				}
			}
		}(w)
	}
	close(start)
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent stress timed out — likely list corruption / deadlock")
	}
}

func mustName(i int) string {
	switch i {
	case 0:
		return "a.example."
	case 1:
		return "b.example."
	default:
		b := []byte("x.example.")
		b[0] = 'a' + byte(i%26)
		return string(b)
	}
}
