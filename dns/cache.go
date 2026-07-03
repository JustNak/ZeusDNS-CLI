package dns

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache is a bounded LRU with per-entry TTLs. A zero-size cache is a no-op.
type Cache struct {
	size int
	mu   sync.Mutex
	m    map[string]*list.Element
	ll   *list.List
}

type cacheEntry struct {
	key    string
	msg    *dns.Msg
	expiry time.Time
}

// NewCache returns a cache holding up to size entries. size <= 0 disables it.
func NewCache(size int) *Cache {
	if size <= 0 {
		return &Cache{}
	}
	return &Cache{size: size, m: make(map[string]*list.Element), ll: list.New()}
}

func cacheKey(q *dns.Msg) (string, bool) {
	if len(q.Question) == 0 {
		return "", false
	}
	qu := q.Question[0]
	return fmt.Sprintf("%d:%s", qu.Qtype, dns.CanonicalName(qu.Name)), true
}

// minTTL returns the smallest TTL among all resource records, or 0 if none.
func minTTL(r *dns.Msg) uint32 {
	var min uint32
	first := true
	for _, rr := range append(append(r.Answer, r.Ns...), r.Extra...) {
		hdr := rr.Header()
		if first || hdr.Ttl < min {
			min = hdr.Ttl
			first = false
		}
	}
	return min
}

// Get returns a cached response for the query if present and unexpired.
// The returned message has its Id set to match the query.
func (c *Cache) Get(q *dns.Msg) (*dns.Msg, bool) {
	if c.size <= 0 {
		return nil, false
	}
	key, ok := cacheKey(q)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if time.Now().After(e.expiry) {
		c.ll.Remove(el)
		delete(c.m, key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	out := e.msg.Copy()
	out.Id = q.Id
	return out, true
}

// Put stores a response, keyed by its first question, for the minimum record
// TTL (clamped to 30s..1h). Responses with no TTL information are not cached.
func (c *Cache) Put(q, r *dns.Msg) {
	if c.size <= 0 || r == nil || r.Rcode != dns.RcodeSuccess {
		return
	}
	key, ok := cacheKey(q)
	if !ok {
		return
	}
	ttl := minTTL(r)
	if ttl == 0 {
		return
	}
	if ttl < 30 {
		ttl = 30
	}
	if ttl > 3600 {
		ttl = 3600
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		el.Value.(*cacheEntry).msg = r.Copy()
		el.Value.(*cacheEntry).expiry = time.Now().Add(time.Duration(ttl) * time.Second)
		c.ll.MoveToFront(el)
		return
	}
	e := &cacheEntry{key: key, msg: r.Copy(), expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
	c.m[key] = c.ll.PushFront(e)
	if c.ll.Len() > c.size {
		back := c.ll.Back()
		if back != nil {
			c.ll.Remove(back)
			delete(c.m, back.Value.(*cacheEntry).key)
		}
	}
}
