package dns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in      string
		proto   Protocol
		server  string
		wantErr bool
	}{
		{"https://dns.controld.com/p2", DoH, "dns.controld.com:443", false},
		{"https://doh.example:8443/dns-query", DoH, "doh.example:8443", false},
		{"tls://dns.adguard.com", DoT, "dns.adguard.com:853", false},
		{"dot://dns.google:853", DoT, "dns.google:853", false},
		{"tls://1.1.1.1:853", DoT, "1.1.1.1:853", false},
		{"8.8.8.8", "", "", true},                     // unsupported, must be DoH/DoT
		{"http://insecure.example/dns", "", "", true}, // not https
		{"", "", "", true},
	}
	for _, c := range cases {
		u, err := ParseUpstream(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseUpstream(%q) expected error, got %+v", c.in, u)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseUpstream(%q) unexpected error: %v", c.in, err)
			continue
		}
		if u.Proto != c.proto || u.Server != c.server {
			t.Errorf("ParseUpstream(%q) = proto=%s server=%s, want proto=%s server=%s", c.in, u.Proto, u.Server, c.proto, c.server)
		}
	}
}

func TestCacheGetPut(t *testing.T) {
	c := NewCache(4)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   netIP(),
	})

	if _, ok := c.Get(q); ok {
		t.Fatal("empty cache should miss")
	}
	c.Put(q, r)
	got, ok := c.Get(q)
	if !ok {
		t.Fatal("put entry should hit")
	}
	if got.Id != q.Id {
		t.Fatalf("cached Id = %d, want %d", got.Id, q.Id)
	}
}

func TestCacheDisabled(t *testing.T) {
	c := NewCache(0)
	q := new(dns.Msg)
	q.SetQuestion("x.example.", dns.TypeA)
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   netIP(),
	})
	c.Put(q, r)
	if _, ok := c.Get(q); ok {
		t.Fatal("disabled cache should never hit")
	}
}

func TestCacheEviction(t *testing.T) {
	c := NewCache(2)
	for i := 0; i < 3; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmtName(i), dns.TypeA)
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: fmtName(i), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   netIP(),
		})
		c.Put(q, r)
	}
	// First inserted should have been evicted.
	q0 := new(dns.Msg)
	q0.SetQuestion(fmtName(0), dns.TypeA)
	if _, ok := c.Get(q0); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	q2 := new(dns.Msg)
	q2.SetQuestion(fmtName(2), dns.TypeA)
	if _, ok := c.Get(q2); !ok {
		t.Fatal("newest entry should still be present")
	}
}
