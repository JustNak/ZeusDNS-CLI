//go:build windows
// +build windows

package windows

import (
	"fmt"
	"net/netip"

	win "golang.org/x/sys/windows"
	"inet.af/wf"
)

// LoopbackProtector installs WFP permit filters for loopback DNS
// (127.0.0.1:53 and [::1]:53, UDP+TCP, inbound and outbound) so that a VPN's
// "block outside DNS" rule does not kill the local resolver.
//
// It uses a dynamic WFP session: closing the session (or the process exiting)
// removes every filter it created, so cleanup is automatic on service stop.
type LoopbackProtector struct {
	session *wf.Session
	enabled bool
}

// NewLoopbackProtector returns an unenabled protector.
func NewLoopbackProtector() *LoopbackProtector { return &LoopbackProtector{} }

// Enable opens a dynamic WFP session and installs the loopback-DNS permit
// filters. Requires elevation.
func (p *LoopbackProtector) Enable() error {
	s, err := wf.New(&wf.Options{
		Name:        "ZeusDNS",
		Description: "Permit loopback DNS past VPN block-outside-DNS rules",
		Dynamic:     true,
	})
	if err != nil {
		return fmt.Errorf("open WFP session: %w", err)
	}
	guid, err := win.GenerateGUID()
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("generate sublayer guid: %w", err)
	}
	subID := wf.SublayerID(guid)
	if err := s.AddSublayer(&wf.Sublayer{
		ID:     subID,
		Name:   "ZeusDNS loopback DNS protect",
		Weight: 0xffff, // top of the sublayer cake, above Windows Defender (0x1000)
	}); err != nil {
		_ = s.Close()
		return fmt.Errorf("add sublayer: %w", err)
	}

	rules, err := buildLoopbackRules(subID)
	if err != nil {
		_ = s.Close()
		return err
	}
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			_ = s.Close()
			return fmt.Errorf("add WFP rule %q: %w", r.Name, err)
		}
	}
	p.session = s
	p.enabled = true
	return nil
}

// Disable closes the dynamic session, which removes all installed filters.
func (p *LoopbackProtector) Disable() error {
	if p.session == nil {
		return nil
	}
	err := p.session.Close()
	p.session = nil
	p.enabled = false
	return err
}

// Enabled reports whether the WFP filters are currently installed.
func (p *LoopbackProtector) Enabled() bool { return p.enabled }

// buildLoopbackRules creates the 8 permit filters:
//
//	outbound (ALE_AUTH_CONNECT):    remote addr = loopback, remote port = 53
//	inbound  (ALE_AUTH_RECV_ACCEPT): local addr = loopback, local port = 53
//
// for IPv4 (127.0.0.1) and IPv6 (::1), UDP and TCP.
func buildLoopbackRules(sub wf.SublayerID) ([]*wf.Rule, error) {
	v4 := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("::1")

	type proto struct {
		name string
		val  uint8
	}
	protos := []proto{
		{"UDP", uint8(wf.IPProtoUDP)},
		{"TCP", uint8(wf.IPProtoTCP)},
	}

	type dir struct {
		name    string
		layer   wf.LayerID
		inbound bool
	}
	dirs := []dir{
		{"outbound", wf.LayerALEAuthConnectV4, false},
		{"outbound", wf.LayerALEAuthConnectV6, false},
		{"inbound", wf.LayerALEAuthRecvAcceptV4, true},
		{"inbound", wf.LayerALEAuthRecvAcceptV6, true},
	}

	var rules []*wf.Rule
	for _, d := range dirs {
		ip := v4
		fam := "v4"
		if d.layer == wf.LayerALEAuthConnectV6 || d.layer == wf.LayerALEAuthRecvAcceptV6 {
			ip = v6
			fam = "v6"
		}
		for _, pr := range protos {
			r, err := loopbackRule(sub, d, ip, fam, pr)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func loopbackRule(sub wf.SublayerID, d struct {
	name    string
	layer   wf.LayerID
	inbound bool
}, ip netip.Addr, fam string, pr struct {
	name string
	val  uint8
}) (*wf.Rule, error) {
	var conds []*wf.Match
	conds = append(conds, &wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: pr.val})
	if d.inbound {
		conds = append(conds, &wf.Match{Field: wf.FieldIPLocalAddress, Op: wf.MatchTypeEqual, Value: ip})
		conds = append(conds, &wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: uint16(53)})
	} else {
		conds = append(conds, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: ip})
		conds = append(conds, &wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: uint16(53)})
	}
	guid, err := win.GenerateGUID()
	if err != nil {
		return nil, fmt.Errorf("generate rule guid: %w", err)
	}
	return &wf.Rule{
		ID:         wf.RuleID(guid),
		Name:       fmt.Sprintf("ZeusDNS permit loopback %s %s %s", fam, d.name, pr.name),
		Layer:      d.layer,
		Sublayer:   sub,
		Weight:     0x0FFFFFFF, // very high weight so we outrank VPN block rules
		Conditions: conds,
		Action:     wf.ActionPermit,
	}, nil
}
