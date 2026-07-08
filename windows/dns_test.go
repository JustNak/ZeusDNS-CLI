//go:build windows
// +build windows

package windows

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestParsePrevDNS_BareArray(t *testing.T) {
	// Legacy format: bare JSON array without checksum.
	data := `[{"InterfaceAlias":"Ethernet","ServerAddresses":["192.168.1.1"],"Dhcp":"Enabled"}]`
	entries, err := parsePrevDNS([]byte(data))
	if err != nil {
		t.Fatalf("parsePrevDNS bare array: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].InterfaceAlias != "Ethernet" {
		t.Fatalf("alias = %q, want Ethernet", entries[0].InterfaceAlias)
	}
}

func TestParsePrevDNS_WrapperWithValidChecksum(t *testing.T) {
	entries := []ifaceDNS{
		{InterfaceAlias: "Wi-Fi", ServerAddresses: []string{"10.0.0.1"}, Dhcp: "Disabled"},
		{InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.168.1.1"}, Dhcp: "Enabled"},
	}
	rawEntries, _ := json.Marshal(entries)
	sum := sha256.Sum256(rawEntries)
	pf := prevDNSFile{
		Entries:  entries,
		Checksum: fmt.Sprintf("%x", sum),
	}
	data, _ := json.Marshal(pf)

	got, err := parsePrevDNS(data)
	if err != nil {
		t.Fatalf("parsePrevDNS with valid checksum: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].InterfaceAlias != "Wi-Fi" {
		t.Fatalf("alias[0] = %q, want Wi-Fi", got[0].InterfaceAlias)
	}
}

func TestParsePrevDNS_WrapperWithBadChecksum(t *testing.T) {
	entries := []ifaceDNS{
		{InterfaceAlias: "Ethernet", ServerAddresses: []string{"192.168.1.1"}},
	}
	pf := prevDNSFile{
		Entries:  entries,
		Checksum: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	data, _ := json.Marshal(pf)

	_, err := parsePrevDNS(data)
	if err == nil {
		t.Fatal("parsePrevDNS with bad checksum: expected error, got nil")
	}
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		t.Fatalf("parsePrevDNS: expected checksum mismatch error, got parse error: %v", err)
	}
	t.Logf("got expected error: %v", err)
}

func TestParsePrevDNS_EmptyArray(t *testing.T) {
	data := `[]`
	entries, err := parsePrevDNS([]byte(data))
	if err != nil {
		t.Fatalf("parsePrevDNS empty array: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("got %d entries, want 0", len(entries))
	}
}
