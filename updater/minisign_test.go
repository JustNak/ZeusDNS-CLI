//go:build windows
// +build windows

package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMinisignVerifyEmptyPubkey(t *testing.T) {
	// With the default empty EmbeddedMinisignPubkey, every verification must
	// fail-closed — even with plausible-looking data.
	err := minisigVerify([]byte("any data"), []byte("fake sig"))
	if err == nil {
		t.Fatal("expected error with empty embedded pubkey, got nil")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected 'not configured' error, got: %v", err)
	}
}

func TestParseMinisignPubkey_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMsg string
	}{
		{"empty", "", "no base64 data"},
		{"only comment", "untrusted comment: hi", "no base64 data"},
		{"not base64", "not-valid-base64!!", "base64 decode"},
		{"too short", base64.StdEncoding.EncodeToString([]byte{0x05, 0x01, 0x02}), "too short"},
		{"wrong alg byte", base64.StdEncoding.EncodeToString(append([]byte{0x99}, make([]byte, 40)...)), "expected 0x05"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseMinisignPubkey(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestParseMinisigFile_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantMsg string
	}{
		{"empty", nil, "no base64 data"},
		{"only comment", []byte("untrusted comment: sig"), "no base64 data"},
		{"not base64", []byte("!!!bad!!!"), "base64 decode"},
		{"too short", []byte(base64.StdEncoding.EncodeToString([]byte{0x45, 0x01})), "too short"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseMinisigFile(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestParseMinisigFile_RoundTrip(t *testing.T) {
	// Verify that a valid .minisig file is parsed correctly.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello, minisign test")
	sig := ed25519.Sign(priv, msg)

	// Build a .minisig blob: first line comment, second line base64.
	// Byte layout: [0x45] [key_id=8B] [sig=64B]
	keyID := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	raw := append([]byte{0x45}, keyID...)
	raw = append(raw, sig...)
	b64 := base64.StdEncoding.EncodeToString(raw)
	sigFile := []byte("untrusted comment: test sig\n" + b64 + "\n")

	alg, parsedKeyID, parsedSig, err := parseMinisigFile(sigFile)
	if err != nil {
		t.Fatalf("parseMinisigFile: %v", err)
	}
	if alg != 0x45 {
		t.Fatalf("expected alg 0x45, got 0x%02x", alg)
	}
	if string(parsedKeyID) != string(keyID) {
		t.Fatalf("key ID mismatch: %x vs %x", parsedKeyID, keyID)
	}
	if string(parsedSig) != string(sig) {
		t.Fatalf("signature mismatch")
	}
}

func TestExtractB64(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"untrusted comment: hi", ""},
		{"abc", "abc"},
		{"untrusted comment: ignore\nabc123", "abc123"},
		{"\n  \nunstripped  \n", "unstripped"},
	}
	for _, tt := range tests {
		got := extractB64(tt.input)
		if got != tt.want {
			t.Errorf("extractB64(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
