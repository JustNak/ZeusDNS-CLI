//go:build windows
// +build windows

package updater

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// EmbeddedMinisignPubkey is the minisign public key used to verify release
// binaries before installing them. The owner generates this with `minisign -G`
// and pastes the entire content of minisign.pub into this constant (including
// the "untrusted comment:" line).
//
// When the key is empty (the default), the updater fails-closed and refuses
// to install any update. See KEYGEN.md for setup instructions.
//
// File format (two lines):
//
//	untrusted comment: minisign public key <hex-id>
//	base64(<alg_byte=0x05> + <key_id=8B> + <pubkey=32B>)
//
// TODO: owner — replace with the full content of your minisign.pub file.
const EmbeddedMinisignPubkey = ""

// minisigFileSuffix is the suffix appended to a release-asset name to form
// the accompanying minisign signature file name.
const minisigFileSuffix = ".minisig"

// minisigVerify verifies the content of data against the Ed25519 signature
// stored in sigData, using the globally embedded public key
// (EmbeddedMinisignPubkey).
//
// It fails-closed with a clear error if the embedded public key is empty
// (not configured).
func minisigVerify(data, sigData []byte) error {
	if EmbeddedMinisignPubkey == "" {
		return errors.New("minisign public key not configured; refusing to update — see KEYGEN.md")
	}

	pubKey, expectedKeyID, err := parseMinisignPubkey(EmbeddedMinisignPubkey)
	if err != nil {
		return fmt.Errorf("invalid embedded minisign public key: %w", err)
	}

	sigAlgorithm, sigKeyID, signature, err := parseMinisigFile(sigData)
	if err != nil {
		return fmt.Errorf("invalid minisign signature file: %w", err)
	}

	if sigAlgorithm != 0x45 {
		return fmt.Errorf("unsupported signature algorithm: 0x%02x (expected 0x45 for Ed25519)", sigAlgorithm)
	}

	if !bytes.Equal(sigKeyID, expectedKeyID) {
		return fmt.Errorf("signature key ID mismatch: embedded expects %x, signature has %x", expectedKeyID, sigKeyID)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("unexpected signature length: %d (expected %d)", len(signature), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pubKey, data, signature) {
		return errors.New("minisign signature verification failed")
	}
	return nil
}

// parseMinisignPubkey parses a minisign public key in the format output by
// `minisign -G` and stored in minisign.pub.
//
// The file contains two lines:
//
//	untrusted comment: minisign public key <hex-id>
//	<base64-encoded key blob>
//
// The decoded key blob has the structure:
//
//	[0]      = algorithm byte (0x05)
//	[1:9]    = key ID (8 bytes)
//	[9:41]   = Ed25519 public key (32 bytes)
func parseMinisignPubkey(pubkeyStr string) (ed25519.PublicKey, []byte, error) {
	b64 := extractB64(pubkeyStr)
	if b64 == "" {
		return nil, nil, errors.New("no base64 data found in public key")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 1+8+ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("public key data too short: %d bytes (want at least %d)", len(raw), 1+8+ed25519.PublicKeySize)
	}
	if raw[0] != 0x05 {
		return nil, nil, fmt.Errorf("unexpected public key algorithm byte: 0x%02x (expected 0x05)", raw[0])
	}
	keyID := raw[1:9]
	pubKey := ed25519.PublicKey(raw[9 : 9+ed25519.PublicKeySize])
	return pubKey, keyID, nil
}

// parseMinisigFile parses the content of a .minisig signature file.
//
// The file contains two lines:
//
//	untrusted comment: <text>
//	<base64-encoded signature blob>
//
// The decoded signature blob has the structure:
//
//	[0]      = signature algorithm byte (0x45 for Ed25519)
//	[1:9]    = key ID (8 bytes)
//	[9:73]   = Ed25519 signature (64 bytes)
func parseMinisigFile(sigData []byte) (alg byte, keyID, signature []byte, err error) {
	b64 := extractB64(string(sigData))
	if b64 == "" {
		return 0, nil, nil, errors.New("no base64 data found in signature file")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 1+8+ed25519.SignatureSize {
		return 0, nil, nil, fmt.Errorf("signature data too short: %d bytes (want at least %d)", len(raw), 1+8+ed25519.SignatureSize)
	}
	alg = raw[0]
	keyID = raw[1:9]
	signature = raw[9 : 9+ed25519.SignatureSize]
	return alg, keyID, signature, nil
}

// extractB64 extracts the first non-empty, non-comment line from s and
// returns it trimmed. Lines beginning with "untrusted comment:" are
// treated as comments and skipped.
func extractB64(s string) string {
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		return line
	}
	return ""
}
