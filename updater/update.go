//go:build windows
// +build windows

// Package updater implements a minimal GitHub-releases self-update for the
// zeusdns.exe binary. It downloads the latest windows release zip, swaps the
// binary using a rename-aside (the running image can be renamed but not
// overwritten on Windows), and restarts the service if it was running.
package updater

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/mod/semver"
	win "golang.org/x/sys/windows"

	"github.com/JustNak/ZeusDNS-CLI/config"
)

// Repo is the GitHub "owner/repo" to pull releases from. Change this if you
// publish under a different path.
const Repo = "JustNak/ZeusDNS-CLI"

const (
	// maxDownloadSize caps the amount of data the updater will accept for a
	// single release-zip download (64 MiB). The actual binary is ~10-20 MiB.
	maxDownloadSize = 64 << 20

	// maxExtractSize caps each zip entry extracted from the archive.
	maxExtractSize = 64 << 20
)

// allowedDownloadHosts restricts HTTP(S) redirect targets for the updater
// client. Only GitHub and its content CDN are permitted.
var allowedDownloadHosts = []string{
	"github.com",
	"api.github.com",
	"objects.githubusercontent.com",
}

// restrictedHTTPClient is the updater's HTTP client with a redirect-target
// allowlist and a maximum-redirect guard. Used for all outbound calls.
var restrictedHTTPClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		host := req.URL.Hostname()
		for _, a := range allowedDownloadHosts {
			if strings.EqualFold(host, a) {
				return nil
			}
		}
		return fmt.Errorf("redirect to disallowed host: %s", host)
	},
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Name    string    `json:"name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// fetchLatestRelease fetches the latest release metadata from GitHub.
func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := restrictedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var r ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// LatestVersion returns the latest release tag (without a leading "v").
func LatestVersion(ctx context.Context) (string, error) {
	r, err := fetchLatestRelease(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(r.TagName, "v"), nil
}

// Update checks for a newer release than currentVersion and, if found, downloads
// and swaps the INSTALLED binary at config.InstallPath (never the running exe,
// so it behaves the same whether launched from the install path or a dev
// build). It refuses if no installed binary exists. It stops and restarts the
// service around the swap if it was running.
func Update(ctx context.Context, currentVersion string) (string, error) {
	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		return "", err
	}
	latest := strings.TrimPrefix(rel.TagName, "v")

	if latest == currentVersion {
		return "already up to date (" + currentVersion + ")", nil
	}
	// Downgrade guard: only when BOTH versions are real semver. Non-semver
	// current ("dev" builds) bypasses the guard so a dev build may update to
	// any real release; the equality case above already short-circuits same-version.
	cv, lv := "v"+currentVersion, "v"+latest
	if semver.IsValid(cv) && semver.IsValid(lv) && semver.Compare(cv, lv) > 0 {
		return "", fmt.Errorf("refusing downgrade: installed %s is newer than latest %s", currentVersion, latest)
	}

	assetURL, assetName, err := findAsset(rel, runtime.GOARCH)
	if err != nil {
		return "", err
	}

	zipPath, err := downloadToTemp(ctx, assetURL, assetName)
	if err != nil {
		return "", err
	}
	defer os.Remove(zipPath)

	// Minisign verification: download the .minisig file and verify the zip
	// against the embedded public key. This is the primary trust anchor.
	// Fail-closed when the pubkey is not configured.
	sigData, err := downloadMinisig(ctx, rel, assetName)
	if err != nil {
		return "", fmt.Errorf("minisign signature download failed: %w", err)
	}
	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		return "", fmt.Errorf("read downloaded zip: %w", err)
	}
	if err := minisigVerify(zipData, sigData); err != nil {
		return "", fmt.Errorf("minisign verification failed: %w", err)
	}
	zipData = nil // allow GC

	newExe, err := extractExe(zipPath)
	if err != nil {
		return "", err
	}
	defer os.Remove(newExe)

	// Verify integrity of the extracted binary before installing it.
	if err := verifyCandidate(ctx, rel, assetName, newExe); err != nil {
		return "", err
	}

	binPath := config.InstallPath()
	if _, err := os.Stat(binPath); err != nil {
		return "", fmt.Errorf("no installed binary at %s: run `zeusdns install` first (%w)", binPath, err)
	}

	// Stop the service if present so its file handle releases.
	svcRunning := false
	if st, err := serviceStatus(); err == nil && st == "running" {
		svcRunning = true
		_ = stopService()
	}

	oldPath := binPath + ".old"
	_ = os.Remove(oldPath) // clear a leftover from a previous update
	if err := os.Rename(binPath, oldPath); err != nil {
		return "", fmt.Errorf("rename current binary aside: %w", err)
	}
	if err := os.Rename(newExe, binPath); err != nil {
		// try to roll back
		_ = os.Rename(oldPath, binPath)
		return "", fmt.Errorf("install new binary: %w", err)
	}
	// The service was stopped before the rename, so .old is not mapped to any
	// running process and is normally deletable. Try a direct remove first;
	// only fall back to MOVEFILE_DELAY_UNTIL_REBOOT if the filesystem or a
	// scanner (AV) prevents deletion.
	if err := os.Remove(oldPath); err != nil {
		_ = win.MoveFileEx(win.StringToUTF16Ptr(oldPath), nil, win.MOVEFILE_DELAY_UNTIL_REBOOT)
	}

	if svcRunning {
		_ = startService()
	}
	return fmt.Sprintf("updated %s -> %s", currentVersion, latest), nil
}

func findAsset(r *ghRelease, arch string) (url, name string, err error) {
	for _, a := range r.Assets {
		low := strings.ToLower(a.Name)
		if strings.Contains(low, "windows") && strings.Contains(low, arch) {
			return a.BrowserDownloadURL, a.Name, nil
		}
	}
	return "", "", fmt.Errorf("no windows/%s asset in release %s (assets: %v)", arch, strings.TrimPrefix(r.TagName, "v"), assetNames(r.Assets))
}

func assetNames(as []ghAsset) string {
	names := make([]string, len(as))
	for i, a := range as {
		names[i] = a.Name
	}
	return strings.Join(names, ", ")
}

func downloadToTemp(ctx context.Context, url, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := restrictedHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}
	// Cap downloads so a malicious release cannot exhaust disk or memory.
	limited := io.LimitReader(resp.Body, maxDownloadSize+1)
	tmp, err := os.CreateTemp("", "zeusdns-update-*.zip")
	if err != nil {
		return "", err
	}
	written, err := io.Copy(tmp, limited)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if written > maxDownloadSize {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("download too large: exceeded %d bytes", maxDownloadSize)
	}
	return tmp.Name(), tmp.Close()
}

// downloadMinisig finds the .minisig signature file for the given release
// asset in the release metadata and downloads its content.
func downloadMinisig(ctx context.Context, r *ghRelease, assetName string) ([]byte, error) {
	sigName := assetName + minisigFileSuffix
	var sigURL string
	for _, a := range r.Assets {
		if a.Name == sigName {
			sigURL = a.BrowserDownloadURL
			break
		}
	}
	if sigURL == "" {
		return nil, fmt.Errorf("no minisign signature file (%s) in release assets", sigName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := restrictedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download minisig returned %d", resp.StatusCode)
	}

	// Minisig files are tiny (<1 KB) but use a small limit as a sanity check.
	sigData, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	return sigData, nil
}

// extractExe finds zeusdns.exe inside the zip and writes it to a temp file.
func extractExe(zipPath string) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == config.BinaryName {
			return copyZipEntry(f)
		}
	}
	return "", fmt.Errorf("no %s found in archive (exact entry name required)", config.BinaryName)
}

func copyZipEntry(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	// Reject entries larger than the cap before streaming.
	if f.UncompressedSize64 > maxExtractSize {
		return "", fmt.Errorf("zip entry %s too large: %d bytes (max %d)", f.Name, f.UncompressedSize64, maxExtractSize)
	}

	limited := io.LimitReader(rc, maxExtractSize+1)
	tmp, err := os.CreateTemp("", "zeusdns-new-*.exe")
	if err != nil {
		return "", err
	}
	written, err := io.Copy(tmp, limited)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if written > maxExtractSize {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("zip entry %s extract exceeded %d bytes", f.Name, maxExtractSize)
	}
	return tmp.Name(), tmp.Close()
}

// checksumAssetNames returns the list of asset-name patterns to try for a
// checksums file, given the downloaded asset's name. Order matters — the
// first match wins, so common aggregate names are checked first.
func checksumAssetNames(assetName string) []string {
	stem := strings.TrimSuffix(assetName, filepath.Ext(assetName))
	names := []string{
		"checksums.txt",
		"SHA256SUMS",
		"sha256sums.txt",
		"sha256sums",
	}
	for _, n := range []string{assetName, stem} {
		names = append(names, n+".sha256", n+".sha256sum")
	}
	return names
}

// findChecksumAsset iterates release assets looking for a checksums file
// matching one of the known patterns, in priority order. It returns the
// download URL and the asset name, or an error if none is found.
func findChecksumAsset(r *ghRelease, assetName string) (string, string, error) {
	candidates := checksumAssetNames(assetName)
	for _, c := range candidates {
		for _, a := range r.Assets {
			if strings.EqualFold(a.Name, c) {
				return a.BrowserDownloadURL, a.Name, nil
			}
		}
	}
	return "", "", fmt.Errorf("no checksum asset found (tried %s)", strings.Join(candidates, ", "))
}

// verifyCandidate fetches the checksums asset for the release, parses
// SHA256SUMS-format content to find the digest for the downloaded asset, and
// verifies it matches the SHA-256 of the candidate binary. On failure the
// candidate file is deleted and an error returned.
func verifyCandidate(ctx context.Context, r *ghRelease, assetName, candidatePath string) error {
	checksumURL, _, err := findChecksumAsset(r, assetName)
	if err != nil {
		os.Remove(candidatePath)
		return fmt.Errorf("update integrity check failed: no checksums asset found in release; refusing to install unverified binary")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return err
	}
	resp, err := restrictedHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch checksums returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse SHA256SUMS format (https://en.wikipedia.org/wiki/SHA256SUMS).
	// Each non-empty line is one of:
	//   <64hex>  <filename>     (two spaces — GNU text mode)
	//   <64hex> *<filename>     (space+asterisk — GNU binary mode)
	lines := strings.Split(string(body), "\n")
	var expected string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var hash, fname string
		switch {
		case strings.Contains(line, "  "):
			// Two-space separator: "<64hex>  <filename>"
			idx := strings.Index(line, "  ")
			hash = strings.TrimSpace(line[:idx])
			fname = strings.TrimSpace(line[idx+2:])
		case strings.Contains(line, " *"):
			// Space+asterisk: "<64hex> *<filename>"
			idx := strings.Index(line, " *")
			hash = strings.TrimSpace(line[:idx])
			fname = strings.TrimSpace(line[idx+2:])
		default:
			// Unrecognized format — skip this line.
			continue
		}
		if len(hash) != 64 || !isHex(hash) {
			continue
		}
		// Accept exact match or base-name match (in case the checksum line
		// includes a path prefix like "./").
		if strings.EqualFold(fname, assetName) || strings.EqualFold(filepath.Base(fname), assetName) {
			expected = hash
			break
		}
	}

	if expected == "" {
		os.Remove(candidatePath)
		return fmt.Errorf("update integrity check failed: no checksum entry found for %s in release checksums", assetName)
	}

	// Compute SHA-256 of the candidate binary and compare.
	data, err := os.ReadFile(candidatePath)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(data)
	actualHex := fmt.Sprintf("%x", actual)

	if !strings.EqualFold(actualHex, expected) {
		os.Remove(candidatePath)
		return fmt.Errorf("update integrity check failed: sha256 mismatch (expected %s)", expected)
	}

	return nil
}

// isHex reports whether every character in s is a valid hex digit.
func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		switch {
		case '0' <= c && c <= '9':
		case 'a' <= c && c <= 'f':
		case 'A' <= c && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// --- thin service helpers so updater doesn't import the service package ---

func serviceStatus() (string, error) {
	out, err := runSC("query", config.ServiceName)
	if err != nil {
		return "", err
	}
	switch {
	case strings.Contains(out, "RUNNING"):
		return "running", nil
	case strings.Contains(out, "STOPPED"):
		return "stopped", nil
	default:
		return "unknown", nil
	}
}

func stopService() error {
	_, err := runSC("stop", config.ServiceName)
	return err
}

func startService() error {
	_, err := runSC("start", config.ServiceName)
	return err
}

// runSC shells out to sc.exe (always present on Windows) to avoid an import
// cycle with the service package.
func runSC(args ...string) (string, error) {
	cmd := exec.Command("sc.exe", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}
