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

	win "golang.org/x/sys/windows"

	"github.com/JustNak/ZeusDNS-CLI/config"
)

// Repo is the GitHub "owner/repo" to pull releases from. Change this if you
// publish under a different path.
const Repo = "JustNak/ZeusDNS-CLI"

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
	resp, err := http.DefaultClient.Do(req)
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

// parseSemver parses a "X.Y.Z" version string into 3 ints (missing segments
// treated as 0). It returns nil if any segment is non-numeric, in which case
// the caller should treat the version as non-semver (e.g. "dev") and skip
// semver comparison entirely rather than guessing via string compare (which
// would rank "dev" > "1.2.3" byte-wise and mis-block dev=>release updates).
func parseSemver(s string) []int {
	parts := strings.Split(s, ".")
	nums := make([]int, 0, 3)
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil // non-numeric segment
		}
		nums = append(nums, n)
	}
	for len(nums) < 3 {
		nums = append(nums, 0)
	}
	return nums
}

// isSemver reports whether s is a pure-numeric "X.Y[.Z]" version.
func isSemver(s string) bool { return parseSemver(s) != nil }

// compareVersion compares two SEMVER strings ("X.Y.Z", tolerating missing
// segments as 0). Returns -1 if a < b, 0 if equal, 1 if a > b.
// Callers must gate on isSemver for both args first: non-semver versions
// ("dev", pre-release tags) have no meaningful ordering and must be skipped,
// not string-compared.
func compareVersion(a, b string) int {
	an := parseSemver(a)
	bn := parseSemver(b)
	for i := 0; i < 3; i++ {
		if an[i] < bn[i] {
			return -1
		}
		if an[i] > bn[i] {
			return 1
		}
	}
	return 0
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
	if isSemver(currentVersion) && isSemver(latest) && compareVersion(currentVersion, latest) > 0 {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "zeusdns-update-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), tmp.Close()
}

// extractExe finds zeusdns.exe inside the zip and writes it to a temp file.
func extractExe(zipPath string) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if strings.EqualFold(filepath.Base(f.Name), config.BinaryName) {
			return copyZipEntry(f)
		}
	}
	// fall back to any .exe in the archive
	for _, f := range zr.File {
		if strings.EqualFold(filepath.Ext(f.Name), ".exe") {
			return copyZipEntry(f)
		}
	}
	return "", fmt.Errorf("no %s found in archive", config.BinaryName)
}

func copyZipEntry(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp("", "zeusdns-new-*.exe")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
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
	resp, err := http.DefaultClient.Do(req)
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
