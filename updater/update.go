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

// LatestVersion returns the latest release tag (without a leading "v").
func LatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var r ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return strings.TrimPrefix(r.TagName, "v"), nil
}

// Update checks for a newer release than currentVersion and, if found,
// downloads and swaps the binary. It stops and restarts the service around
// the swap if the service is installed.
func Update(ctx context.Context, currentVersion string) (string, error) {
	latest, err := LatestVersion(ctx)
	if err != nil {
		return "", err
	}
	if latest == currentVersion {
		return "already up to date (" + currentVersion + ")", nil
	}

	assetURL, assetName, err := findAssetURL(ctx, latest)
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

	binPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	binPath, _ = filepath.Abs(binPath)

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
	// The .old image is still locked by this running process; delete on reboot.
	_ = win.MoveFileEx(win.StringToUTF16Ptr(oldPath), nil, win.MOVEFILE_DELAY_UNTIL_REBOOT)

	if svcRunning {
		_ = startService()
	}
	return fmt.Sprintf("updated %s -> %s", currentVersion, latest), nil
}

func findAssetURL(ctx context.Context, version string) (url, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github api returned %d", resp.StatusCode)
	}
	var r ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", err
	}
	arch := runtime.GOARCH
	for _, a := range r.Assets {
		low := strings.ToLower(a.Name)
		if strings.Contains(low, "windows") && strings.Contains(low, arch) {
			return a.BrowserDownloadURL, a.Name, nil
		}
	}
	return "", "", fmt.Errorf("no windows/%s asset in release %s (assets: %v)", arch, version, assetNames(r.Assets))
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
