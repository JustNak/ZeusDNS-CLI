package internal

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Logger is a thin wrapper around slog that writes to a log file and,
// optionally, mirrors to stdout (used when -v verbose is requested).
type Logger struct {
	*slog.Logger
	mu   *sync.Mutex
	file *os.File
	bufw *bufio.Writer
}

// lockedWriter wraps a *bufio.Writer with a mutex so that slog's concurrent
// Write calls and explicit flush/close are mutually exclusive.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bufio.Writer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.w == nil {
		return 0, io.ErrClosedPipe
	}
	return lw.w.Write(p)
}

// ParseLevel maps the config string to an slog level.
// "verbose" is treated as info-level: the DNS server emits per-query logs at
// info, so selecting verbose surfaces them without a separate level.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "verbose":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info", "":
		return slog.LevelInfo
	default:
		return slog.LevelInfo
	}
}

// maxLogSize is the threshold for size-based rotation (10 MiB).
// If the log file exceeds this when NewLogger is called, the existing
// file is renamed to path+".1" (overwriting any previous backup) and a
// fresh file is started. This is not live rotation — it runs once per
// process start.
const maxLogSize int64 = 10 * 1024 * 1024 // 10 MiB

// NewLogger opens path for append (created if missing) and returns a logger.
// When console is true the same records are also written to stdout.
func NewLogger(level, path string, console bool) (*Logger, error) {
	var w io.Writer = io.Discard
	var file *os.File
	var bufw *bufio.Writer
	mu := &sync.Mutex{}

	// Size-based rotation: if the existing log file is over maxLogSize,
	// rotate it to path+".1" and start fresh. Best-effort — if rotation
	// fails we simply keep appending.
	if path != "" {
		if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
			backup := path + ".1"
			_ = os.Remove(backup)       // Windows: Rename fails if dst exists
			_ = os.Rename(path, backup) // best-effort
		}
	}

	switch {
	case path != "" && console:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, err
		}
		file = f
		bufw = bufio.NewWriterSize(f, 64*1024)
		w = io.MultiWriter(&lockedWriter{mu: mu, w: bufw}, os.Stdout)
	case path != "":
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, err
		}
		file = f
		bufw = bufio.NewWriterSize(f, 64*1024)
		w = &lockedWriter{mu: mu, w: bufw}
	case console:
		w = os.Stdout
	}

	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return &Logger{Logger: slog.New(h), mu: mu, file: file, bufw: bufw}, nil
}

// flushLocked writes any buffered log data to the underlying file.
// The caller MUST hold l.mu.
func (l *Logger) flushLocked() error {
	if l == nil || l.bufw == nil {
		return nil
	}
	return l.bufw.Flush()
}

// Close releases the log file if one was opened and flushes pending output.
func (l *Logger) Close() {
	if l == nil || l.file == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.flushLocked()
	_ = l.file.Close()
	l.file = nil
	l.bufw = nil
}
