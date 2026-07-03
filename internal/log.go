package internal

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger is a thin wrapper around slog that writes to a log file and,
// optionally, mirrors to stdout (used when -v verbose is requested).
type Logger struct {
	*slog.Logger
	file *os.File
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

// NewLogger opens path for append (created if missing) and returns a logger.
// When console is true the same records are also written to stdout.
func NewLogger(level, path string, console bool) (*Logger, error) {
	var w io.Writer = io.Discard
	var file *os.File

	switch {
	case path != "" && console:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		file = f
		w = io.MultiWriter(f, os.Stdout)
	case path != "":
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		file = f
		w = f
	case console:
		w = os.Stdout
	}

	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return &Logger{Logger: slog.New(h), file: file}, nil
}

// Close releases the log file if one was opened.
func (l *Logger) Close() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
	}
}
