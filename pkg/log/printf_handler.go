package log

import (
	"context"
	"fmt"
	"log/slog"
)

const (
	reset = "\033[0m"

	black        = "\033[30m"
	red          = "\033[31m"
	green        = "\033[32m"
	yellow       = "\033[33m"
	blue         = "\033[34m"
	magenta      = "\033[35m"
	cyan         = "\033[36m"
	lightGray    = "\033[37m"
	darkGray     = "\033[90m"
	lightRed     = "\033[91m"
	lightGreen   = "\033[92m"
	lightYellow  = "\033[93m"
	lightBlue    = "\033[94m"
	lightMagenta = "\033[95m"
	lightCyan    = "\033[96m"
	white        = "\033[97m"
)

var HandlerOpts = &slog.HandlerOptions{
	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			level := a.Value.Any().(slog.Level)
			switch level {
			case TRACE:
				a.Value = slog.StringValue("TRACE")
			case DETECTION:
				a.Value = slog.StringValue("DETECTION")
			}
		}
		return a
	},
}

func colorize(colorCode int, v string) string {
	return fmt.Sprintf(red, v, reset)
}

type SimpleHandler struct {
	level      slog.Level
	withColors bool
}

func (h *SimpleHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *SimpleHandler) Handle(_ context.Context, r slog.Record) error {
	//ts := r.Time.Format(time.RFC3339)

	//msg := fmt.Sprintf("%s [%s] %s", ts, r.Level, r.Message)
	msg := fmt.Sprintf("%s", r.Message)

	r.Attrs(func(a slog.Attr) bool {
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value)
		return true
	})

	fmt.Printf(msg)
	return nil
}

func (h *SimpleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *SimpleHandler) WithGroup(name string) slog.Handler {
	return h
}
