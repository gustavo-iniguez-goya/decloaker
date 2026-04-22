package log

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
)

const (
	PLAIN = "plain"
	JSON  = "json"
	TEXT  = "text"
)

const (
	TRACE     = slog.LevelDebug - 2
	DEBUG     = slog.LevelDebug
	OK        = slog.LevelInfo - 1
	INFO      = slog.LevelInfo
	WARN      = slog.LevelWarn
	ERROR     = slog.LevelError
	DETECTION = slog.LevelError + 4
	QUIET     = slog.LevelError + 9000
)

var (
	logLevelMap = map[string]slog.Level{
		"trace":     TRACE,
		"debug":     DEBUG,
		"info":      INFO,
		"warn":      WARN,
		"error":     ERROR,
		"detection": DETECTION,
	}
	logLevelTag = map[slog.Level]string{
		TRACE:     "[t] ",
		DEBUG:     "[d] ",
		OK:        "[\u2713] ",
		INFO:      "[i] ",
		WARN:      "[w] ",
		ERROR:     "[e] ",
		DETECTION: "",
	}
	logLevelColor = map[slog.Level]string{
		TRACE:     magenta + logLevelTag[TRACE] + reset,
		DEBUG:     lightGray + logLevelTag[DEBUG] + reset,
		OK:        green + logLevelTag[OK] + reset,
		INFO:      blue + logLevelTag[INFO] + reset,
		WARN:      yellow + logLevelTag[WARN] + reset,
		ERROR:     red + logLevelTag[ERROR] + reset,
		DETECTION: logLevelTag[DETECTION],
	}
)

var (
	LogLevel  = INFO
	LogFormat = PLAIN
	logger    = &log.Logger{}
	slogger   = &slog.Logger{}
)

func NewLogger(format string) {

	switch format {
	case JSON:
		LogFormat = JSON
		slogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
		slog.SetDefault(slogger)
	case TEXT:
		LogFormat = TEXT
		slogger = slog.New(slog.NewTextHandler(os.Stdout, nil))
		slog.SetDefault(slogger)
	default:
		slogger = slog.New(&SimpleHandler{level: slog.LevelDebug})
		slog.SetDefault(slogger)
		LogFormat = PLAIN
	}
}

func SetLogLevel(level string) {
	LogLevel = logLevelMap[level]
}

func Log(msg string, args ...any) {
	if LogLevel >= DETECTION {
		return
	}

	if LogFormat == PLAIN {
		slogger.Log(context.Background(), slog.LevelInfo, fmt.Sprintf(msg, args...))
	} else if LogFormat == TEXT {
		if len(args) < 1 {
			return
		}
		slogger.Log(context.Background(), slog.LevelInfo, "", args[1:]...)
	} else if LogFormat == JSON {
		if len(args) < 1 {
			return
		}
		slogger.Log(context.Background(), slog.LevelInfo, "", args[1:]...)
	}
}

func Separator() {
	fmt.Fprintf(os.Stderr, "---------------------------------------8<---------------------------------------\n")
}

func Trace(msg string, args ...any) {
	if LogLevel <= TRACE {
		printPlain(TRACE, msg, args...)
	}
}

func Debug(msg string, args ...any) {
	if LogLevel <= DEBUG {
		printPlain(DEBUG, msg, args...)
	}
}

func Ok(msg string, args ...any) {
	if LogLevel <= INFO {
		printPlain(OK, msg, args...)
	}
}

func Info(msg string, args ...any) {
	if LogLevel <= INFO {
		printPlain(INFO, msg, args...)
	}
}

func Warn(msg string, args ...any) {
	if LogLevel <= WARN {
		printPlain(WARN, msg, args...)
	}
}

func Error(msg string, args ...any) {
	if LogLevel <= ERROR {
		printPlain(ERROR, msg, args...)
	}
}

func Detection(msg string, args ...any) {
	if LogLevel <= DETECTION {
		printPlain(DETECTION, msg, args...)
	}
}

func printPlain(level slog.Level, msg string, args ...any) {
	if LogFormat != PLAIN && (level == DETECTION || level == WARN || level == ERROR) {
		msg = strings.ReplaceAll(msg, "\n", " ")
		msg = strings.ReplaceAll(msg, "\t", " ")
		msg = strings.TrimSpace(msg)
		slogger.Log(context.Background(), level, fmt.Sprintf(msg, args...))
		return
	}
	fmt.Printf(logLevelColor[level]+msg, args...)
}
