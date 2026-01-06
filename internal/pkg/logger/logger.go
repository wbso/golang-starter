package logger

import (
	"context"
	"log/slog"
	"os"
)

// defaultLogger is the default logger instance
var defaultLogger *slog.Logger

// Init initializes the default logger
func Init(env string) {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	switch env {
	case "production", "staging":
		// JSON handler for production
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		// Text handler for development
		opts.AddSource = true
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// Default returns the default logger
func Default() *slog.Logger {
	if defaultLogger == nil {
		return slog.Default()
	}
	return defaultLogger
}

// With creates a new logger with additional context
func With(args ...any) *slog.Logger {
	return Default().With(args...)
}

// Debug logs a debug message
func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

// Info logs an info message
func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}

// FromContext extracts a logger from context, or returns the default logger
func FromContext(ctx context.Context) *slog.Logger {
	l := ctx.Value(loggerKey{})
	if l != nil {
		if logger, ok := l.(*slog.Logger); ok {
			return logger
		}
	}
	return Default()
}

// ToContext adds a logger to the context
func ToContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

type loggerKey struct{}
