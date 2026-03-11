package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

type Level int

const (
	PanicLevel Level = iota
	FatalLevel
	ErrorLevel
	WarnLevel
	InfoLevel
	DebugLevel
	TraceLevel
)

func (l Level) toSlogLevel() slog.Level {
	switch l {
	case PanicLevel, FatalLevel:
		return slog.LevelError
	case ErrorLevel:
		return slog.LevelError
	case WarnLevel:
		return slog.LevelWarn
	case InfoLevel:
		return slog.LevelInfo
	case DebugLevel, TraceLevel:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

type Logger struct {
	logger *slog.Logger
	level  Level
	output io.Writer
}

func New(output io.Writer, level Level) *Logger {
	return &Logger{
		logger: newSlogLogger(output, level),
		level:  level,
		output: output,
	}
}

func Default() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(os.Stderr, InfoLevel)
	})
	return globalLogger
}

func (l *Logger) SetLevel(level Level) {
	l.level = level
}

func (l *Logger) Level() Level {
	return l.level
}

func (l *Logger) Output() io.Writer {
	return l.output
}

func (l *Logger) SetOutput(output io.Writer) {
	l.logger = newSlogLogger(output, l.level)
	l.output = output
}

func (l *Logger) Debugf(format string, args ...any) {
	if l.level >= DebugLevel {
		l.logger.Debug(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Infof(format string, args ...any) {
	if l.level >= InfoLevel {
		l.logger.Info(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Warnf(format string, args ...any) {
	if l.level >= WarnLevel {
		l.logger.Warn(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Errorf(format string, args ...any) {
	if l.level >= ErrorLevel {
		l.logger.Error(fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Fatal(args ...any) {
	l.logger.Error(fmt.Sprint(args...))
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (l *Logger) Panic(args ...any) {
	msg := fmt.Sprint(args...)
	l.logger.Error(msg)
	panic(msg)
}

func (l *Logger) Panicf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.logger.Error(msg)
	panic(msg)
}

func (l *Logger) WithField(key string, value any) *Logger {
	return l.withAttrs(key, value)
}

func (l *Logger) WithFields(fields map[string]any) *Logger {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}

	return l.withAttrs(attrs...)
}

func SetLevel(level Level) {
	Default().SetLevel(level)
}

func CurrentLevel() Level {
	return Default().Level()
}

func CurrentOutput() io.Writer {
	return Default().Output()
}

func SetOutput(output io.Writer) {
	Default().SetOutput(output)
}

func Debugf(format string, args ...any) {
	Default().Debugf(format, args...)
}

func Infof(format string, args ...any) {
	Default().Infof(format, args...)
}

func Warnf(format string, args ...any) {
	Default().Warnf(format, args...)
}

func Errorf(format string, args ...any) {
	Default().Errorf(format, args...)
}

func Fatalf(format string, args ...any) {
	Default().Fatalf(format, args...)
}

func Panicf(format string, args ...any) {
	Default().Panicf(format, args...)
}

func newSlogLogger(output io.Writer, level Level) *slog.Logger {
	handler := slog.NewTextHandler(output, &slog.HandlerOptions{
		Level: level.toSlogLevel(),
	})
	return slog.New(handler)
}

func (l *Logger) withAttrs(attrs ...any) *Logger {
	return &Logger{
		logger: l.logger.With(attrs...),
		level:  l.level,
		output: l.output,
	}
}
