package logger

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Helper function to capture log output
func captureOutput(f func()) string {
	var buf bytes.Buffer
	originalOutput := CurrentOutput()
	defer SetOutput(originalOutput)
	SetOutput(&buf)
	f()
	return buf.String()
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name          string
		level         Level
		log           func(*Logger)
		wantLevel     Level
		wantFragments []string
	}{
		{
			name:      "Debug Logger Writes Debug Output",
			level:     DebugLevel,
			wantLevel: DebugLevel,
			log: func(logger *Logger) {
				logger.Debugf("Test message %d", 1)
			},
			wantFragments: []string{"level=DEBUG", "msg=\"Test message 1\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(&buf, tt.level)
			require.NotNil(t, logger)
			require.Equal(t, tt.wantLevel, logger.Level())

			tt.log(logger)

			output := buf.String()
			for _, fragment := range tt.wantFragments {
				require.Contains(t, output, fragment)
			}
		})
	}
}

func TestDefaultLogger(t *testing.T) {
	tests := []struct {
		name      string
		wantLevel Level
	}{
		{name: "Default Logger Uses Info Level", wantLevel: InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := Default()
			require.NotNil(t, logger)
			require.Equal(t, tt.wantLevel, logger.Level())
		})
	}
}

func TestSetGetLevel(t *testing.T) {
	t.Run("Instance Level Controls Output", func(t *testing.T) {
		var buf bytes.Buffer
		logger := New(&buf, InfoLevel)

		require.Equal(t, InfoLevel, logger.Level())

		logger.SetLevel(WarnLevel)
		require.Equal(t, WarnLevel, logger.Level())

		logger.Infof("Info should be ignored")
		require.NotContains(t, buf.String(), "Info should be ignored")

		logger.Warnf("Warn should be logged")
		require.Contains(t, buf.String(), "level=WARN")
		require.Contains(t, buf.String(), "msg=\"Warn should be logged\"")
	})

	t.Run("Global Level Controls Output", func(t *testing.T) {
		originalLevel := CurrentLevel()
		defer SetLevel(originalLevel)

		SetLevel(DebugLevel)
		require.Equal(t, DebugLevel, CurrentLevel())

		output := captureOutput(func() {
			Debugf("Global debug")
		})
		require.Contains(t, output, "level=DEBUG")
		require.Contains(t, output, "msg=\"Global debug\"")
	})
}

func TestSetOutput(t *testing.T) {
	t.Run("Instance Output Can Be Replaced", func(t *testing.T) {
		var first bytes.Buffer
		logger := New(&first, InfoLevel)

		logger.Infof("Message 1")
		require.Contains(t, first.String(), "Message 1")

		var second bytes.Buffer
		logger.SetOutput(&second)
		require.Equal(t, &second, logger.Output())

		logger.Infof("Message 2")
		require.NotContains(t, first.String(), "Message 2")
		require.Contains(t, second.String(), "Message 2")
	})

	t.Run("Global Output Can Be Replaced", func(t *testing.T) {
		originalOutput := CurrentOutput()
		defer SetOutput(originalOutput)

		var buf bytes.Buffer
		SetOutput(&buf)
		require.Equal(t, &buf, CurrentOutput())

		Infof("Global message 3")
		require.Contains(t, buf.String(), "Global message 3")
	})
}

func TestLoggingLevels(t *testing.T) {
	tests := []struct {
		level       Level
		logFunc     func(format string, args ...any)
		levelString string
		shouldLogAt Level
		expectLog   bool
	}{
		{DebugLevel, Debugf, "DEBUG", DebugLevel, true},
		{DebugLevel, Debugf, "DEBUG", InfoLevel, false},
		{InfoLevel, Infof, "INFO", InfoLevel, true},
		{InfoLevel, Infof, "INFO", WarnLevel, false},
		{WarnLevel, Warnf, "WARN", WarnLevel, true},
		{WarnLevel, Warnf, "WARN", ErrorLevel, false},
		{ErrorLevel, Errorf, "ERROR", ErrorLevel, true},
		{ErrorLevel, Errorf, "ERROR", FatalLevel, false}, // FatalLevel iota value is 1, ErrorLevel is 2
	}

	originalLevel := CurrentLevel()
	defer SetLevel(originalLevel)

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_at_%d", tt.levelString, tt.shouldLogAt), func(t *testing.T) {
			SetLevel(tt.shouldLogAt)
			msg := fmt.Sprintf("Testing %s level logging when logger level is set to %d", tt.levelString, tt.shouldLogAt)
			output := captureOutput(func() {
				tt.logFunc(msg)
			})

			if tt.expectLog {
				require.Contains(t, output, "level="+tt.levelString, msg)
				require.Contains(t, output, "msg=\""+msg+"\"", msg)
				return
			}

			require.Empty(t, output, msg)
		})
	}
}

func TestLoggerContextFields(t *testing.T) {
	tests := []struct {
		name                  string
		makeDerivedLogger     func(*Logger) *Logger
		originalMessage       string
		derivedMessage        string
		derivedWantFragments  []string
		originalMissFragments []string
	}{
		{
			name: "WithField",
			makeDerivedLogger: func(logger *Logger) *Logger {
				return logger.WithField("request_id", "12345")
			},
			originalMessage:       "Original message",
			derivedMessage:        "Message with field",
			derivedWantFragments:  []string{"level=INFO", "msg=\"Message with field\"", "request_id=12345"},
			originalMissFragments: []string{"request_id=12345"},
		},
		{
			name: "WithFields",
			makeDerivedLogger: func(logger *Logger) *Logger {
				return logger.WithFields(map[string]any{
					"user":   "alice",
					"system": "billing",
				})
			},
			originalMessage:       "Original message again",
			derivedMessage:        "Message with multiple fields",
			derivedWantFragments:  []string{"level=INFO", "msg=\"Message with multiple fields\"", "user=alice", "system=billing"},
			originalMissFragments: []string{"user=alice", "system=billing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := New(&buf, InfoLevel)
			derived := tt.makeDerivedLogger(logger)

			logger.Infof("%s", tt.originalMessage)
			originalOutput := buf.String()
			require.Contains(t, originalOutput, "msg=\""+tt.originalMessage+"\"")
			for _, fragment := range tt.originalMissFragments {
				require.NotContains(t, originalOutput, fragment)
			}

			buf.Reset()

			derived.Infof("%s", tt.derivedMessage)
			derivedOutput := buf.String()
			for _, fragment := range tt.derivedWantFragments {
				require.Contains(t, derivedOutput, fragment)
			}
			require.Equal(t, logger.Output(), derived.Output())
		})
	}
}
