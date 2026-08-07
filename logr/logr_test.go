package logr

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"
)

var ansiEscapeSequence = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestFileAndConsoleEventParity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	t.Setenv("LOFT_LOG_FILE", path)
	t.Setenv("LOFT_LOG_ENCODING", "console")
	console := captureStderr(t, func() {
		logger, err := NewLoggerWithOptions(
			WithOptionsFromEnv(),
			WithDevelopment(true),
			WithComponentName("test"),
		)
		if err != nil {
			t.Fatalf("create logger: %v", err)
		}
		logger.Info("parity-marker", "key", "value")
	})

	fileContent := readFile(t, path)
	if strings.Count(console, "parity-marker") != 1 {
		t.Fatalf("expected one console event, got %q", console)
	}
	if strings.Count(fileContent, "parity-marker") != 1 {
		t.Fatalf("expected one file event, got %q", fileContent)
	}
	if fileContent != ansiEscapeSequence.ReplaceAllString(console, "") {
		t.Fatalf("expected file bytes to match console bytes minus ANSI color codes\nconsole: %q\nfile: %q", console, fileContent)
	}
}

func TestJSONFileOutputAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	t.Setenv("LOFT_LOG_FILE", path)
	t.Setenv("LOFT_LOG_ENCODING", "json")
	console := captureStderr(t, func() {
		logger, err := NewLoggerWithOptions(
			WithOptionsFromEnv(),
		)
		if err != nil {
			t.Fatalf("create logger: %v", err)
		}
		logger.Info("json-marker", "key", "value")
	})

	fileContent := readFile(t, path)
	if fileContent != console {
		t.Fatalf("expected JSON file and console bytes to match\nconsole: %q\nfile: %q", console, fileContent)
	}

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(fileContent)), &event); err != nil {
		t.Fatalf("parse JSON log: %v", err)
	}
	if event["msg"] != "json-marker" || event["key"] != "value" {
		t.Fatalf("unexpected event: %#v", event)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Fatalf("expected mode 0644, got %04o", got)
	}
}

func TestFileAndConsoleSamplingParity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	t.Setenv("LOFT_LOG_FILE", path)
	t.Setenv("LOFT_LOG_ENCODING", "console")

	const attempts = 250
	console := captureStderr(t, func() {
		logger, err := NewLoggerWithOptions(WithOptionsFromEnv())
		if err != nil {
			t.Fatalf("create logger: %v", err)
		}
		for i := 0; i < attempts; i++ {
			logger.Info("sampling-marker")
		}
	})

	consoleCount := strings.Count(console, "sampling-marker")
	fileCount := strings.Count(readFile(t, path), "sampling-marker")
	if consoleCount != fileCount {
		t.Fatalf("expected matching sampled event counts, console=%d file=%d", consoleCount, fileCount)
	}
	if consoleCount == 0 || consoleCount >= attempts {
		t.Fatalf("expected sampling to retain a subset of %d events, got %d", attempts, consoleCount)
	}
}

func TestFileWriterRegistryReusesWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	first, err := getFileWriteSyncer(path)
	if err != nil {
		t.Fatalf("get first writer: %v", err)
	}
	second, err := getFileWriteSyncer(filepath.Join(filepath.Dir(path), ".", filepath.Base(path)))
	if err != nil {
		t.Fatalf("get second writer: %v", err)
	}
	if first != second {
		t.Fatal("expected the same writer for equivalent paths")
	}
}

func TestFileWriterRotationConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	rotatingWriter := newRotatingWriter(path)
	if rotatingWriter.MaxSize != logFileMaxSizeMB ||
		rotatingWriter.MaxBackups != logFileMaxBackups ||
		rotatingWriter.MaxAge != logFileMaxAgeDays ||
		rotatingWriter.Compress {
		t.Fatalf("unexpected rotation configuration: %#v", rotatingWriter)
	}
}

func TestFileInitializationFailureIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "product.log")
	t.Setenv("LOFT_LOG_FILE", path)
	_, err := NewLoggerWithOptions(
		WithOptionsFromEnv(),
	)
	if err == nil || !strings.Contains(err.Error(), "open log file") {
		t.Fatalf("expected startup file error, got %v", err)
	}
}

func TestFileWriteFailurePreservesConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	canonicalPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		t.Fatalf("resolve path: %v", err)
	}
	fileWritersMu.Lock()
	fileWriters[canonicalPath] = zapcore.AddSync(failingWriter{})
	fileWritersMu.Unlock()
	t.Cleanup(func() {
		fileWritersMu.Lock()
		delete(fileWriters, canonicalPath)
		fileWritersMu.Unlock()
	})
	t.Setenv("LOFT_LOG_FILE", path)

	console := captureStderr(t, func() {
		logger, err := NewLoggerWithOptions(WithOptionsFromEnv())
		if err != nil {
			t.Fatalf("create logger: %v", err)
		}
		logger.Info("file-failure-marker")
	})
	if strings.Count(console, "file-failure-marker") != 1 {
		t.Fatalf("expected console event despite file failure, got %q", console)
	}
	if !strings.Contains(console, "disk full") {
		t.Fatalf("expected Zap sink error, got %q", console)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	original := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = original }()

	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stderr reader: %v", err)
	}
	return string(output)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}
