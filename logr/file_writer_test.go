//go:build unix

// The behaviour under test here is unix file permission enforcement: keeping
// the active log file readable by a differently-privileged sidecar sharing the
// volume. The tests use umask, mkfifo and hard links accordingly.

package logr

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	lograpi "github.com/go-logr/logr"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var ansiEscapeSequence = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// These tests mutate process-wide environment, umask, stderr, and writer
// registry state. They must remain serial and must not call t.Parallel.

func TestFileAndConsoleEventParity(t *testing.T) {
	path, console := captureFileLogger(t, "console", func(logger lograpi.Logger) {
		logger.Info("parity-marker", "key", "value")
	}, WithDevelopment(true), WithComponentName("test"))

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
	path, console := captureFileLogger(t, "json", func(logger lograpi.Logger) {
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

	assertFileMode(t, path, 0644)
}

func TestFileAndConsoleSamplingParity(t *testing.T) {
	const attempts = 250
	path, console := captureFileLogger(t, "console", func(logger lograpi.Logger) {
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

// TestFileAndConsoleLevelParity pins that the file core is built at the
// configured level. At the default level every event passes both destinations,
// so only a raised level can tell the two apart.
func TestFileAndConsoleLevelParity(t *testing.T) {
	path, console := captureFileLogger(t, "console", func(logger lograpi.Logger) {
		logger.Info("suppressed-marker")
		logger.Error(errors.New("boom"), "emitted-marker")
	}, WithLogLevel("error"))

	fileContent := readFile(t, path)
	if strings.Contains(console, "suppressed-marker") || strings.Contains(fileContent, "suppressed-marker") {
		t.Fatalf("expected the info event to be suppressed in both destinations\nconsole: %q\nfile: %q", console, fileContent)
	}
	if !strings.Contains(console, "emitted-marker") || !strings.Contains(fileContent, "emitted-marker") {
		t.Fatalf("expected the error event in both destinations\nconsole: %q\nfile: %q", console, fileContent)
	}
}

func TestFileWriterRegistryReusesWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	first, err := getFileWriteSyncer(path, 0644)
	if err != nil {
		t.Fatalf("get first writer: %v", err)
	}
	t.Cleanup(func() { unregisterFileWriter(t) })
	second, err := getFileWriteSyncer(filepath.Join(filepath.Dir(path), ".", filepath.Base(path)), 0644)
	if err != nil {
		t.Fatalf("get second writer: %v", err)
	}
	if first != second {
		t.Fatal("expected the same writer for equivalent paths")
	}
	if _, err := getFileWriteSyncer(path, 0600); err == nil || !strings.Contains(err.Error(), "already registered with requested mode") {
		t.Fatalf("expected conflicting mode error, got %v", err)
	}
	other := filepath.Join(t.TempDir(), "other.log")
	if _, err := getFileWriteSyncer(other, 0644); err == nil || !strings.Contains(err.Error(), "log file already enabled") {
		t.Fatalf("expected different-path error, got %v", err)
	}
}

// TestFileWriterProductionThresholdRotation drives a real size-triggered
// rotation through the production entry point at the production constants, so
// the mirrored boundary is checked against lumberjack's own at the size that
// ships. The literal pins logFileMaxSizeMB and the byte arithmetic: the
// file is open by then, so lumberjack rotates only strictly above the limit.
func TestFileWriterProductionThresholdRotation(t *testing.T) {
	setUmask(t, 0027)

	path := filepath.Join(t.TempDir(), "product.log")
	syncer, err := getFileWriteSyncer(path, logFileDefaultMode)
	if err != nil {
		t.Fatalf("get write syncer: %v", err)
	}
	t.Cleanup(func() { unregisterFileWriter(t) })

	chunk := bytes.Repeat([]byte("a"), bytesPerMB)
	for i := 0; i < logFileMaxSizeMB+1; i++ {
		if _, err := syncer.Write(chunk); err != nil {
			t.Fatalf("write chunk %d: %v", i, err)
		}
	}

	assertBackupCount(t, path, 1)
	assertFileMode(t, path, 0644)
	assertFileMode(t, backupPaths(t, path)[0], 0644)
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat active file: %v", err)
	} else if info.Size() != int64(bytesPerMB) {
		t.Fatalf("expected the last chunk alone in the new active file, got %d bytes", info.Size())
	}
}

// TestExistingLogFileModeSurvivesRotation goes through the production entry
// point so the writer is built from the mode initializeLogFile resolved rather
// than the mode the caller requested.
func TestExistingLogFileModeSurvivesRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	writeFileWithMode(t, path, nil, 0600)

	mode, err := initializeLogFile(path, logFileDefaultMode)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	writer := newRotatingWriterWithMaxSizeMB(path, mode, 1)
	t.Cleanup(func() { _ = writer.Close() })

	chunk := bytes.Repeat([]byte("a"), 600*1024)
	for i := 0; i < 2; i++ {
		if _, err := writer.Write(chunk); err != nil {
			t.Fatalf("write chunk %d: %v", i, err)
		}
	}

	assertBackupCount(t, path, 1)
	assertFileMode(t, path, 0600)
}

func TestFileWriterAutomaticRotation(t *testing.T) {
	setUmask(t, 0027)

	path := filepath.Join(t.TempDir(), "product.log")
	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	writer := newRotatingWriterWithMaxSizeMB(path, mode, 1)
	t.Cleanup(func() { _ = writer.Close() })

	chunk := bytes.Repeat([]byte("a"), 600*1024)
	if _, err := writer.Write(chunk); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	if _, err := writer.Write(chunk); err != nil {
		t.Fatalf("write rotation-triggering chunk: %v", err)
	}

	if got := readFile(t, path); !bytes.Equal([]byte(got), chunk) {
		t.Fatalf("expected second chunk in active file, got %d bytes", len(got))
	}
	assertBackupCount(t, path, 1)
	backup := backupPaths(t, path)[0]
	if !bytes.Equal([]byte(readFile(t, backup)), chunk) {
		t.Fatalf("expected the first chunk in the backup file %q", backup)
	}
	assertFileMode(t, path, 0644)
	assertFileMode(t, backup, 0644)

	if !writer.opened || writer.size != int64(len(chunk)) {
		t.Fatalf("unexpected writer state after rotation: opened=%v size=%d", writer.opened, writer.size)
	}
}

// TestFileWriterRotationBoundaries pins the wrapper's own prediction, not
// lumberjack's behaviour: the writer state and the restored mode are what the
// asymmetry between the opened and unopened boundary actually controls.
func TestFileWriterRotationBoundaries(t *testing.T) {
	const maxBytes = int64(bytesPerMB)

	t.Run("unopened rotates at equality", func(t *testing.T) {
		setUmask(t, 0027)

		path := filepath.Join(t.TempDir(), "product.log")
		mode, err := initializeLogFile(path, 0644)
		if err != nil {
			t.Fatalf("initialize log file: %v", err)
		}
		if err := os.Truncate(path, maxBytes-1); err != nil {
			t.Fatalf("pre-size log file: %v", err)
		}
		writer := newRotatingWriterWithMaxSizeMB(path, mode, 1)
		t.Cleanup(func() { _ = writer.Close() })

		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatalf("write at equality: %v", err)
		}
		assertBackupCount(t, path, 1)
		assertWriterState(t, writer, 1, true)
		assertFileMode(t, path, 0644)
	})

	t.Run("opened rotates above equality", func(t *testing.T) {
		setUmask(t, 0027)

		path := filepath.Join(t.TempDir(), "product.log")
		mode, err := initializeLogFile(path, 0644)
		if err != nil {
			t.Fatalf("initialize log file: %v", err)
		}
		writer := newRotatingWriterWithMaxSizeMB(path, mode, 1)
		t.Cleanup(func() { _ = writer.Close() })

		if _, err := writer.Write([]byte("x")); err != nil {
			t.Fatalf("open writer: %v", err)
		}
		assertWriterState(t, writer, 1, true)

		if _, err := writer.Write(bytes.Repeat([]byte("a"), int(maxBytes-1))); err != nil {
			t.Fatalf("write to equality: %v", err)
		}
		assertBackupCount(t, path, 0)
		assertWriterState(t, writer, maxBytes, true)

		if _, err := writer.Write([]byte("y")); err != nil {
			t.Fatalf("write above equality: %v", err)
		}
		assertBackupCount(t, path, 1)
		assertWriterState(t, writer, 1, true)
		assertFileMode(t, path, 0644)
	})
}

// TestFileWriterExternalDeletionRestoresMode covers the log file being removed
// by a collector, an operator reclaiming space, or an unaware logrotate while
// the writer sits idle. Lumberjack recreates it at a hardcoded 0600.
func TestFileWriterExternalDeletionRestoresMode(t *testing.T) {
	setUmask(t, 0027)

	path := filepath.Join(t.TempDir(), "product.log")
	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	writer := newRotatingWriter(path, mode)
	t.Cleanup(func() { _ = writer.Close() })

	if _, err := writer.Write(bytes.Repeat([]byte("a"), 5000)); err != nil {
		t.Fatalf("write before deletion: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove log file: %v", err)
	}

	if _, err := writer.Write([]byte("after")); err != nil {
		t.Fatalf("write after deletion: %v", err)
	}
	assertFileMode(t, path, 0644)
	if got := readFile(t, path); got != "after" {
		t.Fatalf("expected only the post-deletion write in the recreated file, got %q", got)
	}
	assertWriterState(t, writer, int64(len("after")), true)
}

// TestFileWriterCloseReopensFromTheRealFile pins that reopening re-reads the
// file rather than carrying a mirrored size across the gap.
func TestFileWriterCloseReopensFromTheRealFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	writer := newRotatingWriter(path, mode)
	t.Cleanup(func() { _ = writer.Close() })

	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if writer.opened {
		t.Fatal("expected close to reset opened state")
	}
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatalf("write after close: %v", err)
	}
	if got := readFile(t, path); got != "first\nsecond\n" {
		t.Fatalf("expected the reopened writer to append, got %q", got)
	}
	assertWriterState(t, writer, int64(len("first\nsecond\n")), true)
}

// TestFileWriterResynchronizesAfterEveryFailedWrite pins that a run of failures
// leaves the writer in a known state after each one, rather than letting opened
// drift from whether lumberjack still holds the file. The fixture sits far from
// the rotation boundary, so no rotation is predicted and the error path is the
// only thing that can put the mode back.
func TestFileWriterResynchronizesAfterEveryFailedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	logger := &partialErrorLogger{path: path, writeBytes: 1}
	writer := &rotatingFileWriter{
		logger:   logger,
		path:     path,
		mode:     mode,
		maxBytes: int64(bytesPerMB),
		opened:   true,
	}

	const failures = 3
	for i := 0; i < failures; i++ {
		n, err := writer.Write([]byte("xy"))
		if n != 1 || err == nil || !strings.Contains(err.Error(), "partial write") {
			t.Fatalf("expected a one-byte partial write error on attempt %d, n=%d err=%v", i, n, err)
		}
		// The descriptor is dropped every time, so the next write re-reads the
		// real file instead of predicting from a mirror it can no longer trust.
		if writer.opened {
			t.Fatalf("expected the writer to be closed after failure %d", i)
		}
		assertFileMode(t, path, 0644)
	}
	if logger.closeCalls != failures {
		t.Fatalf("expected one close per failed write, got %d after %d failures", logger.closeCalls, failures)
	}
}

func TestFileWriterCountPruning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	writer := newRotatingWriter(path, mode)
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := writer.Write([]byte("active\n")); err != nil {
		t.Fatalf("write active file: %v", err)
	}

	// Seed one more backup than the retention limit, so converging on the limit
	// requires a real removal rather than reading back the seeded files.
	for i := 1; i <= logFileMaxBackups+1; i++ {
		name := "product-" + time.Now().UTC().Add(-time.Duration(i)*time.Minute).Format("2006-01-02T15-04-05.000") + ".log"
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), name), []byte("old\n"), 0644); err != nil {
			t.Fatalf("seed backup: %v", err)
		}
	}
	if err := writer.Rotate(); err != nil {
		t.Fatalf("rotate for pruning: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		backups := backupPaths(t, path)
		if len(backups) == logFileMaxBackups {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d retained backups, got %d: %v", logFileMaxBackups, len(backups), backups)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestInitializeLogFileResolvesExistingMode covers a file already at the
// configured path. Wider bits than requested are narrowed, because preserving
// them would let whoever pre-placed the file override WithLogFileMode for the
// process lifetime.
func TestInitializeLogFileResolvesExistingMode(t *testing.T) {
	for _, test := range []struct {
		name     string
		existing os.FileMode
		want     os.FileMode
	}{
		{name: "narrower mode is preserved", existing: 0600, want: 0600},
		{name: "wider mode is narrowed", existing: 0666, want: 0644},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "product.log")
			writeFileWithMode(t, path, nil, test.existing)

			mode, err := initializeLogFile(path, 0644)
			if err != nil {
				t.Fatalf("initialize existing log file: %v", err)
			}
			if mode != test.want {
				t.Fatalf("expected resolved mode %04o, got %04o", test.want, mode)
			}
			assertFileMode(t, path, test.want)
		})
	}
}

// TestRotateRestoresMode covers Rotate's own chmod, which is a separate call
// from the one Write makes on the rotation it predicts.
func TestRotateRestoresMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	writeFileWithMode(t, path, nil, 0600)

	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize existing log file: %v", err)
	}
	writer := newRotatingWriter(path, mode)
	t.Cleanup(func() { _ = writer.Close() })
	if err := writer.Rotate(); err != nil {
		t.Fatalf("rotate existing log file: %v", err)
	}
	assertFileMode(t, path, 0600)
}

// TestRotateReportsModeFailure covers Rotate succeeding while the chmod after
// it does not. The rotation still happened, so the writer records it and the
// error surfaces rather than leaving the caller believing the mode was restored.
func TestRotateReportsModeFailure(t *testing.T) {
	// No file is ever created at the path, so the chmod that follows the
	// rotation has nothing to open.
	path := filepath.Join(t.TempDir(), "product.log")
	writer := &rotatingFileWriter{
		logger:   rotateOnlyLogger{},
		path:     path,
		mode:     0644,
		maxBytes: int64(bytesPerMB),
	}

	err := writer.Rotate()
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected a mode error after a successful rotation, got %v", err)
	}
	assertWriterState(t, writer, 0, true)
}

// TestWithLogFileMode runs under a umask that would narrow every mode under
// test, so each case also pins that the requested mode survives it.
func TestWithLogFileMode(t *testing.T) {
	for _, test := range []struct {
		name string
		opts []Option
		want os.FileMode
	}{
		{name: "explicit mode is applied", opts: []Option{WithLogFileMode(0640)}, want: 0640},
		{name: "zero mode keeps the default", opts: []Option{WithLogFileMode(0)}, want: logFileDefaultMode},
		{name: "unset mode keeps the default", want: logFileDefaultMode},
	} {
		t.Run(test.name, func(t *testing.T) {
			setUmask(t, 0077)

			path := filepath.Join(t.TempDir(), "product.log")
			logger, err := NewLoggerWithOptions(append([]Option{WithLogFile(path)}, test.opts...)...)
			if err != nil {
				t.Fatalf("create logger: %v", err)
			}
			t.Cleanup(func() { unregisterFileWriter(t) })
			logger.Info("mode-marker")
			assertFileMode(t, path, test.want)
		})
	}
}

// TestSymlinkLogFileIsRejected covers a symlink planted at the configured path,
// through both entry points that open it by name. The target is left untouched
// either way.
func TestSymlinkLogFileIsRejected(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target.log")
	writeFileWithMode(t, target, []byte("unchanged"), 0600)
	path := filepath.Join(t.TempDir(), "product.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if _, err := initializeLogFile(path, 0644); err == nil {
		t.Fatal("expected symlink log path to be rejected")
	}
	if err := chmodRegularFile(path, 0644); err == nil {
		t.Fatal("expected symlink chmod to be rejected")
	}
	if got := readFile(t, target); got != "unchanged" {
		t.Fatalf("symlink target was modified: %q", got)
	}
	assertFileMode(t, target, 0600)
}

// TestWriteRejectsSwappedSymlink covers the path being replaced between writes:
// the writer refuses rather than letting lumberjack reopen by name and append
// into whatever the link points at.
func TestWriteRejectsSwappedSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product.log")
	mode, err := initializeLogFile(path, 0644)
	if err != nil {
		t.Fatalf("initialize log file: %v", err)
	}
	writer := newRotatingWriter(path, mode)
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove log file: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if _, err := writer.Write([]byte("second\n")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected swapped symlink to be rejected, got %v", err)
	}
	if got := readFile(t, target); got != "unchanged" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

// TestHardLinkedLogFileIsRejected covers a hard link planted in the shared log
// directory, which would otherwise redirect every chmod this package makes onto
// a file the other party controls.
func TestHardLinkedLogFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "product.log")
	writeFileWithMode(t, path, nil, 0600)
	if err := os.Link(path, filepath.Join(dir, "attacker.log")); err != nil {
		t.Fatalf("create hard link: %v", err)
	}

	if _, err := initializeLogFile(path, 0644); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("expected hard-linked log path to be rejected, got %v", err)
	}
	if err := chmodRegularFile(path, 0644); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("expected hard-linked chmod to be rejected, got %v", err)
	}
	assertFileMode(t, path, 0600)
}

// TestFifoLogFileIsRejectedWithoutHanging pins that opening the log path never
// blocks. A write-only open of a reader-less FIFO blocks forever, and these
// helpers run under the writer's lock on the write path.
func TestFifoLogFileIsRejectedWithoutHanging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product.log")
	if err := syscall.Mkfifo(path, 0644); err != nil {
		t.Fatalf("create fifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := initializeLogFile(path, 0644)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected fifo log path to be rejected")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("initializeLogFile blocked on a fifo log path")
	}

	if _, err := statRegularFile(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected fifo stat to be rejected, got %v", err)
	}
}

func TestLogFile(t *testing.T) {
	t.Setenv("LOFT_LOG_FILE", "  /var/log/product.log\t")
	if got := LogFile(); got != "/var/log/product.log" {
		t.Fatalf("expected trimmed log file path, got %q", got)
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
	canonicalPath, err := canonicalLogFilePath(path)
	if err != nil {
		t.Fatalf("resolve path: %v", err)
	}
	fileWriter = &registeredFileWriter{path: canonicalPath, writeSyncer: zapcore.AddSync(failingWriter{}), requestedMode: logFileDefaultMode}
	t.Cleanup(func() { unregisterFileWriter(t) })
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

func setUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

// newRotatingWriterWithMaxSizeMB builds a writer with a non-production size
// limit so rotation tests stay fast.
func newRotatingWriterWithMaxSizeMB(path string, mode os.FileMode, maxSizeMB int) *rotatingFileWriter {
	return &rotatingFileWriter{
		logger: &lumberjack.Logger{
			Filename:   path,
			MaxSize:    maxSizeMB,
			MaxBackups: logFileMaxBackups,
		},
		path:     path,
		mode:     mode.Perm(),
		maxBytes: int64(maxSizeMB) * bytesPerMB,
	}
}

// unregisterFileWriter clears the process-wide writer so an unrelated test
// cannot pick up a writer pointing at a removed temp directory.
func unregisterFileWriter(t *testing.T) {
	t.Helper()
	fileWriter = nil
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

	type readResult struct {
		output string
		err    error
	}
	done := make(chan readResult, 1)
	go func() {
		output, readErr := io.ReadAll(reader)
		done <- readResult{output: string(output), err: readErr}
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	result := <-done
	if result.err != nil {
		t.Fatalf("read stderr: %v", result.err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stderr reader: %v", err)
	}
	return result.output
}

func captureFileLogger(t *testing.T, encoding string, logFn func(lograpi.Logger), opts ...Option) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "product.log")
	t.Setenv("LOFT_LOG_FILE", path)
	t.Setenv("LOFT_LOG_ENCODING", encoding)
	t.Cleanup(func() { unregisterFileWriter(t) })
	console := captureStderr(t, func() {
		loggerOptions := append([]Option{WithOptionsFromEnv()}, opts...)
		logger, err := NewLoggerWithOptions(loggerOptions...)
		if err != nil {
			t.Fatalf("create logger: %v", err)
		}
		logFn(logger)
	})
	return path, console
}

// writeFileWithMode creates a file at exactly mode, which os.WriteFile alone
// cannot guarantee because the mode it takes goes through the umask.
func writeFileWithMode(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set %s mode: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("expected %s mode %04o, got %04o", path, want, got)
	}
}

func assertWriterState(t *testing.T, writer *rotatingFileWriter, wantSize int64, wantOpened bool) {
	t.Helper()
	if writer.size != wantSize || writer.opened != wantOpened {
		t.Fatalf("expected writer state size=%d opened=%v, got size=%d opened=%v", wantSize, wantOpened, writer.size, writer.opened)
	}
}

func backupPaths(t *testing.T, path string) []string {
	t.Helper()
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	backups, err := filepath.Glob(filepath.Join(filepath.Dir(path), base+"-*"+filepath.Ext(path)))
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	return backups
}

func assertBackupCount(t *testing.T, path string, want int) {
	t.Helper()
	if backups := backupPaths(t, path); len(backups) != want {
		t.Fatalf("expected %d backups, got %d: %v", want, len(backups), backups)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

// rotateOnlyLogger satisfies rotatingLogger without touching the filesystem, so
// a test can drive Rotate against a path in whatever state it chooses.
type rotateOnlyLogger struct{}

func (rotateOnlyLogger) Write(data []byte) (int, error) { return len(data), nil }
func (rotateOnlyLogger) Rotate() error                  { return nil }
func (rotateOnlyLogger) Close() error                   { return nil }

type partialErrorLogger struct {
	path       string
	writeBytes int
	closeCalls int
}

func (l *partialErrorLogger) Write(data []byte) (int, error) {
	if err := os.Chmod(l.path, 0640); err != nil {
		return 0, err
	}
	file, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	n, writeErr := file.Write(data[:l.writeBytes])
	closeErr := file.Close()
	return n, errors.Join(writeErr, closeErr, errors.New("partial write"))
}

func (*partialErrorLogger) Rotate() error { return nil }

func (l *partialErrorLogger) Close() error {
	l.closeCalls++
	return nil
}
