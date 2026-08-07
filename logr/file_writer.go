package logr

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logFileMaxSizeMB  = 100
	logFileMaxBackups = 5
	logFileMaxAgeDays = 7
)

var (
	fileWritersMu sync.Mutex
	fileWriters   = map[string]zapcore.WriteSyncer{}
)

// buildLoggerWithLogFile builds the logger for a file-backed configuration: it creates the
// console logger from config, tees it with a core writing to logFile, and keeps
// sampling consistent across both destinations.
// It owns the console build because sampling has to wrap the combined cores.
// Left on the config, config.Build would sample the console core alone and the
// file core added here would then sample independently, so the two destinations
// would accept different events. Sampling is therefore detached from the config
// before the build and reapplied once around the tee.
func buildLoggerWithLogFile(config zap.Config, fields []zapcore.Field, logFile string) (*zap.Logger, error) {
	sampling := config.Sampling
	config.Sampling = nil

	zapLog, err := config.Build(zap.Fields(fields...))
	if err != nil {
		return nil, err
	}

	fileCore, err := newLogFileCore(config, fields, logFile)
	if err != nil {
		return nil, fmt.Errorf("build log file core: %w", err)
	}

	return zapLog.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		combinedCore := zapcore.NewTee(core, fileCore)
		if sampling == nil {
			return combinedCore
		}

		var samplerOptions []zapcore.SamplerOption
		if sampling.Hook != nil {
			samplerOptions = append(samplerOptions, zapcore.SamplerHook(sampling.Hook))
		}
		return zapcore.NewSamplerWithOptions(
			combinedCore,
			time.Second,
			sampling.Initial,
			sampling.Thereafter,
			samplerOptions...,
		)
	})), nil
}

// newLogFileCore builds a zapcore.Core that writes to the configured log file
// through the rotating file write syncer, using a plain (non-color) level
// encoder.
func newLogFileCore(config zap.Config, fields []zapcore.Field, logFile string) (zapcore.Core, error) {
	writeSyncer, err := getFileWriteSyncer(logFile)
	if err != nil {
		return nil, fmt.Errorf("open log file output: %w", err)
	}

	encoderConfig := config.EncoderConfig
	var encoder zapcore.Encoder
	if config.Encoding == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		// This keeps ANSI color escape codes (used by the console encoder)
		// out of the persisted file so it stays readable by grep and downstream log
		// shippers.
		encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	return zapcore.NewCore(encoder, writeSyncer, config.Level).With(fields), nil
}

func getFileWriteSyncer(path string) (zapcore.WriteSyncer, error) {
	canonicalPath, err := canonicalLogFilePath(path)
	if err != nil {
		return nil, err
	}

	fileWritersMu.Lock()
	defer fileWritersMu.Unlock()
	if writer, ok := fileWriters[canonicalPath]; ok {
		return writer, nil
	}

	if err := initializeLogFile(canonicalPath); err != nil {
		return nil, err
	}
	writer := zapcore.AddSync(newRotatingWriter(canonicalPath))
	fileWriters[canonicalPath] = writer
	return writer, nil
}

func canonicalLogFilePath(path string) (string, error) {
	canonicalPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve log file path: %w", err)
	}
	return canonicalPath, nil
}

func newRotatingWriter(path string) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   path,
		MaxSize:    logFileMaxSizeMB,
		MaxBackups: logFileMaxBackups,
		MaxAge:     logFileMaxAgeDays,
		Compress:   false,
	}
}

func initializeLogFile(path string) error {
	// Fail fast at startup if the directory is missing or unwritable. Set 0644
	// so arbitrary non-root sidecars can read the active file and lumberjack
	// carries the same mode to rotated files.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log file %q: %w", path, err)
	}
	if err := file.Chmod(0644); err != nil {
		_ = file.Close()
		return fmt.Errorf("set log file %q permissions: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close initialized log file %q: %w", path, err)
	}
	return nil
}
