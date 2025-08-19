package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"radius-go/internal/config"
)

type dailyRotateWriter struct {
	mu          sync.Mutex
	rotateDaily bool
	currentDay  string
	logger      *lumberjack.Logger
}

func New(cfg config.LoggingConfig) (*zap.Logger, func() error, error) {
	if dir := filepath.Dir(cfg.File); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, nil, fmt.Errorf("create log directory: %w", err)
		}
	}

	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}

	writer := &dailyRotateWriter{
		rotateDaily: cfg.RotateDaily,
		logger: &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAgeDays,
			Compress:   cfg.Compress,
		},
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.TimeKey = "time"

	fileCore := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(writer), level)
	consoleCore := zapcore.NewCore(zapcore.NewConsoleEncoder(encoderCfg), zapcore.AddSync(os.Stdout), level)
	logger := zap.New(zapcore.NewTee(fileCore, consoleCore), zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	cleanup := func() error {
		_ = logger.Sync()
		return writer.Close()
	}
	return logger, cleanup, nil
}

func (w *dailyRotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.rotateDaily {
		day := time.Now().Format("2006-01-02")
		switch {
		case w.currentDay == "":
			w.currentDay = day
		case w.currentDay != day:
			if err := w.logger.Rotate(); err != nil {
				return 0, err
			}
			w.currentDay = day
		}
	}
	return w.logger.Write(p)
}

func (w *dailyRotateWriter) Sync() error {
	return nil
}

func (w *dailyRotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logger.Close()
}

func parseLevel(value string) (zapcore.Level, error) {
	var level zapcore.Level
	if err := level.Set(strings.ToLower(strings.TrimSpace(value))); err != nil {
		return level, fmt.Errorf("invalid logging.level: %w", err)
	}
	return level, nil
}
