package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/abhiramjoshi/cred-helper-go/pkg/vars"
)

type Config struct {
	Name string
	Verbose bool
	BaseURL string
	ClientId string
	AuthEndpoint string
	TokenEndpoint string
	PollEndpoint string
}

type ctxKeyHandler struct {}
var HandlerKey = ctxKeyHandler{}

type ctxKeyLogger struct {}
var LoggerKey = ctxKeyLogger{}

type ctxKeyConfig struct {}
var ConfigKey = ctxKeyConfig{}

func GetLogger(ctx context.Context) *slog.Logger {
	logger, ok := ctx.Value(LoggerKey).(*slog.Logger)
	if !ok {
		handler := GetHandler(ctx)
		return slog.New(handler)
	}
	return logger
}

func GetConfig(ctx context.Context) *Config {
	cfg, ok := ctx.Value(ConfigKey).(*Config)
	if !ok {
		return &Config{}
	}
	return cfg
}

func GetHandler(ctx context.Context) *slog.TextHandler {
	handler, ok := ctx.Value(HandlerKey).(*slog.TextHandler)
	if !ok {
		return slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelWarn,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					// If it's the time key, format it like the standard log package
					if a.Key == slog.TimeKey {
						// This formats the time as "2006/01/02 15:04:05" (Date Time)
						t := a.Value.Any().(time.Time)
						a.Value = slog.StringValue(t.Format("2006/01/02 15:04:05"))
					}

					// If it's the message key, prepend the command name
					if a.Key == slog.MessageKey {
						// Prepend the command prefix
						a.Value = slog.StringValue(fmt.Sprintf("[%s] %s", vars.CliCommand, a.Value.String()))
					}

					// If AddSource is true, the source key (file:line) is added.
					// We will leave the source key name as 'source' for clarity.

					return a
				},
			})
	}
	return handler
}
