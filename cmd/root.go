package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abhiramjoshi/cred-helper-go/pkg/config"
	"github.com/abhiramjoshi/cred-helper-go/pkg/vars"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	verbose     bool
	environment string
	cfgFile     string
	Cfg         config.Config
	rootCommand *cobra.Command
)

func Execute() {
	if err := rootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	if vars.CliCommand == "" {
		panic("Invalid CLI configuration, command name not set")
	}
	rootCommand = &cobra.Command{
		Use:   vars.CliCommand,
		Short: fmt.Sprintf("%s - Generate credentials for %s", vars.CliCommand, vars.CliCommand),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			initConfig()
			if verbose {
				fmt.Fprintf(os.Stderr, "Using config: %s\n", viper.ConfigFileUsed())
			}
			logLevel := slog.LevelWarn
			if Cfg.Verbose {
				logLevel = slog.LevelDebug
			}
			handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: logLevel,
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
			logger := slog.New(handler)
			slog.SetDefault(logger)
			ctx := context.WithValue(cmd.Context(), config.LoggerKey, logger)
			ctx = context.WithValue(ctx, config.HandlerKey, handler)
			ctx = context.WithValue(ctx, config.ConfigKey, Cfg)
			cmd.SetContext(ctx)
			return nil
		},
	}
	// cobra.OnInitialize(initConfig)
	rootCommand.PersistentFlags().StringVar(&cfgFile, "config", "", fmt.Sprintf("Config file (default $XDG_CONFIG_HOME/%s/config.yaml)", vars.CliCommand))
	rootCommand.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCommand.PersistentFlags().StringVarP(&environment, "env", "e", "dev", "Environment to use")

	viper.BindPFlag("config", rootCommand.PersistentFlags().Lookup("config"))
	viper.BindPFlag("verbose", rootCommand.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("env", rootCommand.PersistentFlags().Lookup("env"))

	viper.SetEnvPrefix(strings.ToUpper(vars.CliCommand))
	viper.AutomaticEnv()

	rootCommand.AddCommand(login)
	rootCommand.AddCommand(refresh)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		configHome, _ := os.UserConfigDir()
		cfgDir := filepath.Join(configHome, vars.CliCommand)
		viper.AddConfigPath(cfgDir)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	_ = viper.ReadInConfig()

	baseUrl, ok := vars.UrlMap[viper.GetString("env")]
	if !ok {
		slog.Error(fmt.Sprintf("Unsupported value specified for --environment flag. Provided flag was %s. Valid option include [dev, prod]", viper.GetString("env")))
		os.Exit(1)
	}

	if vars.AuthorizationEndpoint == "" {
		slog.Error("No Authorization URL has been set")
		os.Exit(1)
	}

	if vars.TokenEndpoint == "" {
		slog.Error("No Token URL has been set")
		os.Exit(1)
	}

	Cfg = config.Config{
		Verbose:       viper.GetBool("verbose"),
		BaseURL:       baseUrl,
		ClientId:      vars.ClientId,
		AuthEndpoint:  vars.AuthorizationEndpoint,
		TokenEndpoint: vars.TokenEndpoint,
	}
}
