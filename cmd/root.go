package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"github.com/abhiramjoshi/cred-helper-go/pkg/vars"
	"github.com/abhiramjoshi/cred-helper-go/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	verbose bool
	environment string
	cfgFile string
	Cfg config.Config
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
		Use: vars.CliCommand,
		Short: fmt.Sprintf("%s - Generate credentials for %s", vars.CliCommand, vars.CliCommand),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				fmt.Fprintf(os.Stderr, "Using config: %s\n", viper.ConfigFileUsed())
			}
			flags := log.LstdFlags
			if Cfg.Verbose {
				flags |= log.Lshortfile
			}
			logger := log.New(os.Stderr, fmt.Sprintf("[%s]", vars.CliCommand), flags)
			
			ctx := context.WithValue(cmd.Context(), config.LoggerKey , logger)	
			ctx = context.WithValue(ctx, config.ConfigKey, Cfg)
			cmd.SetContext(ctx)
			return nil
		},
	}
	cobra.OnInitialize(initConfig)	
	rootCommand.PersistentFlags().StringVar(&cfgFile, "config", "", fmt.Sprintf("Config file (default $XDG_CONFIG_HOME/%s/config.yaml)", vars.CliCommand))
	rootCommand.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCommand.PersistentFlags().StringVarP(&environment, "environment", "env", "dev", "Environment to use")

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
	
	
	baseUrl, ok := vars.UrlMap[viper.GetString("environment")]
	if !ok {
		log.Fatalf("Unsupported value specified for --environment flag")
		os.Exit(1)
	}

	if vars.AuthorizationEndpoint == "" {
		log.Fatalf("Unsupported value specified for --environment flag")
		os.Exit(1)
	}

	if vars.TokenEndpoint == "" {
		log.Fatalf("Unsupported value specified for --environment flag")
		os.Exit(1)
	}

	Cfg = config.Config{
		Verbose: viper.GetBool("verbose"),
		BaseURL: baseUrl,
		AuthEndpoint: vars.AuthorizationEndpoint,
		TokenEndpoint: vars.TokenEndpoint,
	}
}

func GetLogger(ctx context.Context) *log.Logger {
	logger, ok := ctx.Value(config.LoggerKey).(*log.Logger)
	if !ok {
		return log.New(os.Stderr, fmt.Sprintf("[%s]", vars.CliCommand), log.LstdFlags)
	}
	return logger
}

func GetConfig(ctx context.Context) *config.Config {
	cfg, ok := ctx.Value(config.ConfigKey).(*config.Config)
	if !ok {
		return &config.Config{}
	}
	return cfg
}
