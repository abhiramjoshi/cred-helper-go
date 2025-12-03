package config

type Config struct {
	Name string
	Verbose bool
	BaseURL string
	ClientId string
	AuthEndpoint string
	TokenEndpoint string
	PollEndpoint string
}

type ctxKeyLogger struct {}
var LoggerKey = ctxKeyLogger{}

type ctxKeyConfig struct {}
var ConfigKey = ctxKeyConfig{}
