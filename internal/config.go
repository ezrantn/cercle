package internal

import (
	"log/slog"
	"time"

	"github.com/spf13/viper"
)

func LoadConfig() *Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.sslcheck")
	viper.AddConfigPath("/etc/sslcheck")

	viper.SetDefault("timeout", 10*time.Second)
	viper.SetDefault("output_format", "text")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("insecure_skip_verify", false)

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("No configuration file found, using defaults")
	}

	return &Config{
		Timeout:            viper.GetDuration("timeout"),
		OutputFormat:       viper.GetString("output_format"),
		LogLevel:           viper.GetString("log_level"),
		InsecureSkipVerify: viper.GetBool("insecure_skip_verify"),
	}
}
