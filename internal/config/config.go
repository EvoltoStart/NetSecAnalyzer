package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Capture  CaptureConfig  `mapstructure:"capture"`
	Scanner  ScannerConfig  `mapstructure:"scanner"`
	Attack   AttackConfig   `mapstructure:"attack"`
	Log      LogConfig      `mapstructure:"log"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

type DatabaseConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
	DBName       string `mapstructure:"dbname"`
	Charset      string `mapstructure:"charset"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type CaptureConfig struct {
	IP    IPCaptureConfig    `mapstructure:"ip"`
	CAN   CANCaptureConfig   `mapstructure:"can"`
	RS485 RS485CaptureConfig `mapstructure:"rs485"`
}

type IPCaptureConfig struct {
	Interface  string `mapstructure:"interface"`
	Snaplen    int    `mapstructure:"snaplen"`
	Promisc    bool   `mapstructure:"promisc"`
	Timeout    int    `mapstructure:"timeout"`
	BufferSize int    `mapstructure:"buffer_size"`
}

type CANCaptureConfig struct {
	Interface  string `mapstructure:"interface"`
	BufferSize int    `mapstructure:"buffer_size"`
}

type RS485CaptureConfig struct {
	Port     string `mapstructure:"port"`
	BaudRate int    `mapstructure:"baudrate"`
	DataBits int    `mapstructure:"databits"`
	Parity   string `mapstructure:"parity"`
	StopBits int    `mapstructure:"stopbits"`
}

type ScannerConfig struct {
	MaxConcurrent int `mapstructure:"max_concurrent"`
	Timeout       int `mapstructure:"timeout"`
	RateLimit     int `mapstructure:"rate_limit"`
}

type AttackConfig struct {
	AuthorizationRequired bool `mapstructure:"authorization_required"`
	MaxRate               int  `mapstructure:"max_rate"`
}

type LogConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

var GlobalConfig *Config

func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	GlobalConfig = &config
	return &config, nil
}

func GetConfig() *Config {
	return GlobalConfig
}
