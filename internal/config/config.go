package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	WebhookURL          string   `yaml:"webhook_url"`
	Token               string   `yaml:"ultrapki_token",omitempty`
	ScanIntervalSeconds int      `yaml:"scan_interval_seconds"`
	ScanThrottleDelayMs int      `yaml:"scan_throttle_delay_ms"`
	EnableIPv6Discovery bool     `yaml:"enable_ipv6_discovery"`
	Ports               []int    `yaml:"ports"`
	StaticHosts         []string `yaml:"static_hosts"`
	Debug               bool     `yaml:"debug"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
