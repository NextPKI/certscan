package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type IncludeEntry struct {
	Target   string `yaml:"target"`
	Protocol string `yaml:"protocol,omitempty"`
}

type Config struct {
	WebhookURL          string         `yaml:"webhook_url"`
	Token               string         `yaml:"ultrapki_token",omitempty"`
	ScanIntervalSeconds int            `yaml:"scan_interval_seconds"`
	ScanThrottleDelayMs int            `yaml:"scan_throttle_delay_ms"`
	EnableIPv6Discovery bool           `yaml:"enable_ipv6_discovery"`
	Ports               []int          `yaml:"ports"`
	IncludeList         []IncludeEntry `yaml:"include_list"`
	ExcludeList         []string       `yaml:"exclude_list"`
	Debug               bool           `yaml:"debug"`
	MachineID           string         `yaml:"machine_id,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	// Unmarshal into a map first to check for deprecated static_hosts
	var raw map[string]interface{}
	err = yaml.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}
	if v, ok := raw["static_hosts"]; ok {
		fmt.Println("WARNING: 'static_hosts' is deprecated. Please use 'include_list' instead.")
		if arr, ok := v.([]interface{}); ok {
			cfg.IncludeList = make([]IncludeEntry, 0, len(arr))
			for _, entry := range arr {
				if m, ok := entry.(map[interface{}]interface{}); ok {
					var ie IncludeEntry
					if t, ok := m["target"].(string); ok {
						ie.Target = t
					}
					if p, ok := m["protocol"].(string); ok {
						ie.Protocol = p
					}
					cfg.IncludeList = append(cfg.IncludeList, ie)
				}
			}
		}
	}
	// Unmarshal as normal (will overwrite IncludeList if include_list is present)
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
