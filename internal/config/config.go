// Package config provides configuration loading and parsing utilities for the certscan service.
//
// It defines the Config struct, which represents the application's configuration options,
// and provides a function to load configuration from a YAML file.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// IncludeEntry represents an entry in the include_list section of the configuration.
// It specifies a target host and an optional protocol.
type IncludeEntry struct {
	Target   string `yaml:"target"`
	Protocol string `yaml:"protocol,omitempty"`
}

// ExcludeCertRule represents a rule for excluding certificates based on issuer or CN.
type ExcludeCertRule struct {
	Issuer string `yaml:"issuer,omitempty"`
	CN     string `yaml:"cn,omitempty"`
	Name   string `yaml:"name,omitempty"` // Optional: for documentation
}

// Config represents the application's configuration loaded from a YAML file.
// It includes webhook settings, scan intervals, network options, and more.
type Config struct {
	WebhookURL          string            `yaml:"webhook_url"`
	Token               string            `yaml:"ultrapki_token,omitempty"`
	ScanIntervalSeconds int               `yaml:"scan_interval_seconds"`
	ScanThrottleDelayMs int               `yaml:"scan_throttle_delay_ms"`
	EnableIPv6Discovery bool              `yaml:"enable_ipv6_discovery"`
	EnableIPv4Discovery bool              `yaml:"enable_ipv4_discovery"`
	Ports               []int             `yaml:"ports"`
	IncludeList         []IncludeEntry    `yaml:"include_list"`
	ExcludeList         []string          `yaml:"exclude_list"`
	ExcludeCerts        []ExcludeCertRule `yaml:"exclude_certs"`
	Debug               bool              `yaml:"debug"`
	MachineID           string            `yaml:"machine_id,omitempty"`
	ConcurrencyLimit    int               `yaml:"concurrency_limit"`
	DialTimeoutMs       int               `yaml:"dial_timeout_ms"`
	ICMPTimeoutMs       int               `yaml:"icmp_timeout_ms"`
	HTTPTimeoutMs       int               `yaml:"http_timeout_ms"`
	WebhookTimeoutMs    int               `yaml:"webhook_timeout_ms"`
	EnableIPv6PingSweep bool              `yaml:"enable_ipv6_ping_sweep"`
	EnableIPv6NDPSweep  bool              `yaml:"enable_ipv6_ndp_sweep"`
}

const (
	DefaultConcurrency      = 10
	DefaultDialTimeoutMs    = 1000
	DefaultHTTPTimeoutMs    = 3000
	DefaultWebhookTimeoutMs = 5000
	DefaultICMPTimeoutMs    = 3000
)

// LoadConfig loads the configuration from the specified YAML file path.
// It supports migration from the deprecated 'static_hosts' field to 'include_list'.
// Returns a pointer to the Config struct and an error if loading or parsing fails.
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

	if cfg.DialTimeoutMs <= 0 {
		cfg.DialTimeoutMs = DefaultDialTimeoutMs
	}
	if cfg.HTTPTimeoutMs <= 0 {
		cfg.HTTPTimeoutMs = DefaultHTTPTimeoutMs
	}
	if cfg.WebhookTimeoutMs <= 0 {
		cfg.WebhookTimeoutMs = DefaultWebhookTimeoutMs
	}
	if cfg.ICMPTimeoutMs <= 0 {
		cfg.ICMPTimeoutMs = DefaultICMPTimeoutMs
	}
	if cfg.ConcurrencyLimit <= 0 {
		cfg.ConcurrencyLimit = DefaultConcurrency
	}
	// Ensure EnableIPv6PingSweep is false if not set in config (default behavior)
	if _, ok := raw["enable_ipv6_ping_sweep"]; !ok {
		cfg.EnableIPv6PingSweep = false
	}
	if _, ok := raw["enable_ipv6_ndp_sweep"]; !ok {
		cfg.EnableIPv6NDPSweep = false
	}
	return &cfg, nil
}
