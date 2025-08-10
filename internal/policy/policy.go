package policy

import (
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
)

type Policy struct {
	ClientDays       int    `yaml:"client_days"`
	ServerDays       int    `yaml:"server_days"`
	AllowDuplicateCN bool   `yaml:"allow_duplicate_cn"`
	CNPattern        string `yaml:"cn_pattern"`
}

func Default() Policy {
	return Policy{
		ClientDays:       180,
		ServerDays:       365,
		AllowDuplicateCN: false,
		CNPattern:        `^[A-Za-z0-9._-]{3,64}$`,
	}
}

func Load(path string) (Policy, error) {
	if path == "" {
		return Default(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		// if missing, use defaults
		return Default(), nil
	}
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, err
	}
	if p.ClientDays <= 0 {
		p.ClientDays = 180
	}
	if p.ServerDays <= 0 {
		p.ServerDays = 365
	}
	if p.CNPattern == "" {
		p.CNPattern = Default().CNPattern
	}

	if _, err := regexp.Compile(p.CNPattern); err != nil {
		return Policy{}, errors.New("invalid cn_pattern regex")
	}
	return p, nil
}
