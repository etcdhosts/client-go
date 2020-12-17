package client

import (
	"time"
)

type Config struct {
	CA          string        `json:"ca,omitempty" yaml:"ca,omitempty"`
	Cert        string        `json:"cert,omitempty" yaml:"cert,omitempty"`
	Key         string        `json:"key,omitempty" yaml:"key,omitempty"`
	UserName    string        `json:"user_name,omitempty" yaml:"user_name,omitempty"`
	Password    string        `json:"password,omitempty" yaml:"password,omitempty"`
	Endpoints   []string      `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	HostsKey    string        `json:"hosts_key,omitempty" yaml:"hosts_key,omitempty"`
	DialTimeout time.Duration `json:"dial_timeout,omitempty" yaml:"dial_timeout,omitempty"`
	ReqTimeout  time.Duration `json:"req_timeout,omitempty" yaml:"req_timeout,omitempty"`
}
