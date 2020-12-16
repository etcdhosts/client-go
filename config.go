package client

import (
	"time"
)

type Config struct {
	CA          string        `json:"ca" yaml:"ca"`
	Cert        string        `json:"cert" yaml:"cert"`
	Key         string        `json:"key" yaml:"key"`
	UserName    string        `json:"user_name" yaml:"user_name"`
	Password    string        `json:"password" yaml:"password"`
	Endpoints   []string      `json:"endpoints" yaml:"endpoints"`
	HostsKey    string        `json:"hosts_key" yaml:"hosts_key"`
	DialTimeout time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	ReqTimeout  time.Duration `json:"req_timeout" yaml:"req_timeout"`
}
