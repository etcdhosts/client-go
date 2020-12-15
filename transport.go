package client

import (
	"strings"
)

// These transports are supported by CoreDNS.
const (
	DNS   = "dns"
	TLS   = "tls"
	GRPC  = "grpc"
	HTTPS = "https"
)

// Port numbers for the various transports.
const (
	// Port is the default port for DNS
	Port = "53"
	// TLSPort is the default port for DNS-over-TLS.
	TLSPort = "853"
	// GRPCPort is the default port for DNS-over-gRPC.
	GRPCPort = "443"
	// HTTPSPort is the default port for DNS-over-HTTPS.
	HTTPSPort = "443"
)

// Transport returns the transport defined in s and a string where the
// transport prefix is removed (if there was any). If no transport is defined
// we default to TransportDNS
func Transport(s string) (trans string, addr string) {
	switch {
	case strings.HasPrefix(s, TLS+"://"):
		s = s[len(TLS+"://"):]
		return TLS, s

	case strings.HasPrefix(s, DNS+"://"):
		s = s[len(DNS+"://"):]
		return DNS, s

	case strings.HasPrefix(s, GRPC+"://"):
		s = s[len(GRPC+"://"):]
		return GRPC, s

	case strings.HasPrefix(s, HTTPS+"://"):
		s = s[len(HTTPS+"://"):]

		return HTTPS, s
	}

	return DNS, s
}
