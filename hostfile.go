package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/go-homedir"

	"github.com/mritd/logger"
	"go.etcd.io/etcd/clientv3"
)

// Map contains the IPv4/IPv6 and reverse mapping.
type Map struct {
	// Key for the list of literal IP addresses must be a FQDN lowercased host name.
	name4 map[string][]net.IP
	name6 map[string][]net.IP

	// Key for the list of host names must be a literal IP address
	// including IPv6 address without zone identifier.
	// We don't support old-classful IP address notation.
	addr map[string][]string
}

// Hostsfile contains known host entries.
type Hostsfile struct {
	sync.RWMutex

	// hosts maps for lookups
	hmap *Map

	// etcd v3 client
	etcdClient *clientv3.Client

	// etcd client timeout
	etcdTimeout time.Duration

	// etcd key
	etcdHostsKey string

	// etcdKeyVersion are only read and modified by a single goroutine
	etcdKeyVersion int64
}

func newMap() *Map {
	return &Map{
		name4: make(map[string][]net.IP),
		name6: make(map[string][]net.IP),
		addr:  make(map[string][]string),
	}
}

// Len returns the total number of addresses in the hostmap, this includes V4/V6 and any reverse addresses.
func (hm *Map) Len() int {
	l := 0
	for _, v4 := range hm.name4 {
		l += len(v4)
	}
	for _, v6 := range hm.name6 {
		l += len(v6)
	}
	for _, a := range hm.addr {
		l += len(a)
	}
	return l
}

func (hm *Map) String() string {
	var hosts HostList
	for k4, v4 := range hm.name4 {
		for _, ip4 := range v4 {
			hosts = append(hosts, &Hostname{
				Domain: k4,
				IP:     ip4,
				IPv6:   false,
			})
		}
	}

	for k6, v6 := range hm.name6 {
		for _, ip6 := range v6 {
			hosts = append(hosts, &Hostname{
				Domain: k6,
				IP:     ip6,
				IPv6:   true,
			})
		}
	}

	sort.Sort(hosts)

	var buf bytes.Buffer
	for _, h := range hosts {
		buf.WriteString(fmt.Sprintf("%-32s%s\n", h.IP, h.Domain))
	}
	return buf.String()
}

// parseIP calls discards any v6 zone info, before calling net.ParseIP.
func parseIP(addr string) net.IP {
	if i := strings.Index(addr, "%"); i >= 0 {
		// discard ipv6 zone
		addr = addr[0:i]
	}
	return net.ParseIP(addr)
}

func (h *Hostsfile) ReadHosts() {
	ctx, cancel := context.WithTimeout(context.Background(), h.etcdTimeout)
	defer cancel()
	getResp, err := h.etcdClient.Get(ctx, h.etcdHostsKey)
	if err != nil {
		logger.Errorf("failed to get etcd key [%s]: %s", h.etcdHostsKey, err.Error())
		return
	}

	if len(getResp.Kvs) != 1 {
		logger.Errorf("invalid etcd response: %d", len(getResp.Kvs))
		return
	}

	h.RLock()
	version := h.etcdKeyVersion
	h.RUnlock()

	// if version not changed, skip reading
	if version == getResp.Kvs[0].Version {
		return
	}

	newMap := h.Parse(bytes.NewReader(getResp.Kvs[0].Value))
	logger.Debugf("Parsed hosts file into %d entries", newMap.Len())

	h.Lock()
	h.hmap = newMap
	// Update the data cache.
	h.etcdKeyVersion = getResp.Kvs[0].Version
	h.Unlock()
}

// Parse reads the hostsfile and populates the byName and addr maps.
func (h *Hostsfile) Parse(r io.Reader) *Map {
	hmap := newMap()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if i := bytes.Index(line, []byte{'#'}); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := bytes.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr := parseIP(string(f[0]))
		if addr == nil {
			continue
		}

		family := 0
		if addr.To4() != nil {
			family = 1
		} else {
			family = 2
		}

		for i := 1; i < len(f); i++ {
			name := Name(f[i]).Normalize()
			switch family {
			case 1:
				hmap.name4[name] = append(hmap.name4[name], addr)
			case 2:
				hmap.name6[name] = append(hmap.name6[name], addr)
			default:
				continue
			}
			hmap.addr[addr.String()] = append(hmap.addr[addr.String()], name)
		}
	}

	return hmap
}

// lookupStaticHost looks up the IP addresses for the given host from the hosts file.
func (h *Hostsfile) lookupStaticHost(m map[string][]net.IP, host string) []net.IP {
	h.RLock()
	defer h.RUnlock()

	if len(m) == 0 {
		return nil
	}

	ips, ok := m[host]
	if !ok {
		return nil
	}
	ipsCp := make([]net.IP, len(ips))
	copy(ipsCp, ips)
	return ipsCp
}

// LookupStaticHostV4 looks up the IPv4 addresses for the given host from the hosts file.
func (h *Hostsfile) LookupStaticHostV4(host string) []net.IP {
	host = strings.ToLower(host)
	return h.lookupStaticHost(h.hmap.name4, host)
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the hosts file.
func (h *Hostsfile) LookupStaticHostV6(host string) []net.IP {
	host = strings.ToLower(host)
	return h.lookupStaticHost(h.hmap.name6, host)
}

// LookupStaticAddr looks up the hosts for the given address from the hosts file.
func (h *Hostsfile) LookupStaticAddr(addr string) []string {
	addr = parseIP(addr).String()
	if addr == "" {
		return nil
	}

	h.RLock()
	defer h.RUnlock()
	hosts := h.hmap.addr[addr]
	if len(hosts) == 0 {
		return nil
	}

	hostsCp := make([]string, len(hosts))
	copy(hostsCp, hosts)
	return hostsCp
}

func (h *Hostsfile) AddHost(host, ip string, ipv6 bool) error {
	newIP := net.ParseIP(ip)
	if newIP == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	lowerHost := Name(strings.ToLower(host)).Normalize()
	if !ipv6 {
		ips4 := h.LookupStaticHostV4(lowerHost)
		for _, hip := range ips4 {
			if hip.Equal(newIP) {
				return fmt.Errorf("host [%s:%s] already exists", host, ip)
			}
		}
		h.Lock()
		h.hmap.name4[lowerHost] = append(h.hmap.name4[lowerHost], newIP)
		h.Unlock()
		return h.flush()
	} else {
		ips6 := h.LookupStaticHostV4(lowerHost)
		for _, hip := range ips6 {
			if hip.Equal(newIP) {
				return fmt.Errorf("host [%s:%s] already exists", host, ip)
			}
		}
		h.Lock()
		h.hmap.name6[lowerHost] = append(h.hmap.name6[lowerHost], newIP)
		h.Unlock()
		return h.flush()
	}
}

func (h *Hostsfile) DelHost(host, ip string) error {
	delIP := net.ParseIP(ip)
	if delIP == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	lowerHost := Name(strings.ToLower(host)).Normalize()
	if delIP.To4() != nil {
		ips4 := h.LookupStaticHostV4(lowerHost)
		for i, hip := range ips4 {
			if hip.Equal(delIP) {
				h.Lock()
				h.hmap.name4[lowerHost][i] = h.hmap.name4[lowerHost][len(ips4)-1]
				h.hmap.name4[lowerHost][len(ips4)-1] = nil
				h.hmap.name4[lowerHost] = h.hmap.name4[lowerHost][:len(ips4)-1]
				h.Unlock()
				return h.flush()
			}
		}
	} else {
		ips6 := h.LookupStaticHostV6(lowerHost)
		for i, hip := range ips6 {
			if hip.Equal(delIP) {
				h.Lock()
				h.hmap.name6[lowerHost][i] = h.hmap.name6[lowerHost][len(ips6)-1]
				h.hmap.name6[lowerHost][len(ips6)-1] = nil
				h.hmap.name6[lowerHost] = h.hmap.name6[lowerHost][:len(ips6)-1]
				h.Unlock()
				return h.flush()
			}
		}
	}
	return fmt.Errorf("host [%s:%s] not found", host, ip)
}

func (h *Hostsfile) flush() error {
	ctx, cancel := context.WithTimeout(context.Background(), h.etcdTimeout)
	defer cancel()

	h.Lock()
	_, err := h.etcdClient.Put(ctx, h.etcdHostsKey, h.hmap.String())
	h.Unlock()
	defer h.ReadHosts()
	return err
}

func NewHostFile(c EtcdConfig) (*Hostsfile, error) {
	if c.Cert == "" || c.Key == "" {
		return nil, errors.New("[etcd] certs config is empty")
	}

	if len(c.Endpoints) < 1 {
		return nil, errors.New("[etcd] endpoints config is empty")
	}

	var caBs, certBs, keyBs []byte

	// if config is filepath, replace "~" to real home dir
	home, err := homedir.Dir()
	if err != nil {
		return nil, fmt.Errorf("[etcd] failed to get home dir: %w", err)
	}

	if strings.HasPrefix(c.CA, "~") {
		c.CA = strings.Replace(c.CA, "~", home, 1)
	}
	if strings.HasPrefix(c.Cert, "~") {
		c.Cert = strings.Replace(c.Cert, "~", home, 1)
	}
	if strings.HasPrefix(c.Key, "~") {
		c.Key = strings.Replace(c.Key, "~", home, 1)
	}

	// check config is base64 data or filepath
	_, err = os.Stat(c.Cert)
	if err == nil {
		certBs, err = ioutil.ReadFile(c.Cert)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] read cert file %s failed: %w", c.Cert, err)
		}
	} else {
		certBs, err = base64.StdEncoding.DecodeString(c.Cert)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] cert base64 decode failed: %w", err)
		}
	}

	_, err = os.Stat(c.Key)
	if err == nil {
		keyBs, err = ioutil.ReadFile(c.Key)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] read key file %s failed: %w", c.Key, err)
		}
	} else {
		keyBs, err = base64.StdEncoding.DecodeString(c.Key)
		if err != nil {
			return nil, fmt.Errorf("[etcd/cert] key base64 decode failed: %w", err)
		}
	}

	etcdClientCert, err := tls.X509KeyPair(certBs, keyBs)
	if err != nil {
		return nil, fmt.Errorf("[etcd/cert] x509 error: %w", err)
	}

	var rootCertPool *x509.CertPool
	if c.CA != "" {
		_, err = os.Stat(c.CA)
		if err == nil {
			caBs, err = ioutil.ReadFile(c.CA)
			if err != nil {
				return nil, fmt.Errorf("[etcd/cert] read ca file %s failed: %w", c.CA, err)
			}
		} else {
			caBs, err = base64.StdEncoding.DecodeString(c.CA)
			if err != nil {
				return nil, fmt.Errorf("[etcd/cert] ca base64 decode failed: %w", err)
			}
		}

		rootCertPool = x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(caBs)
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   c.Endpoints,
		DialTimeout: c.DialTimeout,
		TLS: &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: []tls.Certificate{etcdClientCert},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("[etcd/client] create etcd client failed: %w", err)
	}

	return &Hostsfile{
		hmap:         newMap(),
		etcdClient:   cli,
		etcdTimeout:  c.ReqTimeout,
		etcdHostsKey: c.HostsKey,
	}, nil
}
