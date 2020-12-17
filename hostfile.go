package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
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

// HostsFile contains known host entries.
type HostsFile struct {
	sync.RWMutex

	// hosts maps for lookups
	hmap *Map

	// version are only read and modified by a single goroutine
	version int64
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

// String sort the hosts map and format it as a human-readable string
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

// parse2Map reads the hostsfile and populates the byName and addr maps.
func parse2Map(r io.Reader) *Map {
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
func (h *HostsFile) lookupStaticHost(m map[string][]net.IP, host string) []net.IP {
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
func (h *HostsFile) LookupStaticHostV4(host string) []net.IP {
	host = strings.ToLower(host)
	return h.lookupStaticHost(h.hmap.name4, host)
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the hosts file.
func (h *HostsFile) LookupStaticHostV6(host string) []net.IP {
	host = strings.ToLower(host)
	return h.lookupStaticHost(h.hmap.name6, host)
}

// LookupStaticAddr looks up the hosts for the given address from the hosts file.
func (h *HostsFile) LookupStaticAddr(addr string) []string {
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

// AddHost add a record to the hosts map
func (h *HostsFile) AddHost(host, ip string) error {
	newIP := net.ParseIP(ip)
	if newIP == nil {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	lowerHost := Name(strings.ToLower(host)).Normalize()
	if newIP.To4() != nil {
		ips4 := h.LookupStaticHostV4(lowerHost)
		for _, hip := range ips4 {
			if hip.Equal(newIP) {
				return fmt.Errorf("host [%s:%s] already exists", host, ip)
			}
		}
		h.Lock()
		h.hmap.name4[lowerHost] = append(h.hmap.name4[lowerHost], newIP)
		h.Unlock()
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
	}
	return nil
}

// DelHost delete exactly one record from the hosts map
func (h *HostsFile) DelHost(host, ip string) error {
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
				return nil
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
				return nil
			}
		}
	}
	return fmt.Errorf("host [%s:%s] not found", host, ip)
}

// PurgeHost delete all records of a given host from the hosts map
func (h *HostsFile) PurgeHost(host string) {
	lowerHost := Name(strings.ToLower(host)).Normalize()
	if _, ok := h.hmap.name4[lowerHost]; ok {
		h.Lock()
		h.hmap.name4[lowerHost] = nil
		h.Unlock()
	}

	if _, ok := h.hmap.name6[lowerHost]; ok {
		h.Lock()
		h.hmap.name6[lowerHost] = nil
		h.Unlock()
	}
}

// SearchHost search all IPs matching the given host from the hosts map
func (h *HostsFile) SearchHost(host string) []net.IP {
	var ips []net.IP
	lowerHost := Name(strings.ToLower(host)).Normalize()
	if _, ok := h.hmap.name4[lowerHost]; ok {
		ips = append(ips, h.hmap.name4[lowerHost]...)
	}

	if _, ok := h.hmap.name6[lowerHost]; ok {
		ips = append(ips, h.hmap.name6[lowerHost]...)
	}

	return ips
}

// String return hosts map string
func (h *HostsFile) String() string {
	return h.hmap.String()
}
