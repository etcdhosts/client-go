package client

import "net"

type Hostname struct {
	Domain string `json:"domain"`
	IP     net.IP `json:"ip"`
	IPv6   bool   `json:"-"`
}

type HostList []*Hostname

// MakeSurrogateIP takes an IP like 127.0.0.1 and munges it to 0.0.0.1 so we can
// sort it more easily. Note that we don't actually want to change the value,
// so we use value copies here (not pointers).
func MakeSurrogateIP(IP net.IP) net.IP {
	if len(IP.String()) > 3 && IP.String()[0:3] == "127" {
		return net.ParseIP("0" + IP.String()[3:])
	}
	return IP
}

// Len returns the number of Hostnames in the list, part of sort.Interface
func (h HostList) Len() int {
	return len(h)
}

// Swap changes the position of two Hostnames, part of sort.Interface
func (h HostList) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

// Less determines the sort order of two Hostnames, part of sort.Interface
func (h HostList) Less(A, B int) bool {
	// Sort IPv4 before IPv6
	// A is IPv4 and B is IPv6. A wins!
	if !h[A].IPv6 && h[B].IPv6 {
		return true
	}
	// A is IPv6 but B is IPv4. A loses!
	if h[A].IPv6 && !h[B].IPv6 {
		return false
	}

	// Sort "localhost" at the top
	if h[A].Domain == "localhost" {
		return true
	}
	if h[B].Domain == "localhost" {
		return false
	}

	// Compare the the IP addresses (byte array)
	// We want to push 127. to the top so we're going to mark it zero.
	surrogateA := MakeSurrogateIP(h[A].IP)
	surrogateB := MakeSurrogateIP(h[B].IP)
	if !surrogateA.Equal(surrogateB) {
		for charIndex := range surrogateA {
			// A and B's IPs differ at this index, and A is less. A wins!
			if surrogateA[charIndex] < surrogateB[charIndex] {
				return true
			}
			// A and B's IPs differ at this index, and B is less. A loses!
			if surrogateA[charIndex] > surrogateB[charIndex] {
				return false
			}
		}
		// If we got here then the IPs are the same and we want to continue on
		// to the domain sorting section.
	}

	// Prep for sorting by domain name
	aLength := len(h[A].Domain)
	bLength := len(h[B].Domain)
	max := aLength
	if bLength > max {
		max = bLength
	}

	// Sort domains alphabetically
	// TODO: This works best if domains are lowercased. However, we do not
	// enforce lowercase because of UTF-8 domain names, which may be broken by
	// case folding. There is a way to do this correctly but it's complicated
	// so I'm not going to do it right now.
	for charIndex := 0; charIndex < max; charIndex++ {
		// This index is longer than A, so A is shorter. A wins!
		if charIndex >= aLength {
			return true
		}
		// This index is longer than B, so B is shorter. A loses!
		if charIndex >= bLength {
			return false
		}
		// A and B differ at this index and A is less. A wins!
		if h[A].Domain[charIndex] < h[B].Domain[charIndex] {
			return true
		}
		// A and B differ at this index and B is less. A loses!
		if h[A].Domain[charIndex] > h[B].Domain[charIndex] {
			return false
		}
	}

	// If we got here then A and B are the same -- by definition A is not Less
	// than B so we return false. Technically we shouldn't get here since Add
	// should not allow duplicates, but we'll guard anyway.
	return false
}
