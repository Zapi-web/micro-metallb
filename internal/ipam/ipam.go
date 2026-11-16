package ipam

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

type Allocator struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	base    netip.Addr
	next    uint64
	size    uint64
	keyToIp map[string]netip.Addr
	ipToKey map[netip.Addr]string
}

func New(prefix netip.Prefix) (*Allocator, error) {
	if !prefix.IsValid() {
		return nil, errors.New("invalid IP prefix")
	}

	prefix = prefix.Masked()
	shift := uint(prefix.Addr().BitLen()) - uint(prefix.Bits())
	if shift > 63 {
		return nil, errors.New("prefix pool is too large (max 2^63 addresses)")
	}
	return &Allocator{
		prefix:  prefix,
		base:    prefix.Addr(),
		size:    1 << shift,
		keyToIp: make(map[string]netip.Addr),
		ipToKey: make(map[netip.Addr]string),
	}, nil
}

func (a *Allocator) Allocate(key string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip, ok := a.keyToIp[key]; ok {
		return ip, nil
	}

	for i := uint64(0); i < a.size; i++ {
		off := (a.next + i) % a.size
		ip := a.offsetToAddr(off)

		if _, taken := a.ipToKey[ip]; taken {
			continue
		}

		a.keyToIp[key] = ip
		a.ipToKey[ip] = key
		a.next = (off + 1) % a.size
		return ip, nil
	}

	return netip.Addr{}, errors.New("allocator is full")
}

func (a *Allocator) Release(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	ip, ok := a.keyToIp[key]
	if !ok {
		return
	}

	delete(a.keyToIp, key)
	delete(a.ipToKey, ip)

	if off, ok := a.addrToOffset(ip); ok && off < a.next {
		a.next = off
	}
}

func (a *Allocator) offsetToAddr(off uint64) netip.Addr {
	b := a.base.As16()
	low := binary.BigEndian.Uint64(b[8:])
	binary.BigEndian.PutUint64(b[8:], low+off)
	return netip.AddrFrom16(b).Unmap()
}

func (a *Allocator) addrToOffset(ip netip.Addr) (uint64, bool) {
	if !a.prefix.Contains(ip) {
		return 0, false
	}

	baseBytes := a.base.As16()
	ipBytes := ip.As16()

	baseLow := binary.BigEndian.Uint64(baseBytes[8:])
	ipLow := binary.BigEndian.Uint64(ipBytes[8:])

	return ipLow - baseLow, true
}
