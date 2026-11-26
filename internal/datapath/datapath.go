package datapath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/zapi-web/micro-metallb/internal/domain"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Wno-missing-declarations -I/usr/include -D__TARGET_ARCH_x86" xdpLb ../../bpf/xdp.c

const maxBackends = 64

type Manager struct {
	iface     string
	objs      xdpLbObjects
	link      link.Link
	closeOnce sync.Once
}

func New(iface string) (*Manager, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to interface %q: %w", iface, err)
	}

	var objs xdpLbObjects
	if err := loadXdpLbObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load objects in memory: %w", err)
	}

	tp, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLb,
		Interface: ifi.Index,
	})

	if err != nil {
		if errObjs := objs.Close(); errObjs != nil {
			err = errors.Join(err, errObjs)
		}
		return nil, fmt.Errorf("failed to attach XDP: %w", err)
	}

	return &Manager{
		iface: iface,
		objs:  objs,
		link:  tp,
	}, nil
}

func (m *Manager) UpsertService(s domain.Service) error {
	if !s.VIP.Is4() {
		return fmt.Errorf("only IPv4 VIPs are supported, got %s", s.VIP)
	}
	if s.Protocol != domain.ProtoTCP && s.Protocol != domain.ProtoUDP {
		return fmt.Errorf("unsupported protocol %d", s.Protocol)
	}
	if len(s.Backends) == 0 || len(s.Backends) > maxBackends {
		return fmt.Errorf("backend count %d outside [1,%d]", len(s.Backends), maxBackends)
	}

	key := xdpLbLbKey{
		Vip:   ip4ToKey(s.VIP),
		Dport: bpfHtons(s.Port),
		Proto: s.Protocol,
	}

	val := xdpLbLbService{Count: uint32(len(s.Backends))}
	for i, b := range s.Backends {
		if len(b.MAC) != 6 {
			return fmt.Errorf("backend %d: MAC must be 6 bytes, got %d", i, len(b.MAC))
		}
		copy(val.Backends[i].Mac[:], b.MAC)
		val.Backends[i].TargetPort = bpfHtons(b.TargetPort)
	}

	return m.objs.LbServices.Put(&key, &val)
}

func (m *Manager) DeleteService(s domain.Service) error {
	key := xdpLbLbKey{
		Vip:   ip4ToKey(s.VIP),
		Dport: bpfHtons(s.Port),
		Proto: s.Protocol,
	}

	if err := m.objs.LbServices.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (m *Manager) SetLBMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("MAC must be 6 bytes, got %d", len(mac))
	}

	key := uint32(0)
	val := xdpLbLbMac{IsSet: 1}
	copy(val.Mac[:], mac)

	return m.objs.LbMac.Put(&key, &val)
}

func (m *Manager) Close() error {
	var err error

	m.closeOnce.Do(func() {
		if m.link != nil {
			if lErr := m.link.Close(); lErr != nil {
				err = errors.Join(err, fmt.Errorf("close tracepoint: %w", lErr))
			}
		}
		if oErr := m.objs.Close(); oErr != nil {
			err = errors.Join(err, fmt.Errorf("close bpf objects: %w", oErr))
		}
	})

	return err
}

func bpfHtons(v uint16) uint16 {
	return bits.ReverseBytes16(v)
}

func ip4ToKey(a netip.Addr) uint32 {
	b := a.As4()
	return binary.LittleEndian.Uint32(b[:])
}
