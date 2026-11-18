package ipam

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPrefix = "192.168.1.10/24"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		prefix   netip.Prefix
		wantErr  bool
		wantBase netip.Addr
		wantSize uint64
	}{
		{
			name:    "invalid prefix",
			prefix:  netip.Prefix{},
			wantErr: true,
		},
		{
			name:    "shift exceeds 63 (IPv6 pool too large)",
			prefix:  netip.MustParsePrefix("2001:db8::/64"),
			wantErr: true,
		},
		{
			name:     "valid IPv4 prefix",
			prefix:   netip.MustParsePrefix(testPrefix),
			wantErr:  false,
			wantBase: netip.MustParseAddr("192.168.1.0"),
			wantSize: 256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.prefix)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, got)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantBase, got.base)
			assert.Equal(t, tt.wantSize, got.size)
		})
	}
}

func TestAllocate(t *testing.T) {
	t.Run("allocate unique until full", func(t *testing.T) {
		testAllocator, err := New(netip.MustParsePrefix("192.168.1.10/30"))
		require.NoError(t, err)
		keys := []string{"key1", "key2", "key3", "key4", "errorKey"}
		allocated := make(map[netip.Addr]struct{}, 4)

		for i := range 4 {
			ip, err := testAllocator.Allocate(keys[i])
			require.NoError(t, err)
			require.True(t, ip.IsValid())
			require.True(t, testAllocator.prefix.Contains(ip))

			_, exists := allocated[ip]
			require.False(t, exists, "duplicated IP %v", ip)
			allocated[ip] = struct{}{}
		}

		nilIp, err := testAllocator.Allocate(keys[4])
		require.Error(t, err)
		require.Empty(t, nilIp)
	})

	t.Run("idempotent for existing key", func(t *testing.T) {
		testAllocator, err := New(netip.MustParsePrefix("192.168.1.10/30"))
		require.NoError(t, err)
		keys := []string{"key1", "key2", "key3", "key4"}

		firstIP, err := testAllocator.Allocate(keys[0])
		require.NoError(t, err)

		for i := 1; i < len(keys); i++ {
			_, err := testAllocator.Allocate(keys[i])
			require.NoError(t, err)
		}

		secondIP, err := testAllocator.Allocate(keys[0])
		require.NoError(t, err)
		require.Equal(t, firstIP, secondIP)
	})
}

func TestAllocate_Concurrency(t *testing.T) {
	const workers = 2048
	testAllocator, err := New(netip.MustParsePrefix("192.168.1.10/21"))
	require.NoError(t, err)

	var wg sync.WaitGroup
	start := make(chan struct{})
	ips := make([]netip.Addr, workers)
	errs := make([]error, workers)

	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			ips[id], errs[id] = testAllocator.Allocate(fmt.Sprintf("key-%d", id))
		}(i)
	}

	close(start)
	wg.Wait()

	seen := make(map[netip.Addr]struct{}, workers)
	for i := range workers {
		require.NoError(t, errs[i])
		require.NotContains(t, seen, ips[i])
		seen[ips[i]] = struct{}{}
	}
}

func TestRelease(t *testing.T) {
	t.Run("frees address and reuses lowest offset", func(t *testing.T) {
		testAllocator, err := New(netip.MustParsePrefix("192.168.1.0/30"))
		require.NoError(t, err)

		ip1, err := testAllocator.Allocate("key1")
		require.NoError(t, err)
		ip2, err := testAllocator.Allocate("key2")
		require.NoError(t, err)
		_, err = testAllocator.Allocate("key3")
		require.NoError(t, err)
		_, err = testAllocator.Allocate("key4")
		require.NoError(t, err)

		testAllocator.Release("key2")
		testAllocator.Release("key1")

		reused1, err := testAllocator.Allocate("newKey1")
		require.NoError(t, err)
		assert.Equal(t, ip1, reused1)

		reused2, err := testAllocator.Allocate("newKey2")
		require.NoError(t, err)
		assert.Equal(t, ip2, reused2)
	})

	t.Run("releasing unknown or already released key is safe no-op", func(t *testing.T) {
		testAllocator, err := New(netip.MustParsePrefix("192.168.1.0/30"))
		require.NoError(t, err)

		ip1, err := testAllocator.Allocate("key1")
		require.NoError(t, err)

		require.NotPanics(t, func() {
			testAllocator.Release("non-existent")
			testAllocator.Release("key1")
			testAllocator.Release("key1")
		})

		reused, err := testAllocator.Allocate("key2")
		require.NoError(t, err)
		assert.Equal(t, ip1, reused)
	})
}

func TestOffsetToAddr(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		offset  uint64
		wantRes netip.Addr
	}{
		{
			name:    "IPv4 zero offset (network address)",
			prefix:  testPrefix,
			offset:  0,
			wantRes: netip.MustParseAddr("192.168.1.0"),
		},
		{
			name:    "IPv4 standard offset",
			prefix:  testPrefix,
			offset:  42,
			wantRes: netip.MustParseAddr("192.168.1.42"),
		},
		{
			name:    "IPv4 carry across octets (/16)",
			prefix:  "10.0.0.0/16",
			offset:  258, // 1*256 + 2
			wantRes: netip.MustParseAddr("10.0.1.2"),
		},
		{
			name:    "IPv6 large offset (/65)",
			prefix:  "2001:db8::/65",
			offset:  (1 << 62) + 15,
			wantRes: netip.MustParseAddr("2001:db8::4000:0:0:f"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAllocator, err := New(netip.MustParsePrefix(tt.prefix))
			require.NoError(t, err)
			assert.Equal(t, tt.wantRes, testAllocator.offsetToAddr(tt.offset))
		})
	}
}

func TestAddrToOffset(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		addr       netip.Addr
		wantOffset uint64
		wantBool   bool
	}{
		{
			name:       "IPv4 base address (offset 0)",
			prefix:     "192.168.1.0/24",
			addr:       netip.MustParseAddr("192.168.1.0"),
			wantOffset: 0,
			wantBool:   true,
		},
		{
			name:       "IPv4 address inside subnet across octets",
			prefix:     "10.0.0.0/16",
			addr:       netip.MustParseAddr("10.0.1.2"),
			wantOffset: 258,
			wantBool:   true,
		},
		{
			name:       "IPv4 broadcast address (last in subnet)",
			prefix:     "192.168.1.0/24",
			addr:       netip.MustParseAddr("192.168.1.255"),
			wantOffset: 255,
			wantBool:   true,
		},
		{
			name:       "IPv4 out of prefix range",
			prefix:     "192.168.1.0/24",
			addr:       netip.MustParseAddr("192.168.2.1"),
			wantOffset: 0,
			wantBool:   false,
		},
		{
			name:       "IPv4-mapped IPv6 address against IPv4 prefix",
			prefix:     "192.168.1.0/24",
			addr:       netip.MustParseAddr("::ffff:192.168.1.10"),
			wantOffset: 0,
			wantBool:   false,
		},
		{
			name:       "IPv6 address with large offset (/65)",
			prefix:     "2001:db8::/65",
			addr:       netip.MustParseAddr("2001:db8::4000:0:0:f"),
			wantOffset: (1 << 62) + 15,
			wantBool:   true,
		},
		{
			name:       "IPv6 out of /65 range (65th bit is 1)",
			prefix:     "2001:db8::/65",
			addr:       netip.MustParseAddr("2001:db8::8000:0:0:1"),
			wantOffset: 0,
			wantBool:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testAllocator, err := New(netip.MustParsePrefix(tt.prefix))
			require.NoError(t, err)
			val, ok := testAllocator.addrToOffset(tt.addr)
			assert.Equal(t, tt.wantOffset, val)
			assert.Equal(t, tt.wantBool, ok)
		})
	}
}
