package cfg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []uint16
		wantErr string
	}{
		{name: "empty", in: "", want: nil},
		{name: "blank", in: "   ", want: nil},
		{name: "single", in: "53", want: []uint16{53}},
		{name: "list", in: "53,80,443", want: []uint16{53, 80, 443}},
		{name: "list with spaces", in: " 53 , 80 ", want: []uint16{53, 80}},
		{name: "range", in: "8000-8003", want: []uint16{8000, 8001, 8002, 8003}},
		{name: "range with spaces", in: " 8000 - 8002 ", want: []uint16{8000, 8001, 8002}},
		{name: "mixed", in: "53,8000-8001", want: []uint16{53, 8000, 8001}},
		{name: "single element range", in: "80-80", want: []uint16{80}},
		{name: "boundaries", in: "0,65535", want: []uint16{0, 65535}},

		{name: "not a number", in: "http", wantErr: `invalid port "http"`},
		{name: "overflow", in: "65536", wantErr: `invalid port "65536"`},
		{name: "reversed range", in: "900-800", wantErr: "start is greater than end"},
		{name: "range overflow", in: "1-70000", wantErr: `invalid port "70000"`},
		{name: "empty element", in: "53,,80", wantErr: `invalid port ""`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePorts(tc.in)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Len(t, got, len(tc.want))
			for _, port := range tc.want {
				assert.Contains(t, got, port)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	t.Run("bare address becomes a host route", func(t *testing.T) {
		got, err := ParseCIDRs([]string{"192.168.1.1"})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "192.168.1.1/32", got[0].String())
	})

	t.Run("bare ipv6 address becomes a host route", func(t *testing.T) {
		got, err := ParseCIDRs([]string{"2001:db8::1"})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "2001:db8::1/128", got[0].String())
	})

	t.Run("prefixes are kept", func(t *testing.T) {
		got, err := ParseCIDRs([]string{"10.0.0.0/8", "172.16.0.0/12"})
		require.NoError(t, err)
		require.Len(t, got, 2)
		assert.Equal(t, "10.0.0.0/8", got[0].String())
		assert.Equal(t, "172.16.0.0/12", got[1].String())
	})

	t.Run("host bits are masked off", func(t *testing.T) {
		got, err := ParseCIDRs([]string{"10.1.2.3/8"})
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.0/8", got[0].String())
	})

	t.Run("empty input", func(t *testing.T) {
		got, err := ParseCIDRs(nil)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("invalid address", func(t *testing.T) {
		_, err := ParseCIDRs([]string{"not-an-ip"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid ip "not-an-ip"`)
	})

	t.Run("invalid prefix", func(t *testing.T) {
		_, err := ParseCIDRs([]string{"10.0.0.0/99"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid ip")
	})
}

func TestLoad(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}

	t.Run("normalizes rules", func(t *testing.T) {
		path := write(t, `{
			"pcap": {"network": "172.26.0.0/16", "localIP": "172.26.0.1"},
			"routing": {"rules": [{"dstPort": "53,8000-8001", "srcIP": ["172.26.0.5"], "outboundTag": "dns-out"}]},
			"outbounds": [{"tag": "", "direct": {}}, {"tag": "dns-out", "dns": {}}]
		}`)

		config, err := Load(path)
		require.NoError(t, err)

		require.Len(t, config.Routing.Rules, 1)
		rule := config.Routing.Rules[0]
		assert.Len(t, rule.DstPorts, 3)
		assert.Contains(t, rule.DstPorts, uint16(53))
		assert.Contains(t, rule.DstPorts, uint16(8001))
		assert.Empty(t, rule.SrcPorts)
		require.Len(t, rule.SrcIPs, 1)
		assert.Equal(t, "172.26.0.5/32", rule.SrcIPs[0].String())
	})

	t.Run("reports which rule is broken", func(t *testing.T) {
		path := write(t, `{
			"routing": {"rules": [
				{"dstPort": "53", "outboundTag": "a"},
				{"dstPort": "nope", "outboundTag": "b"}
			]},
			"outbounds": [{"tag": "", "direct": {}}]
		}`)

		_, err := Load(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "routing rule 1")
		assert.Contains(t, err.Error(), "dstPort")
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
		require.Error(t, err)
	})

	t.Run("malformed json", func(t *testing.T) {
		_, err := Load(write(t, `{"pcap":`))
		require.Error(t, err)
	})
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	assert.False(t, Exists(path))
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	assert.True(t, Exists(path))
}
