package e2e

import (
	"os"
	"testing"
	"time"

	"github.com/DaniilSokolyuk/go-pcap2socks/tunnel"
)

// TestMain shortens the UDP idle timeout so that sessions left behind by a test
// do not keep goroutines (and the test binary) alive for minutes.
func TestMain(m *testing.M) {
	tunnel.SetUDPSessionTimeout(2 * time.Second)
	os.Exit(m.Run())
}
