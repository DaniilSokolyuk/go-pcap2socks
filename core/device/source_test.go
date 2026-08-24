package device

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemSourceRoundTrip(t *testing.T) {
	src := NewMemSource(4)

	src.Inject([]byte{1, 2, 3})

	frame, err := src.ReadFrame()
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, frame)

	require.NoError(t, src.WriteFrame([]byte{4, 5}))
	assert.Equal(t, []byte{4, 5}, <-src.Outbound())
}

// TestMemSourceCopiesFrames checks callers may reuse their buffers, which both
// gVisor (which releases views after Write) and the wire pump rely on.
func TestMemSourceCopiesFrames(t *testing.T) {
	src := NewMemSource(4)

	buf := []byte{1, 2, 3}
	src.Inject(buf)
	buf[0] = 9

	frame, err := src.ReadFrame()
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, frame, "injected frames must be copied")

	out := []byte{7, 8}
	require.NoError(t, src.WriteFrame(out))
	out[0] = 9
	assert.Equal(t, []byte{7, 8}, <-src.Outbound(), "written frames must be copied")
}

// TestMemSourceCloseUnblocksReader is what stops the dispatch loop from
// spinning on a dead source.
func TestMemSourceCloseUnblocksReader(t *testing.T) {
	src := NewMemSource(1)

	done := make(chan error, 1)
	go func() {
		_, err := src.ReadFrame()
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	require.NoError(t, src.Close())

	select {
	case err := <-done:
		assert.ErrorIs(t, err, io.EOF)
	case <-time.After(2 * time.Second):
		t.Fatal("Close must unblock ReadFrame")
	}
}

func TestMemSourceCloseIsIdempotent(t *testing.T) {
	src := NewMemSource(1)
	require.NoError(t, src.Close())
	require.NoError(t, src.Close())

	assert.ErrorIs(t, src.WriteFrame([]byte{1}), io.ErrClosedPipe)

	// Injecting into a closed source drops the frame instead of blocking.
	src.Inject([]byte{1})
}
