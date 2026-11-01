// Package dutproto is the frame protocol between a test tool and a DUT process: a tool sends one
// request frame on the process's standard input and reads one response frame from its standard
// output, as docs/design/v2/test-tooling.md section 3 and its appendix define. The frames carry a
// TCP/IP engine's packets, clock and socket operations, so internal/tcpharness/rustdut can drive
// an engine in another process, the Rust wgstack or the Go wgstack's dutserve, and so the same
// frames can serve as a recording of one engine to replay against another.
//
// The package imports nothing from the module, so internal/wgstack's tests can import it without
// a cycle.
package dutproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version HELLO carries. A DUT refuses any other.
const Version = 1

// MaxFrame bounds a frame's length field: the kind byte and the body. A larger length is a
// protocol error, so a corrupt stream cannot make a reader allocate without bound.
const MaxFrame = 64 << 20

// ErrProtocol marks a malformed frame or body.
var ErrProtocol = errors.New("dutproto: protocol error")

func protoErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, args...))
}

// WriteFrame writes one frame: the length of the kind and the body as a little-endian u32, the
// kind, and the body.
func WriteFrame(w io.Writer, k Kind, body []byte) error {
	if 1+len(body) > MaxFrame {
		return protoErr("frame of %d bytes exceeds %d", 1+len(body), MaxFrame)
	}
	var hdr [5]byte
	binary.LittleEndian.PutUint32(hdr[:4], uint32(1+len(body)))
	hdr[4] = byte(k)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// ReadFrame reads one frame. It returns io.EOF only when the stream ends on a frame boundary, and
// io.ErrUnexpectedEOF when it ends inside a frame.
func ReadFrame(r io.Reader) (Kind, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:4]); err != nil {
		return 0, nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:4])
	if n == 0 || n > MaxFrame {
		return 0, nil, protoErr("frame length %d out of range 1 to %d", n, MaxFrame)
	}
	if _, err := io.ReadFull(r, hdr[4:5]); err != nil {
		return 0, nil, unexpected(err)
	}
	body := make([]byte, n-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, unexpected(err)
	}
	return Kind(hdr[4]), body, nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// WriteMsg encodes m and writes it as one frame.
func WriteMsg(w io.Writer, m Msg) error {
	body, err := Encode(m)
	if err != nil {
		return err
	}
	return WriteFrame(w, m.Kind(), body)
}

// ReadMsg reads one frame and decodes it.
func ReadMsg(r io.Reader) (Msg, error) {
	k, body, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	return Decode(k, body)
}

// Frame returns m as one frame, or Encode's error.
func Frame(m Msg) ([]byte, error) {
	body, err := Encode(m)
	if err != nil {
		return nil, err
	}
	b := binary.LittleEndian.AppendUint32(nil, uint32(1+len(body)))
	b = append(b, byte(m.Kind()))
	return append(b, body...), nil
}

// AppendFrame appends m as one frame to b. It is for messages the caller built from values it
// knows the body can carry, and panics with Encode's error otherwise; Frame returns the error.
func AppendFrame(b []byte, m Msg) []byte {
	body, err := Encode(m)
	if err != nil {
		panic(err)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(1+len(body)))
	b = append(b, byte(m.Kind()))
	return append(b, body...)
}

// Conn is one side of a frame stream with buffered I/O.
type Conn struct {
	r *bufio.Reader
	w *bufio.Writer
}

// NewConn wraps r and w.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 64<<10), w: bufio.NewWriterSize(w, 64<<10)}
}

// Send writes m and flushes.
func (c *Conn) Send(m Msg) error {
	if err := WriteMsg(c.w, m); err != nil {
		return err
	}
	return c.w.Flush()
}

// SendRaw writes one frame already encoded by AppendFrame and flushes.
func (c *Conn) SendRaw(frame []byte) error {
	if _, err := c.w.Write(frame); err != nil {
		return err
	}
	return c.w.Flush()
}

// ReadRaw reads one frame and returns its kind and body.
func (c *Conn) ReadRaw() (Kind, []byte, error) { return ReadFrame(c.r) }

// Recv reads and decodes one frame.
func (c *Conn) Recv() (Msg, error) { return ReadMsg(c.r) }
