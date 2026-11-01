package dutproto

import (
	"fmt"
	"net/netip"
	"time"
)

// Kind is a frame's kind byte. Requests are below 0x80 and responses from 0x80 up. The numbers
// and the bodies are the appendix of docs/design/v2/test-tooling.md; a change here changes the
// appendix and testdata/frames in the same commit.
type Kind uint8

// Requests.
const (
	KindHello            Kind = 0x01
	KindInject           Kind = 0x02
	KindPoll             Kind = 0x03
	KindAdvance          Kind = 0x04
	KindNow              Kind = 0x05
	KindTCPListen        Kind = 0x06
	KindUDPListen        Kind = 0x07
	KindAccept           Kind = 0x08
	KindRead             Kind = 0x09
	KindWrite            Kind = 0x0a
	KindClose            Kind = 0x0b
	KindCloseWrite       Kind = 0x0c
	KindAbort            Kind = 0x0d
	KindCloseForDelivery Kind = 0x0e
	KindDelivered        Kind = 0x0f
	KindBoostPolicy      Kind = 0x10
	KindEvents           Kind = 0x11
	KindUDPRecv          Kind = 0x12
	KindUDPSend          Kind = 0x13
	KindPingOpen         Kind = 0x14
	KindPingSend         Kind = 0x15
	KindPingRecv         Kind = 0x16
	KindPingClose        Kind = 0x17
	KindStats            Kind = 0x18
	KindBound            Kind = 0x19
	KindHeld             Kind = 0x1a
	KindRTOAt            Kind = 0x1b
	KindConnSocket       Kind = 0x1c
)

// Responses.
const (
	KindHelloOK    Kind = 0x80
	KindOK         Kind = 0x81
	KindError      Kind = 0x82
	KindWouldBlock Kind = 0x83
	KindPackets    Kind = 0x84
	KindTime       Kind = 0x85
	KindHandle     Kind = 0x86
	KindAccepted   Kind = 0x87
	KindData       Kind = 0x88
	KindWrote      Kind = 0x89
	KindBool       Kind = 0x8a
	KindEventList  Kind = 0x8b
	KindDatagram   Kind = 0x8c
	KindText       Kind = 0x8d
	KindRTO        Kind = 0x8e
)

// IsRequest reports whether k is a request's kind.
func (k Kind) IsRequest() bool { return k < 0x80 }

func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return fmt.Sprintf("KIND_0x%02x", uint8(k))
}

var kindNames = map[Kind]string{
	KindHello: "HELLO", KindInject: "INJECT", KindPoll: "POLL", KindAdvance: "ADVANCE", KindNow: "NOW",
	KindTCPListen: "TCP_LISTEN", KindUDPListen: "UDP_LISTEN", KindAccept: "ACCEPT", KindRead: "READ",
	KindWrite: "WRITE", KindClose: "CLOSE", KindCloseWrite: "CLOSE_WRITE", KindAbort: "ABORT",
	KindCloseForDelivery: "CLOSE_FOR_DELIVERY", KindDelivered: "DELIVERED", KindBoostPolicy: "BOOST_POLICY",
	KindEvents: "EVENTS", KindUDPRecv: "UDP_RECV", KindUDPSend: "UDP_SEND", KindPingOpen: "PING_OPEN",
	KindPingSend: "PING_SEND", KindPingRecv: "PING_RECV", KindPingClose: "PING_CLOSE", KindStats: "STATS",
	KindBound: "BOUND", KindHeld: "HELD", KindRTOAt: "RTO_AT", KindConnSocket: "CONN_SOCKET",
	KindHelloOK: "HELLO_OK", KindOK: "OK", KindError: "ERROR", KindWouldBlock: "WOULD_BLOCK",
	KindPackets: "PACKETS", KindTime: "TIME", KindHandle: "HANDLE", KindAccepted: "ACCEPTED", KindData: "DATA",
	KindWrote: "WROTE", KindBool: "BOOL", KindEventList: "EVENT_LIST", KindDatagram: "DATAGRAM", KindText: "TEXT",
	KindRTO: "RTO",
}

// Handle names a listener, connection, UDP socket or ping endpoint the DUT made. The DUT numbers
// them from 1 in the order it makes them, and never reuses one; 0 is never a handle.
type Handle uint32

// Clock is HELLO's clock: fake is the clock the requests advance, real runs the engine on real
// time for qbench.
type Clock uint8

const (
	ClockFake Clock = 0
	ClockReal Clock = 1
)

// Boost is HELLO's boost policy. The values are internal/wgstack's BoostPolicy.
type Boost uint8

const (
	BoostOnDemand Boost = 0
	BoostAtAccept Boost = 1
	BoostNever    Boost = 2
)

// Congestion is HELLO's congestion control. The values are internal/wgstack's CongestionControl.
type Congestion uint8

const (
	CongestionCubic   Congestion = 0
	CongestionNewReno Congestion = 1
)

// ErrKind is an ERROR response's kind, which the client turns back into the error the engine
// returned.
type ErrKind uint8

const (
	ErrOther      ErrKind = 0
	ErrTimeout    ErrKind = 1
	ErrEOF        ErrKind = 2
	ErrClosed     ErrKind = 3
	ErrReset      ErrKind = 4
	ErrBrokenPipe ErrKind = 5
)

func (k ErrKind) String() string {
	switch k {
	case ErrOther:
		return "other"
	case ErrTimeout:
		return "timeout"
	case ErrEOF:
		return "EOF"
	case ErrClosed:
		return "closed"
	case ErrReset:
		return "reset"
	case ErrBrokenPipe:
		return "broken-pipe"
	}
	return fmt.Sprintf("kind-%d", uint8(k))
}

// SeedLen is the length of HELLO's seed.
const SeedLen = 64

// Msg is one request or response.
type Msg interface {
	Kind() Kind
	encode(e *enc)
	decode(d *dec)
}

// Encode returns m's body.
func Encode(m Msg) []byte {
	var e enc
	m.encode(&e)
	if e.b == nil {
		return []byte{}
	}
	return e.b
}

// Decode decodes a body of kind k.
func Decode(k Kind, body []byte) (Msg, error) {
	mk, ok := makers[k]
	if !ok {
		return nil, protoErr("unknown frame kind 0x%02x", uint8(k))
	}
	m := mk()
	d := dec{b: body}
	m.decode(&d)
	if err := d.done(); err != nil {
		return nil, fmt.Errorf("%s: %w", k, err)
	}
	return m, nil
}

var makers = map[Kind]func() Msg{
	KindHello: func() Msg { return &Hello{} }, KindInject: func() Msg { return &Inject{} },
	KindPoll: func() Msg { return &Poll{} }, KindAdvance: func() Msg { return &Advance{} },
	KindNow: func() Msg { return &Now{} }, KindTCPListen: func() Msg { return &TCPListen{} },
	KindUDPListen: func() Msg { return &UDPListen{} }, KindAccept: func() Msg { return &Accept{} },
	KindRead: func() Msg { return &Read{} }, KindWrite: func() Msg { return &Write{} },
	KindClose: func() Msg { return &Close{} }, KindCloseWrite: func() Msg { return &CloseWrite{} },
	KindAbort: func() Msg { return &Abort{} }, KindCloseForDelivery: func() Msg { return &CloseForDelivery{} },
	KindDelivered: func() Msg { return &Delivered{} }, KindBoostPolicy: func() Msg { return &BoostPolicy{} },
	KindEvents: func() Msg { return &Events{} }, KindUDPRecv: func() Msg { return &UDPRecv{} },
	KindUDPSend: func() Msg { return &UDPSend{} }, KindPingOpen: func() Msg { return &PingOpen{} },
	KindPingSend: func() Msg { return &PingSend{} }, KindPingRecv: func() Msg { return &PingRecv{} },
	KindPingClose: func() Msg { return &PingClose{} }, KindStats: func() Msg { return &Stats{} },
	KindBound: func() Msg { return &Bound{} }, KindHeld: func() Msg { return &Held{} },
	KindRTOAt: func() Msg { return &RTOAt{} }, KindConnSocket: func() Msg { return &ConnSocket{} },
	KindHelloOK: func() Msg { return &HelloOK{} }, KindOK: func() Msg { return &OK{} },
	KindError: func() Msg { return &Error{} }, KindWouldBlock: func() Msg { return &WouldBlock{} },
	KindPackets: func() Msg { return &Packets{} }, KindTime: func() Msg { return &Time{} },
	KindHandle: func() Msg { return &HandleResp{} }, KindAccepted: func() Msg { return &Accepted{} },
	KindData: func() Msg { return &Data{} }, KindWrote: func() Msg { return &Wrote{} },
	KindBool: func() Msg { return &Bool{} }, KindEventList: func() Msg { return &EventList{} },
	KindDatagram: func() Msg { return &Datagram{} }, KindText: func() Msg { return &Text{} },
	KindRTO: func() Msg { return &RTO{} },
}

// Limit is one entry of HELLO's limits: the name of a table size of the engine and its value.
type Limit struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

// Hello starts the session: the DUT builds its engine from it. An empty Limits asks for the
// engine's default limits.
type Hello struct {
	Version    uint16     `json:"version"`
	Clock      Clock      `json:"clock"`
	Addr       netip.Addr `json:"addr"`
	MTU        uint32     `json:"mtu"`
	Seed       Bytes      `json:"seed"`
	Limits     []Limit    `json:"limits"`
	Boost      Boost      `json:"boost"`
	Congestion Congestion `json:"congestion"`
}

func (*Hello) Kind() Kind { return KindHello }
func (m *Hello) encode(e *enc) {
	e.u16(m.Version)
	e.u8(uint8(m.Clock))
	e.addr(m.Addr)
	e.u32(m.MTU)
	var seed [SeedLen]byte
	copy(seed[:], m.Seed)
	e.b = append(e.b, seed[:]...)
	e.list(len(m.Limits))
	for _, l := range m.Limits {
		e.str(l.Name)
		e.u64(l.Value)
	}
	e.u8(uint8(m.Boost))
	e.u8(uint8(m.Congestion))
}
func (m *Hello) decode(d *dec) {
	m.Version = d.u16()
	m.Clock = Clock(d.u8())
	m.Addr = d.addr()
	m.MTU = d.u32()
	m.Seed = append(Bytes{}, d.take(SeedLen)...)
	m.Limits = []Limit{}
	for range d.list(10) {
		m.Limits = append(m.Limits, Limit{Name: d.str(), Value: d.u64()})
	}
	m.Boost = Boost(d.u8())
	m.Congestion = Congestion(d.u8())
}

// Inject hands the engine a batch of IPv4 packets, as one write from the tunnel.
type Inject struct {
	Packets []Bytes `json:"packets"`
}

func (*Inject) Kind() Kind { return KindInject }
func (m *Inject) encode(e *enc) {
	e.list(len(m.Packets))
	for _, p := range m.Packets {
		e.bytes(p)
	}
}
func (m *Inject) decode(d *dec) {
	m.Packets = []Bytes{}
	for range d.list(4) {
		m.Packets = append(m.Packets, d.bytes())
	}
}

// Poll takes up to Max packets the engine sends now.
type Poll struct {
	Max uint32 `json:"max"`
}

func (*Poll) Kind() Kind      { return KindPoll }
func (m *Poll) encode(e *enc) { e.u32(m.Max) }
func (m *Poll) decode(d *dec) { m.Max = d.u32() }

// Advance moves the fake clock forward by D and fires the timers that fall due.
type Advance struct {
	D time.Duration `json:"d"`
}

func (*Advance) Kind() Kind      { return KindAdvance }
func (m *Advance) encode(e *enc) { e.dur(m.D) }
func (m *Advance) decode(d *dec) { m.D = d.dur() }

// empty is the body of a request without fields.
type empty struct{}

func (empty) encode(*enc) {}
func (empty) decode(*dec) {}

// Now asks for the engine's clock.
type Now struct{ empty }

func (*Now) Kind() Kind { return KindNow }

// TCPListen opens a TCP listener on the DUT's address and Port.
type TCPListen struct {
	Port uint16 `json:"port"`
}

func (*TCPListen) Kind() Kind      { return KindTCPListen }
func (m *TCPListen) encode(e *enc) { e.u16(m.Port) }
func (m *TCPListen) decode(d *dec) { m.Port = d.u16() }

// UDPListen opens an unconnected UDP socket on the DUT's address and Port.
type UDPListen struct {
	Port uint16 `json:"port"`
}

func (*UDPListen) Kind() Kind      { return KindUDPListen }
func (m *UDPListen) encode(e *enc) { e.u16(m.Port) }
func (m *UDPListen) decode(d *dec) { m.Port = d.u16() }

// handleBody is the body of a request on one handle.
type handleBody struct {
	H Handle `json:"h"`
}

func (m *handleBody) encode(e *enc) { e.handle(m.H) }
func (m *handleBody) decode(d *dec) { m.H = d.handle() }

// Accept takes the listener's next established connection without waiting.
type Accept struct{ handleBody }

func (*Accept) Kind() Kind { return KindAccept }

// Read reads up to Max bytes from a connection without waiting.
type Read struct {
	H   Handle `json:"h"`
	Max uint32 `json:"max"`
}

func (*Read) Kind() Kind { return KindRead }
func (m *Read) encode(e *enc) {
	e.handle(m.H)
	e.u32(m.Max)
}
func (m *Read) decode(d *dec) {
	m.H = d.handle()
	m.Max = d.u32()
}

// Write writes what the connection takes now of Data.
type Write struct {
	H    Handle `json:"h"`
	Data Bytes  `json:"data"`
}

func (*Write) Kind() Kind { return KindWrite }
func (m *Write) encode(e *enc) {
	e.handle(m.H)
	e.bytes(m.Data)
}
func (m *Write) decode(d *dec) {
	m.H = d.handle()
	m.Data = d.bytes()
}

// Close closes a listener, connection or UDP socket.
type Close struct{ handleBody }

func (*Close) Kind() Kind { return KindClose }

// CloseWrite closes a connection's sending direction.
type CloseWrite struct{ handleBody }

func (*CloseWrite) Kind() Kind { return KindCloseWrite }

// Abort closes a connection with a RST.
type Abort struct{ handleBody }

func (*Abort) Kind() Kind { return KindAbort }

// CloseForDelivery closes a connection that keeps its slot until it has delivered its data.
type CloseForDelivery struct{ handleBody }

func (*CloseForDelivery) Kind() Kind { return KindCloseForDelivery }

// Delivered asks whether a closed connection has delivered everything it had to send.
type Delivered struct{ handleBody }

func (*Delivered) Kind() Kind { return KindDelivered }

// BoostPolicy registers the connection's boost hook. The hook answers Floor when the engine asks
// whether the connection may go back to its floor buffers; false keeps the boost. The response
// says whether the connection has its boost now, and later changes come from EVENTS.
type BoostPolicy struct {
	H     Handle `json:"h"`
	Floor bool   `json:"floor"`
}

func (*BoostPolicy) Kind() Kind { return KindBoostPolicy }
func (m *BoostPolicy) encode(e *enc) {
	e.handle(m.H)
	e.bool(m.Floor)
}
func (m *BoostPolicy) decode(d *dec) {
	m.H = d.handle()
	m.Floor = d.bool()
}

// Events takes the boost changes the hooks saw since the last EVENTS.
type Events struct{ empty }

func (*Events) Kind() Kind { return KindEvents }

// UDPRecv takes the socket's next datagram, cut to Max bytes, without waiting.
type UDPRecv struct {
	H   Handle `json:"h"`
	Max uint32 `json:"max"`
}

func (*UDPRecv) Kind() Kind { return KindUDPRecv }
func (m *UDPRecv) encode(e *enc) {
	e.handle(m.H)
	e.u32(m.Max)
}
func (m *UDPRecv) decode(d *dec) {
	m.H = d.handle()
	m.Max = d.u32()
}

// UDPSend sends Data to To from the socket, if the engine takes it without waiting.
type UDPSend struct {
	H    Handle         `json:"h"`
	To   netip.AddrPort `json:"to"`
	Data Bytes          `json:"data"`
}

func (*UDPSend) Kind() Kind { return KindUDPSend }
func (m *UDPSend) encode(e *enc) {
	e.handle(m.H)
	e.addrPort(m.To)
	e.bytes(m.Data)
}
func (m *UDPSend) decode(d *dec) {
	m.H = d.handle()
	m.To = d.addrPort()
	m.Data = d.bytes()
}

// PingOpen opens an ICMP echo endpoint from the DUT's address to To.
type PingOpen struct {
	To netip.Addr `json:"to"`
}

func (*PingOpen) Kind() Kind      { return KindPingOpen }
func (m *PingOpen) encode(e *enc) { e.addr(m.To) }
func (m *PingOpen) decode(d *dec) { m.To = d.addr() }

// PingSend sends the ICMP echo request message Data from the endpoint.
type PingSend struct {
	H    Handle `json:"h"`
	Data Bytes  `json:"data"`
}

func (*PingSend) Kind() Kind { return KindPingSend }
func (m *PingSend) encode(e *enc) {
	e.handle(m.H)
	e.bytes(m.Data)
}
func (m *PingSend) decode(d *dec) {
	m.H = d.handle()
	m.Data = d.bytes()
}

// PingRecv takes the endpoint's reply message, cut to Max bytes, without waiting.
type PingRecv struct {
	H   Handle `json:"h"`
	Max uint32 `json:"max"`
}

func (*PingRecv) Kind() Kind { return KindPingRecv }
func (m *PingRecv) encode(e *enc) {
	e.handle(m.H)
	e.u32(m.Max)
}
func (m *PingRecv) decode(d *dec) {
	m.H = d.handle()
	m.Max = d.u32()
}

// PingClose closes an echo endpoint.
type PingClose struct{ handleBody }

func (*PingClose) Kind() Kind { return KindPingClose }

// Stats asks for the engine's counters as key=value text.
type Stats struct{ empty }

func (*Stats) Kind() Kind { return KindStats }

// Bound asks for the values of the engine's memory bound as key=value text.
type Bound struct{ empty }

func (*Bound) Kind() Kind { return KindBound }

// Held asks for what the engine holds now as key=value text.
type Held struct{ empty }

func (*Held) Kind() Kind { return KindHeld }

// RTOAt asks for the RTO the connection used at At. Only a DUT on --clock real answers it.
type RTOAt struct {
	H  Handle        `json:"h"`
	At time.Duration `json:"at"`
}

func (*RTOAt) Kind() Kind { return KindRTOAt }
func (m *RTOAt) encode(e *enc) {
	e.handle(m.H)
	e.dur(m.At)
}
func (m *RTOAt) decode(d *dec) {
	m.H = d.handle()
	m.At = d.dur()
}

// ConnSocket asks the DUT to connect to the Unix socket Path and relay the connection's bytes
// through it. Only a DUT on --clock real answers it.
type ConnSocket struct {
	H    Handle `json:"h"`
	Path string `json:"path"`
}

func (*ConnSocket) Kind() Kind { return KindConnSocket }
func (m *ConnSocket) encode(e *enc) {
	e.handle(m.H)
	e.str(m.Path)
}
func (m *ConnSocket) decode(d *dec) {
	m.H = d.handle()
	m.Path = d.str()
}

// HelloOK names the engine the DUT built.
type HelloOK struct {
	Engine  string `json:"engine"`
	Version uint16 `json:"version"`
}

func (*HelloOK) Kind() Kind { return KindHelloOK }
func (m *HelloOK) encode(e *enc) {
	e.str(m.Engine)
	e.u16(m.Version)
}
func (m *HelloOK) decode(d *dec) {
	m.Engine = d.str()
	m.Version = d.u16()
}

// OK is the response of a request that succeeded with nothing to return.
type OK struct{ empty }

func (*OK) Kind() Kind { return KindOK }

// Error is a failed request: the kind of error and the engine's message for it.
type Error struct {
	Err ErrKind `json:"err"`
	Msg string  `json:"msg"`
}

func (*Error) Kind() Kind { return KindError }
func (m *Error) encode(e *enc) {
	e.u8(uint8(m.Err))
	e.str(m.Msg)
}
func (m *Error) decode(d *dec) {
	m.Err = ErrKind(d.u8())
	m.Msg = d.str()
}

// WouldBlock says the operation would have to wait; the engine did nothing.
type WouldBlock struct{ empty }

func (*WouldBlock) Kind() Kind { return KindWouldBlock }

// Packets is POLL's response: the packets in the order the engine sends them, none when empty.
type Packets struct {
	Packets []Bytes `json:"packets"`
}

func (*Packets) Kind() Kind { return KindPackets }
func (m *Packets) encode(e *enc) {
	e.list(len(m.Packets))
	for _, p := range m.Packets {
		e.bytes(p)
	}
}
func (m *Packets) decode(d *dec) {
	m.Packets = []Bytes{}
	for range d.list(4) {
		m.Packets = append(m.Packets, d.bytes())
	}
}

// Time is the engine's clock: the time since the DUT was made.
type Time struct {
	Now time.Duration `json:"now"`
}

func (*Time) Kind() Kind      { return KindTime }
func (m *Time) encode(e *enc) { e.dur(m.Now) }
func (m *Time) decode(d *dec) { m.Now = d.dur() }

// HandleResp is the handle of what a request made.
type HandleResp struct{ handleBody }

func (*HandleResp) Kind() Kind { return KindHandle }

// Accepted is an accepted connection and its peer's address and port.
type Accepted struct {
	H      Handle         `json:"h"`
	Remote netip.AddrPort `json:"remote"`
}

func (*Accepted) Kind() Kind { return KindAccepted }
func (m *Accepted) encode(e *enc) {
	e.handle(m.H)
	e.addrPort(m.Remote)
}
func (m *Accepted) decode(d *dec) {
	m.H = d.handle()
	m.Remote = d.addrPort()
}

// Data is the bytes a read returned.
type Data struct {
	Data Bytes `json:"data"`
}

func (*Data) Kind() Kind      { return KindData }
func (m *Data) encode(e *enc) { e.bytes(m.Data) }
func (m *Data) decode(d *dec) { m.Data = d.bytes() }

// Wrote is how many bytes WRITE handed the engine; 0 means the write has to wait.
type Wrote struct {
	N uint32 `json:"n"`
}

func (*Wrote) Kind() Kind      { return KindWrote }
func (m *Wrote) encode(e *enc) { e.u32(m.N) }
func (m *Wrote) decode(d *dec) { m.N = d.u32() }

// Bool is a yes or no answer.
type Bool struct {
	V bool `json:"v"`
}

func (*Bool) Kind() Kind      { return KindBool }
func (m *Bool) encode(e *enc) { e.bool(m.V) }
func (m *Bool) decode(d *dec) { m.V = d.bool() }

// BoostEvent is one call of a connection's boost hook.
type BoostEvent struct {
	H       Handle `json:"h"`
	Boosted bool   `json:"boosted"`
}

// EventList is EVENTS' response, in the order the hooks were called.
type EventList struct {
	Events []BoostEvent `json:"events"`
}

func (*EventList) Kind() Kind { return KindEventList }
func (m *EventList) encode(e *enc) {
	e.list(len(m.Events))
	for _, v := range m.Events {
		e.handle(v.H)
		e.bool(v.Boosted)
	}
}
func (m *EventList) decode(d *dec) {
	m.Events = []BoostEvent{}
	for range d.list(5) {
		m.Events = append(m.Events, BoostEvent{H: d.handle(), Boosted: d.bool()})
	}
}

// Datagram is a received UDP datagram and its sender.
type Datagram struct {
	From netip.AddrPort `json:"from"`
	Data Bytes          `json:"data"`
}

func (*Datagram) Kind() Kind { return KindDatagram }
func (m *Datagram) encode(e *enc) {
	e.addrPort(m.From)
	e.bytes(m.Data)
}
func (m *Datagram) decode(d *dec) {
	m.From = d.addrPort()
	m.Data = d.bytes()
}

// Text is key=value pairs separated by spaces.
type Text struct {
	S string `json:"s"`
}

func (*Text) Kind() Kind      { return KindText }
func (m *Text) encode(e *enc) { e.str(m.S) }
func (m *Text) decode(d *dec) { m.S = d.str() }

// RTO is RTO_AT's response: the RTO in use at the asked time, when the DUT knows it.
type RTO struct {
	Known bool          `json:"known"`
	RTO   time.Duration `json:"rto"`
}

func (*RTO) Kind() Kind { return KindRTO }
func (m *RTO) encode(e *enc) {
	e.bool(m.Known)
	e.dur(m.RTO)
}
func (m *RTO) decode(d *dec) {
	m.Known = d.bool()
	m.RTO = d.dur()
}
