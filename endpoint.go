package natTraversal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	execv "github.com/hariguchi/go-execv"
	utils "github.com/hariguchi/go-utils"
	"github.com/pion/stun/v3"
	"github.com/sirupsen/logrus"
)

type Endpoint struct {
	// Local listen port
	listenPort int
	// Tunnel interface name
	tunIf string
	// Endpoint sockaddr (<IPv4-addr>:<port> or [<IPv6-addr>]:<port>)
	// UNLESS this endpoint is behind NAT. Otherwise empty string.
	// The IP addresses of 'endpoint' is one of the interface
	// IP addresses unless this endpoint is behind NAT. In this case,
	// the port number of this endpoint is the same as 'listenPort'.
	endpoint string
	// Reflexive sockaddr (<IPv4-addr>:<port> or [<IPv6-addr>]:<port>)
	// if this endpoint is behind NAT. Otherwise empty string because
	// 'reflexive' will be the same as 'endpoint.
	reflexive string
	// UDP connection
	conn *net.UDPConn
}

type Error struct {
	Message string
	Err     error
}

type IPtypes utils.IPtypes
type STUNservers []string

const (
	IPv4 = utils.IPv4
	IPv6 = utils.IPv6

	Panic = logrus.PanicLevel
	Fatal = logrus.FatalLevel
	Err   = logrus.ErrorLevel
	Warn  = logrus.WarnLevel
	Info  = logrus.InfoLevel
	Debug = logrus.DebugLevel
	Trace = logrus.TraceLevel

	udpReadDuration = 1 * time.Second
)

// Error types
var (
	ErrCanceled   = errors.New("Canceled.")
	ErrWrongPort  = errors.New("Wrong port number.")
	ErrIfAddr     = errors.New("Failed to retrieve interface IP address(es).")
	ErrPubIP      = errors.New("Failed to retrieve a public IP address.")
	ErrListenUDP  = errors.New("Failed to open a local UDP port.")
	ErrResolvUDP  = errors.New("Failed to resolve UDP address.")
	ErrWriteUDP   = errors.New("Failed to write to a UDP peer.")
	ErrReadUDP    = errors.New("Failed to read to a UDP peer.")
	ErrTimeout    = errors.New("Timed out.")
	ErrNoEndpoint = errors.New("No endpoint information.")
	ErrNotNATted  = errors.New("Not NATted.")
	ErrSetTimeout = errors.New("Failed to set timeout.")
)

var (
	STUNsvrs = []STUNservers{
		{"stun.ekiga.net:3478", "stun.stunprotocol.org:3478"},
		{"stunserver2024.stunprotocol.org"},
	}

	stunTimeout = 5 * time.Second
	peerTimeout = 5 * time.Second
)

var (
	log      = logrus.New()
	funcName = utils.FuncName
)

func init() {
	utils.SetLogFormat(log)
}

func SetLogLevel(l logrus.Level) {
	log.SetLevel(l)
}

// Constructor for 'endpoint'.
func NewEndpoint(port int) (*Endpoint, error) {
	fn := funcName(false)

	if (port < 0) || (port > 65535) {
		return nil, &Error{
			Message: fmt.Sprintf("%s: %d: wrong port number", fn, port),
			Err:     ErrWrongPort,
		}
	}
	ep := new(Endpoint)
	ep.listenPort = port
	return ep, nil
}

func (ep *Endpoint) OpenEndpoint(ctx context.Context, ipVer utils.IPtypes) error {
	fn := funcName(false)

	var ipa netip.Addr
	ipas, err := GetPublicIP(ipVer)
	if err == nil {
		ipa, err = netip.ParseAddr(ipas)
		if err != nil {
			return &Error{
				Message: fmt.Sprintf("%s: %v", fn, err),
				Err:     ErrPubIP,
			}
		}
	}

	ifAddrsStr, err := net.InterfaceAddrs()
	if err != nil {
		return &Error{
			Message: fmt.Sprintf("%s: net.InterfaceAddrs: %v", fn, err),
			Err:     ErrIfAddr,
		}
	}
	ifAddrs := make(map[netip.Addr]bool)
	for _, ifps := range ifAddrsStr {
		ifp, err := netip.ParsePrefix(ifps.String())
		if err != nil {
			log.Errorf("netip.ParseAddr(%s)\n", ifps)

			continue
		}
		ifAddrs[ifp.Addr()] = true
	}
	if _, ok := ifAddrs[ipa]; ok {
		log.Infof("%s: This endpoint is not behind NAT.", ipas)

		if ipVer == IPv4 {
			ep.endpoint = fmt.Sprintf("%s:%d", ipas, ep.listenPort)
		} else {
			ep.endpoint = fmt.Sprintf("[%s]:%d", ipas, ep.listenPort)
		}
	} else {
		log.Infof("This endpoint is NATted.")

		err = ep.getReflexive(ctx, ipVer, "")
		if err != nil {
			return fmt.Errorf("%s: %w", fn, err)
		}
	}
	ep.conn, err = net.ListenUDP("udp", nil)
	if err != nil {
		return &Error{
			Message: fmt.Sprintf("%s: net.ListenUDP: %v", fn, err),
			Err:     ErrListenUDP,
		}
	}

	return nil
}

func (ep *Endpoint) Connect(ctx context.Context, peerCh <-chan string) error {
	fn := funcName(false)

	// Wait for the peer's reflexive information
	timeout := time.NewTicker(peerTimeout)
	defer func() {
		timeout.Stop()
	}()
	var (
		peer    *net.UDPAddr
		peerStr string
		err     error
	)
waitPeerInfo:
	for {
		select {
		case <-ctx.Done():
			// Canceled
			return &Error{
				Message: fmt.Sprintf("%s: Canceled.", fn),
				Err:     ErrCanceled,
			}
		case <-timeout.C:
			// Failed to establish a NAT Traversal
			// within 'timeout' seconds.
			return &Error{
				Message: fmt.Sprintf("%s: Timed out.", fn),
				Err:     ErrTimeout,
			}
		case peerStr = <-peerCh:
			peer, err = net.ResolveUDPAddr("udp", peerStr)
			if err != nil {
				return &Error{
					Message: fmt.Sprintf("%s: net.ResolveUDPAddr(%s): %s", fn, peerStr, err),
					Err:     ErrResolvUDP,
				}
			}
			break waitPeerInfo
		}
	}
	log.Tracef("Got peer address: %s", peerStr)

	//
	// Confirm the channel is open
	//

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	sendPong := make(chan bool)
	go sendPingPong(ctx2, ep.conn, peer, sendPong)

	fn = fmt.Sprintf("%s (%s): ", fn, peerStr)
	gotPong := false
	sentPong := false
	buf := make([]byte, 1024)
	for {
		select {
		case <-ctx.Done():
			// Canceled
			return &Error{
				Message: fmt.Sprintf("%sCanceled.", fn),
				Err:     ErrCanceled,
			}
		case <-timeout.C:
			// Failed to establish a NAT Traversal
			// within 'timeout' seconds.
			return &Error{
				Message: fmt.Sprintf("%sTimed out.", fn),
				Err:     ErrTimeout,
			}
		default:
			err = ep.conn.SetReadDeadline(time.Now().Add(udpReadDuration))
			if err != nil {
				return &Error{
					Message: fmt.Sprintf("%snet.(*UDPConn).SeatReadDeadLine: %s", fn, err),
					Err:     ErrSetTimeout,
				}
			}
			_, _, err := ep.conn.ReadFromUDP(buf)
			if err == nil {
				msg := string(buf[:])
				if msg == pingMsg {
					if sentPong == false {
						select {
						case sendPong <- true:
							sentPong = true
							log.Debugf("Rcv'ed ping. Start sending pong to %s.", peerStr)
						default:
							log.Errorf("To %s: Channel sendPong is full.", peerStr)
						}
					} else {
						log.Tracef("Rcv'ed ping from %s. Pong was already sent.", peerStr)
					}
				} else if msg == pongMsg {
					if sentPong == false {
						log.Debugf("%s received my ping before sending its ping.", peerStr)

						sentPong = true
					} else {
						log.Tracef("Rcv'ed poing from %s. Pong was already sent.", peerStr)
					}
					gotPong = true
				} else {
					log.Errorf("From %s: Unknown message: %s", peerStr, msg)
				}
			} else {
				if e, ok := err.(net.Error); !ok || !e.Timeout() {
					return &Error{
						Message: fmt.Sprintf("%sRreadFromUDP: %v", fn, err),
						Err:     ErrReadUDP,
					}
				}
				log.Errorf("UDP read timeout.")
			}
		}

		if gotPong && sentPong {
			return nil
		}
	}
	return nil
}

func (ep *Endpoint) IsNATted() bool {
	if ep.endpoint == "" {
		return true
	}
	return false
}

func (ep *Endpoint) Reset() {
	ep.endpoint = ""
	ep.reflexive = ""
	ep.tunIf = ""
	if ep.conn != nil {
		ep.conn.Close()
		ep.conn = nil
	}
}

func (ep *Endpoint) Close() {
	ep.conn.Close()
}

// Sets the reflexive sockaddr to 'ep.endpoint'
// Parameters:
//  1. Must be eitehr 'IPv4' or 'IPv6'
//  2. A sock addr of a STUN server ("host:port") or "".
//     GetReflexive uses a list of default STUN servers
//     if 'stunSstr' is "".
func (ep *Endpoint) getReflexive(ctx context.Context, ipVer utils.IPtypes, stunSstr string) error {
	fn := funcName(false)

	ipVidx := (ipVer >> 1) & 1
	udp := utils.UDP[ipVidx]
	log.Tracef("proto: %s", udp)

	var (
		err     error
		stunSvr *net.UDPAddr
	)
	if stunSstr != "" {
		stunSvr, err = net.ResolveUDPAddr(udp, stunSstr)
		if err != nil {
			return &Error{
				Message: fmt.Sprintf("%s: net.ResolveUDPAddr(%s): %v", fn, stunSstr, err),
				Err:     ErrResolvUDP,
			}
		}
	} else {
		stunSvr, err = ep.getStunSvr(udp, STUNsvrs[ipVidx])
		if err != nil {
			return fmt.Errorf("%s: %w", fn, err)
		}
	}
	if ep.conn == nil {
		ep.conn, err = net.ListenUDP("udp", nil)
		if err != nil {
			return &Error{
				Message: fmt.Sprintf("%s: net.ListenUDP: %v", fn, err),
				Err:     ErrListenUDP,
			}
		}
	}

	// Now we have the STUN server's UDP sockaddr.
	// Let us Retrieve our reflexive information.
	timeout := time.NewTicker(stunTimeout)
	defer func() {
		timeout.Stop()
	}()
	err = sendBindingRequest(ep.conn, stunSvr)
	if err != nil {
		log.Errorf("sendBindingRequest(%s): %s", STUNsvrs[ipVidx], err)
	}

	var reflexiveAddr stun.XORMappedAddress
	buf := make([]byte, 1024)
loop:
	for {
		select {
		case <-ctx.Done():
			// Stop sending STUN ping
			return &Error{
				Message: fmt.Sprintf("%s: Canceled.", fn),
				Err:     ErrCanceled,
			}
		case <-timeout.C:
			// Failed to retrieve the reflexive information
			// within 'timeout' seconds.
			return &Error{
				Message: fmt.Sprintf("%s: Timed out.", fn),
				Err:     ErrTimeout,
			}
		default:
			err = ep.conn.SetReadDeadline(time.Now().Add(udpReadDuration))
			if err != nil {
				return &Error{
					Message: fmt.Sprintf("%s: net.(*UDPConn).SeatReadDeadLine: %s", fn, err),
					Err:     ErrSetTimeout,
				}
			}
			_, _, err := ep.conn.ReadFromUDP(buf)
			if err != nil {
				if e, ok := err.(net.Error); !ok || !e.Timeout() {
					return &Error{
						Message: fmt.Sprintf("%s: RreadFromUDP: %v", fn, err),
						Err:     ErrReadUDP,
					}
				}
				// Timeout. Send a STUN bind message again.
				err = sendBindingRequest(ep.conn, stunSvr)
				if err != nil {
					log.Errorf("sendBindingRequest(%s): %s", STUNsvrs[ipVidx], err)
				}
				break
			}
			// Successfully received a STUN reply.
			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				log.Errorf("Decode: %s", err)

				break
			}
			var xorAddr stun.XORMappedAddress
			if err = xorAddr.GetFrom(m); err != nil {
				log.Errorf("GetFrom: %s", err)

				break loop
			}
			if reflexiveAddr.String() != xorAddr.String() {
				log.Infof("reflexive information: %s", xorAddr)

				ep.reflexive = xorAddr.String()
				break loop
			}
		}
	}

	return nil
}

func (ep *Endpoint) getStunSvr(udp string, svrs []string) (*net.UDPAddr, error) {
	fn := funcName(false)

	for _, svr := range svrs {
		stunSvr, err := net.ResolveUDPAddr(udp, svr)
		if err == nil {
			return stunSvr, nil
		}
		log.Tracef("Failed to resolve UDP address: %s: %s", svr, err)
	}

	return nil, &Error{
		Message: fmt.Sprintf("%s: Failed to resolve STUN server's address", fn),
		Err:     ErrResolvUDP,
	}
}

func GetPublicIP(ipVer utils.IPtypes) (string, error) {
	fn := funcName(false)

	var url string
	if ipVer == IPv4 {
		url = "http://ipv4.icanhazip.com"
	} else {
		url = "http://ipv6.icanhazip.com"
	}
	cmd := execv.NewCmd([]string{"curl", "-s", url})
	err := cmd.Run()
	if err != nil {
		log.Errorf("%s", err)

		return "", fmt.Errorf("%s: IPv%d: %w", fn, ipVer, err)
	}
	out := cmd.Stdout()
	return strings.TrimSpace(out), nil
}

func (p *Error) Error() string {
	return fmt.Sprintf("%v: %s", p.Err, p.Message)
}

func (p *Error) Unwrap() error {
	return p.Err
}

func SetPeerTimeout(sec int) {
	peerTimeout = time.Duration(sec) * time.Second
}
