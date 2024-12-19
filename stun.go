package natTraversal

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
	//"github.com/sirupsen/logrus"
)

const (
	pingMsg = "ping"
	pongMsg = "pong"

	msgDuration = 500 * time.Millisecond
)

func sendPingPong(ctx context.Context, conn *net.UDPConn, dest *net.UDPAddr, sendPong <-chan bool) {
	dst := dest.String()

	interval := time.NewTicker(msgDuration)
	defer func() {
		interval.Stop()
	}()
	msg := pingMsg
	for {
		select {
		case <-ctx.Done():
			log.Debugf("to %s: Canceled.", dst)

			return
		case <-sendPong:
			log.Debugf("Start sending pong msg to %s.", dst)

			msg = pongMsg
		case <-interval.C:
			log.Tracef("Sending %s to %s.", msg, dst)

			err := sendStr(msg, conn, dest)
			if err != nil {
				log.Errorf("sendStr(%s): %s", dst, err)

				return
			}
		}
	}
}

func sendBindingRequest(conn *net.UDPConn, addr *net.UDPAddr) error {
	fn := funcName(false)

	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	err := send(m.Raw, conn, addr)
	if err != nil {
		return fmt.Errorf("%s: %w", fn, err)
	}

	return nil
}

func sendStr(msg string, conn *net.UDPConn, addr *net.UDPAddr) error {
	return send([]byte(msg), conn, addr)
}

func send(msg []byte, conn *net.UDPConn, addr *net.UDPAddr) error {
	fn := funcName(false)

	_, err := conn.WriteToUDP(msg, addr)
	if err != nil {
		return &Error{
			Message: fmt.Sprintf("%s: (net.UDPConn).WriteToUDP: %v", fn, err),
			Err:     ErrWriteUDP,
		}
	}

	return nil
}
