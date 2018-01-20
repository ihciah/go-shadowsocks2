package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var (
	tx, rx uint64
)

type NoDelaySetter interface {
	SetNoDelay(noDelay bool) error
}

// Create a SOCKS server listening on addr and proxy to server.
func socksLocal(localAddr string, dial func(string, string) (net.Conn, error)) {
	tcpLocal(localAddr, dial, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(localAddr string, proxyDial func(string, string) (net.Conn, error), getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", localAddr)
	if err != nil {
		logf("failed to listen on %s: %v", localAddr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tcpConn := c.(*net.TCPConn)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
			tcpConn.SetNoDelay(true)
			tgt, err := getAddr(c)
			if err != nil {
				logf("failed to get target address: %v", err)
				return
			}
			if fakeDns != nil {
				tgt = fakeDns.Replace(tgt)
			}
			remote := tgt.String()

			directConnect := false
			if host, _, _ := net.SplitHostPort(tgt.String()); host != "" {
				ip := net.ParseIP(host)
				if ip != nil && fakeDns.ShouldDirectConnect(ip) {
					directConnect = true
				}
			}

			var rc io.ReadWriteCloser
			var dialFunc func(string, string) (net.Conn, error)
			var proxyType string
			if directConnect {
				dialFunc = dialer.Dial
				proxyType = "direct"
			} else {
				dialFunc = proxyDial
				proxyType = "proxy"
			}
			rc, err = dialFunc("tcp4", remote)
			if err != nil {
				logf("failed to dial %v: %v", remote, err)
				return
			}
			if tcpConn, ok := rc.(NoDelaySetter); ok {
				tcpConn.SetNoDelay(true)
			}
			logf("%s %s <-> %s", proxyType, c.RemoteAddr(), tgt)
			defer rc.Close()

			_, _, err = relay(&CountedReadWriteCloser{rc}, c)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally. Returns number of
// bytes copied from right to left, from left to right, and any error occurred.
func relay(left, right io.ReadWriteCloser) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		err = ignoreClosedErr(err)
		right.Close()
		left.Close()
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	err = ignoreClosedErr(err)
	right.Close()
	left.Close()
	rs := <-ch

	if err == nil {
		err = rs.Err
	}

	// http2 response.Body的Close和net.Conn不同，提前Close会导致数据流断开，进而上层读取时异常，只能这样绕过
	type ReaderCloser interface {
		CloseRead() error
	}
	if c, ok := left.(ReaderCloser); ok {
		c.CloseRead()
	}
	if c, ok := right.(ReaderCloser); ok {
		c.CloseRead()
	}

	return n, rs.N, err
}

type CountedReadWriteCloser struct {
	io.ReadWriteCloser
}

func (r *CountedReadWriteCloser) Write(b []byte) (n int, err error) {
	n, err = r.ReadWriteCloser.Write(b)
	if n > 0 {
		tx += uint64(n)
	}
	return
}

func (r *CountedReadWriteCloser) Read(b []byte) (n int, err error) {
	n, err = r.ReadWriteCloser.Read(b)
	if n > 0 {
		rx += uint64(n)
	}
	return
}

func sendStat() {
	if _, err := os.Stat("no_stat"); err == nil {
		logf("no_stat detected, disable stat report")
		return
	}
	const statPath = "stat_path"
	var (
		localTx, localRx uint64
	)
	writeBuf := make([]byte, 16)
	readBuf := make([]byte, 1)
	for {
		time.Sleep(500 * time.Millisecond)
		func() {
			if localTx == tx && localRx == rx {
				return
			}
			localTx, localRx = tx, rx
			conn, err := dialer.Dial("unix", statPath)
			if err != nil {
				logf("dial %s: %v", statPath, err)
				return
			}
			defer conn.Close()
			binary.LittleEndian.PutUint64(writeBuf, localTx)
			binary.LittleEndian.PutUint64(writeBuf[8:], localRx)
			if _, err := conn.Write(writeBuf); err != nil {
				logf("send %s: %v", statPath, err)
				return
			}
			if _, err := conn.Read(readBuf); err != nil && err != io.EOF {
				logf("recv %s: %v", statPath, err)
			}
		}()
	}
}

func ignoreClosedErr(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
