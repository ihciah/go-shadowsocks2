package main

import (
	"net"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func ssShadow(proxyServer string, ciph core.Cipher) func(string, string) (net.Conn, error) {
	return func(_, realServer string) (net.Conn, error) {
		conn, err := dialer.Dial("tcp", proxyServer)
		if err != nil {
			return nil, err
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}
		conn = ciph.StreamConn(conn)
		if _, err := conn.Write(socks.ParseAddr(realServer)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}
