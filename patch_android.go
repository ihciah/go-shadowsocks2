package main

import (
	"fmt"
	"net"
	"syscall"

	"github.com/pkg/errors"
)

func init() {
	protectFd := func(fd int) error {
		const protectPath = "protect_path"
		conn, err := dialer.Dial("unix", protectPath)
		if err != nil {
			return errors.Wrap(err, "dial "+protectPath)
		}
		defer conn.Close()
		protectConn := conn.(*net.UnixConn)
		rights := syscall.UnixRights(fd)
		n, oobn, err := protectConn.WriteMsgUnix(nil, rights, nil)
		if err != nil {
			return errors.Wrap(err, "WriteMsgUnix")
		}
		if oobn != len(rights) {
			return fmt.Errorf("WriteMsgUnix got %d want %d", oobn, len(rights))
		}
		dummyByte := make([]byte, 1)
		n, err = protectConn.Read(dummyByte)
		if n == 0 || err != nil {
			return errors.Wrap(err, fmt.Sprintf("Read fd=%d", fd))
		}
		ret := dummyByte[0]
		if ret != 0 {
			return fmt.Errorf("protect_path return %d", ret)
		}
		return nil
	}

	net.SetSocketFunc(func(domain int, typ int, proto int) (int, error) {
		fd, err := syscall.Socket(domain, typ, proto)
		if err == nil {
			if domain == syscall.AF_INET || domain == syscall.AF_INET6 {
				err := protectFd(fd)
				if err != nil {
					syscall.Close(fd)
					return 0, errors.Wrap(err, "protect")
				}
			}
		}
		return fd, err
	})
}
