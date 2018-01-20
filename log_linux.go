// +build linux

package main

import "syscall"

func redirectStream(fd uintptr) {
	syscall.Dup3(int(fd), 1, 0)
	syscall.Dup3(int(fd), 2, 0)
}
