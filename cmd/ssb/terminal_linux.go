//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func ioctl(fd, request uintptr, value unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(value))
	if errno != 0 {
		return errno
	}
	return nil
}

func terminalState() (syscall.Termios, error) {
	var state syscall.Termios
	err := ioctl(os.Stdin.Fd(), syscall.TCGETS, unsafe.Pointer(&state))
	return state, err
}

func setTerminal(state *syscall.Termios) error {
	return ioctl(os.Stdin.Fd(), syscall.TCSETS, unsafe.Pointer(state))
}

func terminalSize() (width, height int, err error) {
	var size [4]uint16
	err = ioctl(os.Stdout.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&size))
	return max(1, int(size[1])-1), max(1, int(size[0])-1), err
}
