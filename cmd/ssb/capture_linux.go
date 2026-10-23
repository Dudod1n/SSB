package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func capture(ctx context.Context, duration time.Duration, rawDir string) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	packets, err := os.OpenFile(filepath.Join(rawDir, "packets.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, packets.Close()) }()
	diagnostic, err := os.OpenFile(filepath.Join(rawDir, "capture.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, diagnostic.Close()) }()
	// Quiet output keeps UDP application data (such as DNS queries) out of raw/.
	command := exec.Command("tcpdump", "-i", "any", "-nn", "-tttt", "-q", "-l", captureFilter)
	command.Env = append(os.Environ(), "LC_ALL=C")
	command.Stdout, command.Stderr = packets, diagnostic
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return err
	}
	defer func() {
		cleanupErr := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if cleanupErr != nil && !errors.Is(cleanupErr, syscall.ESRCH) {
			err = errors.Join(err, cleanupErr)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
	case <-ctx.Done():
	}
	// Signal the process group so subprocesses cannot keep a capture running.
	signalErr := syscall.Kill(-command.Process.Pid, syscall.SIGINT)
	if errors.Is(signalErr, syscall.ESRCH) {
		signalErr = nil
	}
	grace := time.NewTimer(5 * time.Second)
	defer grace.Stop()
	select {
	case err := <-done:
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.Sys().(syscall.WaitStatus).Signal() == syscall.SIGINT {
			err = nil
		}
		return errors.Join(ctx.Err(), signalErr, err)
	case <-grace.C:
		syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		<-done
		return errors.Join(ctx.Err(), signalErr, fmt.Errorf("tcpdump принудительно остановлен через 5 секунд после SIGINT"))
	}
}
