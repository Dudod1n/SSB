package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func newTUIModel(duration time.Duration) tuiModel {
	m := tuiModel{phase: phasePrepare, data: collectionResult{Report: report{Duration: duration}}}
	m.hostname, _ = os.Hostname()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return m
	}
	var snapshot []string
	for _, address := range addresses {
		snapshot = append(snapshot, address.String())
	}
	all, published, _, err := selectAddresses(snapshot)
	if err != nil {
		return m
	}
	for _, value := range append(published, all...) {
		ip, err := netip.ParseAddr(value)
		if err == nil && ip.IsGlobalUnicast() {
			m.ip = value
			break
		}
	}
	return m
}

func (s *screen) draw(m tuiModel) error {
	width, height, err := terminalSize()
	if err != nil {
		return err
	}
	output := s.update(renderTUI(m, width, height, time.Now()), width, height)
	if output == "" {
		return nil
	}
	_, err = io.WriteString(os.Stdout, output)
	return err
}

type input struct {
	char rune
	err  error
}

func interactive(old syscall.Termios, m tuiModel, collect collectionFunc) (code int, err error) {
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGWINCH)
	defer signal.Stop(signals)
	raw := old
	raw.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.IEXTEN | syscall.ISIG
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 1, 0
	if err := setTerminal(&raw); err != nil {
		return 1, err
	}
	type jobResult struct {
		data collectionResult
		err  error
	}
	duration := m.data.Report.Duration
	var cancel context.CancelFunc
	var done <-chan jobResult
	var updates <-chan collectionUpdate
	defer func() {
		if cancel != nil {
			cancel()
		}
		if done != nil {
			result := <-done
			m.data = result.data
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				err = errors.Join(err, result.err)
				code = 1
			}
		}
		restoreErr := setTerminal(&old)
		_, writeErr := io.WriteString(os.Stdout, "\x1b[0m\x1b[?25h\x1b[?1049l")
		err = errors.Join(err, restoreErr, writeErr)
		if m.data.Directory != "" {
			_, writeErr = fmt.Fprintln(os.Stdout, "Данные сохранены:", clean(m.data.Directory))
			err = errors.Join(err, writeErr)
		}
	}()
	if _, err := io.WriteString(os.Stdout, "\x1b[?1049h\x1b[?25l"); err != nil {
		return 1, err
	}
	start := func() {
		ctx, stop := context.WithCancel(context.Background())
		cancel = stop
		progress := make(chan collectionUpdate, 8)
		finished := make(chan jobResult, 1)
		updates, done = progress, finished
		m.data = collectionResult{Report: report{Hostname: m.data.Report.Hostname, Addresses: m.data.Report.Addresses, Duration: duration}}
		m.phase, m.busy, m.failure, m.selected = phasePrepare, true, nil, 0
		m.notice, m.noticeError = "", false
		go func() {
			data, err := collect(ctx, duration, func(update collectionUpdate) error {
				select {
				case progress <- update:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			finished <- jobResult{data, err}
		}()
	}
	inputs := make(chan input, 32)
	stopInput := make(chan struct{})
	defer close(stopInput)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			char, _, err := reader.ReadRune()
			select {
			case inputs <- input{char, err}:
			case <-stopInput:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(125 * time.Millisecond)
	defer ticker.Stop()
	var escapeTimeout <-chan time.Time
	escape := ""
	display := screen{}
	start()
	if err := display.draw(m); err != nil {
		return 1, err
	}
	for {
		key := ""
		select {
		case update := <-updates:
			m.data, m.phase = update.Data, update.Phase
		case result := <-done:
			cancel()
			done, updates = nil, nil // Queued progress must never replace the finished report.
			m.data, m.busy, m.failure = result.data, false, result.err
			m.phase = phaseReady
			if result.err != nil {
				m.phase, m.notice, m.noticeError = phaseError, result.err.Error(), true
			}
		case sig := <-signals:
			switch sig {
			case os.Interrupt:
				return 130, nil
			case syscall.SIGTERM:
				return 143, nil
			}
		case <-ticker.C:
			if !m.busy {
				continue
			}
		case <-escapeTimeout:
			escape, key, escapeTimeout = "", "esc", nil
		case event := <-inputs:
			if errors.Is(event.err, io.EOF) {
				return 0, nil
			}
			if event.err != nil {
				return 1, event.err
			}
			if event.char == '\x03' {
				return 130, nil
			}
			if event.char == '\x1b' {
				escape = "\x1b"
				escapeTimeout = time.After(80 * time.Millisecond)
				continue
			}
			if escape != "" {
				escape += string(event.char)
				if escape == "\x1b[" || escape == "\x1bO" {
					continue
				}
				switch escape {
				case "\x1b[A", "\x1bOA":
					key = "up"
				case "\x1b[B", "\x1bOB":
					key = "down"
				}
				escape, escapeTimeout = "", nil
				if key == "" {
					continue
				}
			} else {
				key = string(event.char)
				switch event.char {
				case '\r', '\n':
					key = "enter"
				case '\x7f', '\b':
					key = "backspace"
				case '\t':
					key = "tab"
				}
			}
		}
		editing := m.editing
		if m.key(key) {
			if m.failure != nil {
				return 1, m.failure
			}
			return 0, nil
		}
		if !editing && key == "r" {
			if m.busy {
				m.notice, m.noticeError = "Сбор уже выполняется.", false
			} else {
				start()
			}
		}
		if !editing && key == "e" {
			name, exportErr := exportReport(".", m)
			m.noticeError = exportErr != nil
			if exportErr == nil {
				m.notice = "TXT (все): " + filepath.Base(name)
			} else if name != "" {
				m.notice = "Неполный TXT: " + filepath.Base(name)
			} else {
				var pathErr *os.PathError
				if errors.As(exportErr, &pathErr) {
					exportErr = pathErr.Err
				}
				m.notice = "Экспорт: " + exportErr.Error()
			}
		}
		if err := display.draw(m); err != nil {
			return 1, err
		}
	}
}

func exportReport(directory string, m tuiModel) (string, error) {
	if m.busy || m.phase != phaseReady || m.data.Report.Finished.IsZero() {
		return "", errors.New("дождитесь готовности отчёта")
	}
	file, err := os.CreateTemp(directory, "ssb-report-*.txt")
	if err != nil {
		return "", err
	}
	_, writeErr := io.WriteString(file, formatReport(m.data.Report))
	err = errors.Join(writeErr, file.Close())
	if err != nil {
		if cleanupErr := os.Remove(file.Name()); cleanupErr != nil {
			return file.Name(), errors.Join(err, cleanupErr)
		}
		return "", err
	}
	return file.Name(), nil
}
