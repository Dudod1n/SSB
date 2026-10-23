package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Only the test executable has this entry point and artificial collector.
func TestTUIProcess(t *testing.T) {
	mode := os.Getenv("SSB_TEST_TUI_HELPER")
	if mode == "" {
		return
	}
	if mode == "plain" {
		os.Exit(run([]string{"--plain", "1"}))
	}
	if mode == "cli" {
		os.Exit(run(strings.Split(os.Getenv("SSB_TEST_ARGS"), "\n")))
	}
	old, err := terminalState()
	if err != nil {
		os.Exit(99)
	}
	collector := func(ctx context.Context, duration time.Duration, notify func(collectionUpdate) error) (data collectionResult, err error) {
		data.Report = report{Hostname: "test-host", Addresses: []string{"192.0.2.10"}, CIDRs: []string{"192.0.2.10/24"}, Duration: duration}
		data.Directory, err = os.MkdirTemp(".", "tcp-report-test-")
		if err != nil {
			return data, err
		}
		raw := filepath.Join(data.Directory, "raw")
		if err := os.Mkdir(raw, 0700); err != nil {
			return data, err
		}
		publish := func(phase string) error { return notify(collectionUpdate{Phase: phase, Data: data}) }
		if err := publish(phasePrepare); err != nil {
			return data, err
		}
		r := &data.Report
		r.TCPBefore = tcpSnapshot{Taken: time.Now(), Sockets: []tcpSocket{{Local: netip.MustParseAddrPort("192.0.2.10:40000"), Remote: netip.MustParseAddrPort("198.51.100.30:5432")}}}
		r.Started = time.Now()
		if err := publish(phaseCapture); err != nil {
			return data, err
		}
		if mode != "instant" {
			if err := capture(ctx, duration, raw); err != nil {
				return data, fmt.Errorf("capture failed: %w", err)
			}
		}
		r.Finished = time.Now()
		r.TCPAfter = tcpSnapshot{Taken: r.Finished, Sockets: r.TCPBefore.Sockets}
		r.Links, r.Unparsed, err = parseCapture(strings.NewReader("IP 198.51.100.12.54000 > 192.0.2.10.22: tcp 0\nIP 192.0.2.10.40001 > 203.0.113.53.53: UDP, length 12\n"), r.Addresses, r.Addresses, io.Discard)
		if err != nil {
			return data, err
		}
		if err := publish(phaseDNS); err != nil {
			return data, err
		}
		if mode != "instant" {
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				return data, ctx.Err()
			}
		}
		r.Names = map[string]string{"198.51.100.12": "admin.example", "203.0.113.53": "dns.example", "198.51.100.30": "db.example"}
		if err := publish(phaseSave); err != nil {
			return data, err
		}
		data.Path = filepath.Join(data.Directory, "report_test-host.txt")
		err = os.WriteFile(data.Path, []byte(formatReport(*r)), 0600)
		return data, err
	}
	m := tuiModel{ip: "192.0.2.10", hostname: "test-host", data: collectionResult{Report: report{Duration: time.Second}}}
	code, err := interactive(old, m, collector)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

type tuiPTY struct {
	t       *testing.T
	master  *os.File
	slave   *os.File
	command *exec.Cmd
	chunks  <-chan []byte
	exited  <-chan error
	waited  bool
	output  bytes.Buffer
	before  syscall.Termios
	dir     string
	plain   bool
}

func startTUI(t *testing.T, mode string) *tuiPTY {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	unlock, number := int32(0), uint32(0)
	if err := ioctl(master.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		master.Close()
		t.Fatal(err)
	}
	if err := ioctl(master.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&number)); err != nil {
		master.Close()
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0600)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	h := &tuiPTY{t: t, master: master, slave: slave, dir: t.TempDir(), plain: mode == "plain"}
	if err := ioctl(slave.Fd(), syscall.TCGETS, unsafe.Pointer(&h.before)); err != nil {
		t.Fatal(err)
	}
	h.resize(100, 30)
	script := "#!/bin/sh\nprintf '%s\\n' \"$$\" >> \"$SSB_TEST_PID_FILE\"\n"
	if mode == "error" {
		script += "printf 'test capture error\\n' >&2\nexit 1\n"
	} else {
		script += "trap 'exit 0' INT\nwhile :; do :; done\n"
	}
	if mode != "plain" {
		if err := os.WriteFile(filepath.Join(h.dir, "tcpdump"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h.command = exec.Command(executable, "-test.run=^TestTUIProcess$", "-test.timeout=15s")
	h.command.Dir = h.dir
	h.command.Env = append(os.Environ(), "TERM=xterm-256color", "SSB_TEST_TUI_HELPER="+mode, "PATH="+h.dir, "SSB_TEST_PID_FILE="+filepath.Join(h.dir, "pids"))
	h.command.Stdin, h.command.Stdout, h.command.Stderr = slave, slave, slave
	h.command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := h.command.Start(); err != nil {
		t.Fatal(err)
	}
	chunks := make(chan []byte, 128)
	h.chunks = chunks
	go func() {
		defer close(chunks)
		buffer := make([]byte, 8192)
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				chunks <- append([]byte(nil), buffer[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	exited := make(chan error, 1)
	h.exited = exited
	go func() { exited <- h.command.Wait() }()
	t.Cleanup(func() {
		if !h.waited {
			h.command.Process.Kill()
			<-h.exited
		}
		slave.Close()
		master.Close()
	})
	return h
}

func (h *tuiPTY) resize(width, height uint16) {
	h.t.Helper()
	size := [4]uint16{height, width}
	if err := ioctl(h.slave.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&size)); err != nil {
		h.t.Fatal(err)
	}
	if h.command != nil {
		h.command.Process.Signal(syscall.SIGWINCH)
	}
}

func (h *tuiPTY) send(text string) {
	h.t.Helper()
	if _, err := io.WriteString(h.master, text); err != nil {
		h.t.Fatal(err)
	}
}

func (h *tuiPTY) readFor(duration time.Duration) string {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	start := h.output.Len()
	for {
		select {
		case chunk, ok := <-h.chunks:
			if !ok {
				return h.output.String()[start:]
			}
			h.output.Write(chunk)
		case <-timer.C:
			return h.output.String()[start:]
		}
	}
}

func (h *tuiPTY) await(text string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(h.output.String(), text) {
		if time.Now().After(deadline) {
			h.t.Fatalf("missing %q in terminal output:\n%s", text, h.output.String())
		}
		h.readFor(10 * time.Millisecond)
	}
}

func (h *tuiPTY) finish(want int) {
	h.t.Helper()
	select {
	case err := <-h.exited:
		h.waited = true
		got := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			got = exit.ExitCode()
		} else if err != nil {
			h.t.Fatal(err)
		}
		if got != want {
			h.t.Fatalf("exit code %d, want %d", got, want)
		}
	case <-time.After(7 * time.Second):
		h.t.Fatal("TUI/collector did not exit")
	}
	h.readFor(30 * time.Millisecond)
	var after syscall.Termios
	if err := ioctl(h.slave.Fd(), syscall.TCGETS, unsafe.Pointer(&after)); err != nil || !reflect.DeepEqual(h.before, after) {
		h.t.Fatalf("terminal settings not restored: %v", err)
	}
	if !h.plain && !strings.Contains(h.output.String(), "\x1b[?1049l") {
		h.t.Fatal("alternate screen not restored")
	}
	if h.plain && strings.ContainsRune(h.output.String(), '\x1b') {
		h.t.Fatal("--plain entered the alternate screen or emitted ANSI")
	}
	data, _ := os.ReadFile(filepath.Join(h.dir, "pids"))
	for _, value := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(value)
		if err != nil {
			h.t.Fatal(err)
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err == nil && !bytes.Contains(status, []byte("State:\tZ")) {
			h.t.Fatalf("capture still running after TUI exit: %d", pid)
		}
	}
}

func TestTUIPTYNavigationExportAndRestart(t *testing.T) {
	h := startTUI(t, "normal")
	h.await("test-host")
	h.await("Захват: [")
	stable := h.readFor(250 * time.Millisecond)
	if strings.Contains(stable, "192.0.2.10 test-host") || strings.Contains(stable, "\x1b[2J") {
		t.Fatal("static IP/header was repainted during capture")
	}
	h.send("e")
	h.await("дождитесь готовности")
	h.send("/e")
	h.await("e_")
	if files, _ := filepath.Glob(filepath.Join(h.dir, "ssb-report-*.txt")); len(files) != 0 {
		t.Fatal("busy/search input exported a file")
	}
	h.send("\x1b")
	h.await("Готово")
	h.send("\x1b")
	time.Sleep(20 * time.Millisecond)
	h.send("[")
	time.Sleep(20 * time.Millisecond)
	h.send("B")
	h.await("192.0.2.10 → 203.0.113.53:53")
	h.send("4")
	h.await("Наблюдения / Открытые TCP")
	h.await("начало: + · конец: +")
	h.send("3/dns.example\r")
	h.await("dns.example · исходящие")
	h.send("ee")
	h.await("TXT (все):")
	h.readFor(100 * time.Millisecond)
	files, _ := filepath.Glob(filepath.Join(h.dir, "ssb-report-*.txt"))
	if len(files) != 2 {
		t.Fatalf("expected two distinct exports, got %d", len(files))
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		info, statErr := os.Stat(name)
		if err != nil || statErr != nil || info.Mode().Perm() != 0600 || !bytes.Contains(data, []byte("admin.example")) || !bytes.Contains(data, []byte("dns.example")) || !bytes.Contains(data, []byte("198.51.100.30:5432")) {
			t.Fatalf("filtered or non-private export: %v %v", err, statErr)
		}
	}
	h.resize(45, 19)
	h.readFor(100 * time.Millisecond)
	h.resize(100, 30)
	h.readFor(100 * time.Millisecond)
	h.send("\x1b")
	time.Sleep(100 * time.Millisecond)
	h.send("rr")
	h.await("Сбор уже выполняется")
	h.readFor(100 * time.Millisecond)
	pids, _ := os.ReadFile(filepath.Join(h.dir, "pids"))
	if len(strings.Fields(string(pids))) != 2 {
		t.Fatalf("restart overlapped collectors: %s", pids)
	}
	h.send("q")
	h.finish(0)
}

func TestTUIPTYSignalsAndFailureRestoreTerminal(t *testing.T) {
	for _, mode := range []string{"ctrl-c", "sigterm", "error"} {
		t.Run(mode, func(t *testing.T) {
			h := startTUI(t, mode)
			want := 1
			if mode == "error" {
				h.await("capture failed")
				h.send("q")
			} else {
				h.await("Захват: [")
				if mode == "ctrl-c" {
					h.send("\x03")
					want = 130
				} else {
					h.command.Process.Signal(syscall.SIGTERM)
					want = 143
				}
			}
			h.finish(want)
		})
	}
}

func TestTUIPTYFinishedReportCannotBeReplacedByQueuedProgress(t *testing.T) {
	h := startTUI(t, "instant")
	h.await("Готово")
	h.readFor(250 * time.Millisecond)
	text := h.output.String()
	if strings.LastIndex(text, "· Готово ·") < strings.LastIndex(text, "· Сохранение ·") {
		t.Fatal("stale stage replaced the finished report")
	}
	h.send("e")
	h.await("TXT (все):")
	h.send("q")
	h.finish(0)
}

func TestTUIPTYPlainOptionKeepsTerminalUnchanged(t *testing.T) {
	h := startTUI(t, "plain")
	h.finish(1) // Empty PATH deliberately prevents any real collection.
	if !strings.Contains(h.output.String(), "не найдена команда tcpdump") {
		t.Fatal("--plain did not reach the text collector")
	}
}

func TestRunPipeHelpVersionAndValidation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		text string
	}{
		{[]string{"--help"}, 0, "--plain"},
		{[]string{"--version"}, 0, "SSB v"},
		{[]string{"0"}, 2, "длительность"},
		{[]string{"--plain", "-1"}, 2, "длительность"},
		{[]string{"--plain", "1"}, 1, "не найдена команда tcpdump"},
		{[]string{"1"}, 1, "не найдена команда tcpdump"},
	} {
		dir := t.TempDir()
		command := exec.Command(executable, "-test.run=^TestTUIProcess$")
		command.Dir = dir
		command.Env = append(os.Environ(), "TERM=xterm-256color", "PATH="+dir, "SSB_TEST_TUI_HELPER=cli", "SSB_TEST_ARGS="+strings.Join(tc.args, "\n"))
		output, err := command.CombinedOutput()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if code != tc.code || !bytes.Contains(output, []byte(tc.text)) || bytes.ContainsRune(output, '\x1b') {
			t.Fatalf("run(%v): exit=%d, output=%s", tc.args, code, output)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("help/validation/missing prerequisite created files: %v", err)
		}
	}
}
