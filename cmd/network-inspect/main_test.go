package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDuration(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want time.Duration
	}{
		{nil, time.Minute}, {[]string{"120"}, 2 * time.Minute},
	} {
		got, err := parseDuration(tc.args)
		if err != nil || got != tc.want {
			t.Fatalf("parseDuration(%v) = %v, %v", tc.args, got, err)
		}
	}
	for _, arg := range []string{"0", "-1", "1.5", "+1", "01", "", "99999999999999999999"} {
		if _, err := parseDuration([]string{arg}); err == nil {
			t.Errorf("accepted duration %q", arg)
		}
	}
	if _, err := parseDuration([]string{"1", "2"}); err == nil {
		t.Fatal("accepted extra arguments")
	}
}

func TestAddressSelection(t *testing.T) {
	all, ips, cidrs, err := selectAddresses([]string{
		"127.0.0.1/8", "172.17.0.1/16", "10.20.0.20/23", "10.20.0.20/23", "::1/128",
	})
	if err != nil || !reflect.DeepEqual(all, []string{"10.20.0.20", "127.0.0.1", "172.17.0.1"}) ||
		!reflect.DeepEqual(ips, []string{"10.20.0.20"}) || !reflect.DeepEqual(cidrs, []string{"10.20.0.20/23"}) {
		t.Fatalf("addresses = %v %v %v, %v", all, ips, cidrs, err)
	}
}

func TestParseCapture(t *testing.T) {
	input := strings.Join([]string{
		"IP 10.20.0.15.12345 > 10.20.0.20.80: Flags [S]",
		"IP 10.20.0.15.54321 > 10.20.0.20.80: Flags [S]",
		"IP 10.20.0.20.40000 > 172.22.0.10.443: Flags [S]",
		"IP 172.17.0.1.40000 > 10.20.0.20.22: Flags [S]",
		"IP 10.20.0.20.40000 > 127.0.0.2.22: Flags [S]",
		"IP 10.20.0.15.12345 > 10.20.0.20.65536: Flags [S]",
		"IP 999.0.0.15.12345 > 10.20.0.20.80: Flags [S]",
		"invalid packet", "",
	}, "\n")
	var bad strings.Builder
	links, count, err := parseCapture(strings.NewReader(input),
		[]string{"10.20.0.20", "127.0.0.1", "172.17.0.1"}, []string{"10.20.0.20"}, &bad)
	want := []link{
		{"10.20.0.15", "10.20.0.20", 80, "incoming"},
		{"10.20.0.20", "172.22.0.10", 443, "outgoing"},
	}
	if err != nil || !reflect.DeepEqual(links, want) || count != 3 || !strings.Contains(bad.String(), "invalid packet") {
		t.Fatalf("links = %#v; unparsed = %d; error = %v", links, count, err)
	}
}

func TestResolveNamesKeepsPartialResultsOnDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	names, status := resolveNames(ctx, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		func(ctx context.Context, ip string) ([]string, error) {
			if ip == "10.0.0.1" {
				return []string{"bad\nname", "client.example."}, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	if status != "budget_exhausted" || names["10.0.0.1"] != "client.example" || len(names) != 1 {
		t.Fatalf("resolution = %v, %s", names, status)
	}
}

func TestResolveNamesKeepsValidPartialDNSAnswer(t *testing.T) {
	names, status := resolveNames(context.Background(), []string{"10.0.0.1"},
		func(context.Context, string) ([]string, error) {
			return []string{"bad\nname", "client.example."}, errors.New("one PTR name is malformed")
		})
	if names["10.0.0.1"] != "client.example" || status != "complete" {
		t.Fatalf("partial DNS answer was lost: %v, %s", names, status)
	}
}

func TestReportGroupsAndUnknownNames(t *testing.T) {
	r := report{
		Hostname: "app/blue", Addresses: []string{"10.20.0.20"}, CIDRs: []string{"10.20.0.20/24"},
		Links: []link{{"10.20.0.15", "10.20.0.20", 80, "incoming"},
			{"10.20.0.15", "10.20.0.20", 443, "incoming"},
			{"10.20.0.20", "10.20.0.15", 22, "outgoing"},
			{"10.20.0.20", "10.20.0.30", 5432, "outgoing"}},
		Names: map[string]string{"10.20.0.15": "client.example"}, ResolutionStatus: "complete",
	}
	txt := formatReport(r)
	_, names, ok := strings.Cut(txt, "ИМЕНА ХОСТОВ ПО IP\n")
	if !ok {
		t.Fatal("missing hostname section")
	}
	incoming, outgoing, ok := strings.Cut(names, "Исходящие\n")
	if !ok || strings.Count(incoming, "client.example") != 1 || strings.Count(outgoing, "client.example") != 1 ||
		!strings.Contains(outgoing, "10.20.0.30") || !strings.Contains(outgoing, "-") {
		t.Fatalf("incorrect hostname groups:\n%s", names)
	}
	if safeHostname(r.Hostname) != "app_blue" {
		t.Fatal("unsafe report filename")
	}
	empty := formatReport(report{})
	if strings.Count(empty, "За время наблюдения обращений не обнаружено.") != 4 {
		t.Fatal("empty connection/hostname groups are missing")
	}
}

func TestCaptureFailureRetainsPrivateRawFiles(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tcpdump")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'capture failed\\n' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	err := capture(context.Background(), time.Second, dir)
	if err == nil {
		t.Fatal("capture failure was accepted")
	}
	for _, name := range []string{"syn.log", "capture.log"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("raw file %s: %v, %v", name, info, err)
		}
	}
	diagnostic, _ := os.ReadFile(filepath.Join(dir, "capture.log"))
	if !strings.Contains(string(diagnostic), "capture failed") {
		t.Fatal("capture diagnostics were lost")
	}
}

func TestCaptureDeadlineAndCancellation(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ntrap 'exit 0' INT\nwhile :; do :; done\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	started := time.Now()
	if err := capture(context.Background(), 30*time.Millisecond, dir); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("capture did not stop at the deadline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := capture(ctx, time.Second, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
}

func TestCaptureStopsDescendantsWhenDirectChildExits(t *testing.T) {
	for _, mode := range []string{"failure", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			script := "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s' \"$!\" > \"$CHILD_PID_FILE\"\n" +
				"[ \"$CAPTURE_MODE\" = failure ] && exit 1\ntrap 'exit 0' INT\nwait\n"
			if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			t.Setenv("CHILD_PID_FILE", filepath.Join(dir, "child.pid"))
			t.Setenv("CAPTURE_MODE", mode)
			err := capture(context.Background(), 100*time.Millisecond, dir)
			if (err != nil) != (mode == "failure") {
				t.Fatalf("capture returned %v", err)
			}
			contents, err := os.ReadFile(filepath.Join(dir, "child.pid"))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(contents))
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Kill(pid, syscall.SIGKILL)
			for until := time.Now().Add(time.Second); time.Now().Before(until); {
				status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
				if os.IsNotExist(err) || strings.Contains(string(status), "State:\tZ") {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("tcpdump descendant is still running after capture returned")
		})
	}
}
