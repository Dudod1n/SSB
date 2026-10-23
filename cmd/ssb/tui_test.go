package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectionCancellationDoesNotStartWork(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := collectReport(ctx, time.Second, nil)
	if !errors.Is(err, context.Canceled) || result.Directory != "" {
		t.Fatalf("canceled collection started work: %#v, %v", result, err)
	}
}

func TestTUIViewsSearchAndFullPrivateExport(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	r := report{Hostname: "test-host", Addresses: []string{"192.0.2.10"}, Started: now, Finished: now.Add(time.Minute), Duration: time.Minute,
		Links: []link{
			{Source: "198.51.100.12", Destination: "192.0.2.10", Port: 22, Direction: "incoming", Protocol: "TCP", Packets: 3},
			{Source: "192.0.2.10", Destination: "203.0.113.53", Port: 53, Direction: "outgoing", Protocol: "UDP", Packets: 8},
		}, Names: map[string]string{"198.51.100.12": "admin.example", "203.0.113.53": "dns.example"},
	}
	socket, err := parseTCPSockets(strings.NewReader("sl local_address rem_address st\n0: "+procEndpoint("192.0.2.10", 40000)+" "+procEndpoint("198.51.100.30", 5432)+" 01\n"), r.Addresses, r.Addresses)
	if err != nil {
		t.Fatal(err)
	}
	r.TCPBefore = tcpSnapshot{Taken: now, Sockets: socket}
	r.TCPAfter = tcpSnapshot{Taken: r.Finished, Sockets: socket}
	m := tuiModel{data: collectionResult{Report: r}, phase: phaseReady}
	if len(m.filtered()) != 3 {
		t.Fatal("packet rows or established socket missing")
	}
	m.key("2")
	if rows := m.filtered(); len(rows) != 1 || rows[0].direction != "incoming" {
		t.Fatalf("incoming filter = %#v", rows)
	}
	m.key("3")
	if rows := m.filtered(); len(rows) != 1 || rows[0].protocol != "UDP" {
		t.Fatalf("outgoing UDP filter = %#v", rows)
	}
	m.key("4")
	if rows := m.filtered(); len(rows) != 1 || rows[0].kind != "ESTABLISHED" || rows[0].direction != "" {
		t.Fatalf("established socket was assigned an initiator: %#v", rows)
	}
	m.key("1")
	m.key("/")
	for _, key := range []string{"d", "n", "s", ".", "e"} {
		m.key(key)
	}
	if m.query != "dns.e" || len(m.filtered()) != 1 || !m.editing {
		t.Fatalf("search, including e, failed: %#v", m)
	}
	m.key("enter")
	dir := t.TempDir()
	first, err := exportReport(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	second, err := exportReport(dir, m)
	if err != nil || first == second {
		t.Fatalf("export overwrote a previous file: %q %q %v", first, second, err)
	}
	for _, name := range []string{first, second} {
		text, err := os.ReadFile(name)
		info, statErr := os.Stat(name)
		if err != nil || statErr != nil || info.Mode().Perm() != 0600 || !strings.Contains(string(text), "admin.example") || !strings.Contains(string(text), "dns.example") || !strings.Contains(string(text), "198.51.100.30:5432") || strings.ContainsRune(string(text), '\x1b') {
			t.Fatalf("incomplete/non-private TXT %s: %v %v", filepath.Base(name), err, statErr)
		}
	}
	m.busy = true
	if name, err := exportReport(dir, m); name != "" || err == nil {
		t.Fatal("unfinished collection was exported")
	}
}

func TestTUIFramesAndCaptureProgress(t *testing.T) {
	started := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m := tuiModel{phase: phaseCapture, busy: true, data: collectionResult{Report: report{Hostname: "test-host\x1b[31m", Addresses: []string{"192.0.2.10"}, Started: started, Duration: time.Minute}}}
	for _, size := range [][2]int{{44, 18}, {80, 24}, {100, 30}, {240, 120}, {1, 1}} {
		rows := renderTUI(m, size[0], size[1], started.Add(30*time.Second))
		if len(rows) > size[1] {
			t.Fatalf("frame height %v: %d", size, len(rows))
		}
		for _, row := range rows {
			text := plain([]line{row})
			if len([]rune(text)) != size[0] || strings.ContainsRune(text, '\x1b') {
				t.Fatalf("invalid row at %v: %q", size, text)
			}
		}
	}
	text := plain(renderTUI(m, 100, 30, started.Add(30*time.Second)))
	if !strings.Contains(text, "SSB v") || !strings.Contains(text, "192.0.2.10 test-host") || !strings.Contains(text, "30/60 с") || strings.Contains(text, "ДЕМО") {
		t.Fatalf("header/progress = %s", text)
	}
	m.data.Report.Finished = started.Add(time.Minute)
	m.phase = phaseDNS
	text = plain(renderTUI(m, 100, 30, started.Add(70*time.Second)))
	if !strings.Contains(text, "Захват: Выполнен (60 секунд)") || !strings.Contains(text, "Поиск имён") || strings.Contains(text, "70/60") {
		t.Fatalf("finished capture progress = %s", text)
	}
	rows := renderTUI(m, 100, 30, started.Add(70*time.Second))
	display := screen{}
	if display.update(rows, 100, 30) == "" || display.update(rows, 100, 30) != "" {
		t.Fatal("unchanged frame was redrawn")
	}
	changed := append([]line(nil), rows...)
	changed[1] = fit(row("progress only", "text"), 100)
	output := display.update(changed, 100, 30)
	if strings.Contains(output, "\x1b[2J") || strings.Contains(output, "test-host") || !strings.Contains(output, "\x1b[2;1H") {
		t.Fatalf("IP/header flicker regression: %q", output)
	}
}

func TestTUIFitsWideAndCombiningSearchText(t *testing.T) {
	for _, tc := range []struct {
		text  string
		width int
		want  string
	}{
		{"A界B", 4, "A界B"},
		{"e\u0301x", 2, "e\u0301x"},
		{"界界", 3, "界 "},
		{"a\u202eb", 2, "ab"},
	} {
		if got := plain([]line{fit(row(tc.text, "text"), tc.width)}); got != tc.want {
			t.Errorf("fit(%q, %d) = %q, want %q", tc.text, tc.width, got, tc.want)
		}
	}
}

func TestTUIHostIdentitySurvivesCollectionFailure(t *testing.T) {
	m := tuiModel{ip: "192.0.2.10", hostname: "test-host", phase: phaseError}
	text := plain(renderTUI(m, 100, 30, time.Now()))
	if !strings.Contains(text, "192.0.2.10 test-host") {
		t.Fatal("host identity disappeared when no report was produced")
	}
}
