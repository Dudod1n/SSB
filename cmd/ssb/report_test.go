package main

import (
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func TestReportTableHeaderUsesActualCaptureWindow(t *testing.T) {
	started := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	r := report{Hostname: "app-host", Addresses: []string{"192.0.2.10", "192.0.2.11"}, CIDRs: []string{"192.0.2.10/24", "192.0.2.11/24"}, Started: started, Finished: started.Add(2 * time.Second), Duration: time.Minute}
	text := formatReport(r)
	for _, want := range []string{
		"SSB v" + version + " | ОТЧЁТ TCP/UDP IPv4\n",
		"Сохранён:",
		"Хост запуска: app-host (192.0.2.10, 192.0.2.11)\n",
		"Окно наблюдения: 2 с\n",
		"2026-10-24T12:00:00Z — 2026-10-24T12:00:02Z",
		"задано: 60 с",
		"192.0.2.10/24, 192.0.2.11/24",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in table report:\n%s", want, text)
		}
	}
}

func TestReportTableColumnsKeepLargePacketCounts(t *testing.T) {
	r := report{Links: []link{
		{Source: "198.51.100.12", Destination: "192.0.2.10", Port: 22, Direction: "incoming", Protocol: "TCP", Packets: 1},
		{Source: "198.51.100.53", Destination: "192.0.2.10", Port: 65535, Direction: "incoming", Protocol: "UDP", Packets: ^uint64(0)},
	}, Names: map[string]string{"198.51.100.12": "admin.example", "198.51.100.53": "dns.example"}}
	text := formatReport(r)
	column, rows := -1, 0
	for _, line := range strings.Split(text, "\n") {
		if index := strings.Index(line, "Имя удалённого узла"); index >= 0 {
			column = utf8.RuneCountInString(line[:index])
		}
		for _, name := range []string{"admin.example", "dns.example"} {
			if index := strings.Index(line, name); index >= 0 {
				if column < 0 || utf8.RuneCountInString(line[:index]) != column {
					t.Fatalf("hostname column shifted:\n%s", text)
				}
				rows++
			}
		}
	}
	if rows != 2 || !strings.Contains(text, "65535 UDP      18446744073709551615 dns.example") {
		t.Fatalf("packet counts or same-row names lost:\n%s", text)
	}
}

func TestReportTableDoesNotEmitMetadataControls(t *testing.T) {
	r := report{Hostname: "app\nINJECT\x1b", Names: map[string]string{"198.51.100.12": "admin\t\u202e.example"},
		Links:       []link{{Source: "198.51.100.12", Destination: "192.0.2.10", Port: 22, Direction: "incoming", Protocol: "TCP", Packets: 1}},
		Diagnostics: "listening\r\x1b\n2 packets captured\n",
		TCPBefore:   tcpSnapshot{Taken: time.Now(), Problem: "tcp6\nINJECT\x1b"},
	}
	text := formatReport(r)
	for _, char := range text {
		if (unicode.IsControl(char) && char != '\n') || unicode.Is(unicode.Cf, char) {
			t.Fatalf("metadata control leaked: %q", char)
		}
	}
	if !strings.Contains(text, "Хост запуска: appINJECT") || !strings.Contains(text, "admin.example") || !strings.Contains(text, "tcp6INJECT") || !strings.Contains(text, "listening\n2 packets captured\n") {
		t.Fatalf("metadata or diagnostic lines lost:\n%s", text)
	}
}
