package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestCaptureSeparatesProtocolsAndCountsPackets(t *testing.T) {
	input := strings.Join([]string{
		"2026-10-23 12:00:00.000001 IP 198.51.100.12.40000 > 192.0.2.10.53: Flags [S], seq 1, length 0",
		"2026-10-23 12:00:00.000002 IP 198.51.100.12.40000 > 192.0.2.10.53: Flags [S], seq 1, length 0",
		"2026-10-23 12:00:00.000003 IP 198.51.100.12.40001 > 192.0.2.10.53: UDP, length 12",
		"2026-10-23 12:00:00.000004 IP 198.51.100.12.40001 > 192.0.2.10.53: UDP, length 12",
		"2026-10-23 12:00:00.000005 IP 198.51.100.12.40000 > 192.0.2.10.53: Flags [.], ack 1, length 0",
		"2026-10-23 12:00:00.000006 IP 198.51.100.12.40000 > 192.0.2.10.53: Flags [S.], seq 1, ack 1, length 0",
	}, "\n")
	var bad strings.Builder
	links, unparsed, err := parseCapture(strings.NewReader(input), []string{"192.0.2.10"}, []string{"192.0.2.10"}, &bad)
	if err != nil || len(links) != 2 || unparsed != 0 {
		t.Fatalf("expected separate TCP and UDP rows: %#v, unparsed=%d, error=%v", links, unparsed, err)
	}
	txt := formatReport(report{Links: links})
	for _, protocol := range []string{"TCP", "UDP"} {
		found := false
		for _, line := range strings.Split(txt, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 5 && strings.Join(fields[:5], " ") == "198.51.100.12 192.0.2.10 53 "+protocol+" 2" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s packet count in report:\n%s", protocol, txt)
		}
	}
}

func TestUDPDirectionAndExcludedAddresses(t *testing.T) {
	input := strings.Join([]string{
		"2026-10-23 12:00:00.000001 eth0 Out IP 192.0.2.10.40000 > 198.51.100.53.53: UDP, length 12",
		"IP 192.0.2.10.40001 > 198.51.100.53.53: UDP, length 12",
		"IP 198.51.100.53.53 > 192.0.2.10.40000: UDP, length 12",
		"IP 172.17.0.1.40000 > 192.0.2.10.53: UDP, length 12",
		"IP 192.0.2.10.40000 > 127.0.0.2.53: UDP, length 12",
		"IP 192.0.2.10.40000 > 192.0.2.11.53: UDP, length 12",
		"IP 198.51.100.53.40000 > 203.0.113.53.53: UDP, length 12",
	}, "\n")
	links, unparsed, err := parseCapture(strings.NewReader(input), []string{"192.0.2.10", "192.0.2.11", "172.17.0.1"}, []string{"192.0.2.10", "192.0.2.11"}, io.Discard)
	if err != nil || unparsed != 0 || len(links) != 2 || links[0].Direction != "incoming" || links[0].Packets != 1 || links[1].Direction != "outgoing" || links[1].Packets != 2 {
		t.Fatalf("UDP direction/filter/counts = %#v, unparsed=%d, error=%v", links, unparsed, err)
	}
}

func TestCaptureParserPropagatesReadAndDiagnosticWriteErrors(t *testing.T) {
	failure := errors.New("test I/O failure")
	if _, _, err := parseCapture(iotest.ErrReader(failure), nil, nil, io.Discard); !errors.Is(err, failure) {
		t.Fatalf("read error lost: %v", err)
	}
	if _, _, err := parseCapture(strings.NewReader("invalid packet\n"), nil, nil, failWriter{failure}); !errors.Is(err, failure) {
		t.Fatalf("diagnostic write error lost: %v", err)
	}
}

type failWriter struct{ error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.error }
