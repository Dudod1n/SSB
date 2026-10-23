package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func procEndpoint(ip string, port uint16) string {
	address := netip.MustParseAddr(ip)
	if address.Is4() {
		bytes := address.As4()
		return fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(bytes[:]), port)
	}
	bytes := address.As16()
	return fmt.Sprintf("%08X%08X%08X%08X:%04X", binary.NativeEndian.Uint32(bytes[0:4]), binary.NativeEndian.Uint32(bytes[4:8]), binary.NativeEndian.Uint32(bytes[8:12]), binary.NativeEndian.Uint32(bytes[12:16]), port)
}

func TestEstablishedIPv4MappedSocketsAreIncluded(t *testing.T) {
	input := "sl local_address remote_address st\n0: " + procEndpoint("::ffff:192.0.2.10", 22) + " " + procEndpoint("::ffff:198.51.100.30", 50000) + " 01\n" +
		"1: " + procEndpoint("2001:db8::1", 22) + " " + procEndpoint("2001:db8::2", 50000) + " 01\n"
	got, err := parseTCPSockets(strings.NewReader(input), []string{"192.0.2.10"}, []string{"192.0.2.10"})
	want := []tcpSocket{{Local: netip.MustParseAddrPort("192.0.2.10:22"), Remote: netip.MustParseAddrPort("198.51.100.30:50000")}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4-mapped socket lost or native IPv6 included: %#v, %v", got, err)
	}
}

func TestEstablishedSocketsIncludeIdleConnectionsAndExcludeLocal(t *testing.T) {
	input := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	for i, row := range []struct{ local, remote, state string }{
		{procEndpoint("192.0.2.10", 40000), procEndpoint("198.51.100.20", 443), "01"},
		{procEndpoint("192.0.2.10", 22), procEndpoint("198.51.100.30", 50000), "01"},
		{procEndpoint("192.0.2.10", 22), procEndpoint("0.0.0.0", 0), "0A"},
		{procEndpoint("172.17.0.1", 40000), procEndpoint("198.51.100.20", 443), "01"},
		{procEndpoint("192.0.2.10", 40000), procEndpoint("172.17.0.1", 443), "01"},
		{procEndpoint("192.0.2.10", 40000), procEndpoint("127.0.0.2", 443), "01"},
		{procEndpoint("192.0.2.10", 40000), procEndpoint("198.51.100.20", 443), "01"},
		{procEndpoint("192.0.2.10", 40000), procEndpoint("198.51.100.40", 443), "06"},
	} {
		input += fmt.Sprintf("%d: %s %s %s 00000000:00000000 00:00000000 00000000 1000 0 100\n", i, row.local, row.remote, row.state)
	}
	got, err := parseTCPSockets(strings.NewReader(input), []string{"192.0.2.10", "172.17.0.1"}, []string{"192.0.2.10"})
	want := []tcpSocket{
		{Local: netip.MustParseAddrPort("192.0.2.10:22"), Remote: netip.MustParseAddrPort("198.51.100.30:50000")},
		{Local: netip.MustParseAddrPort("192.0.2.10:40000"), Remote: netip.MustParseAddrPort("198.51.100.20:443")},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("established sockets = %#v, error=%v", got, err)
	}
	for _, malformed := range []string{"", "corrupt header\n", "sl local_address rem_address st\n0: broken 146433C6:01BB 01\n", "sl local_address rem_address st\n0: 0A0200C0:10000 146433C6:01BB 01\n"} {
		if _, err := parseTCPSockets(strings.NewReader(malformed), nil, nil); err == nil {
			t.Fatalf("corrupt snapshot accepted as empty: %q", malformed)
		}
	}
}

func TestSocketSnapshotRetainsRawAndReportsUnavailableSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "tcp")
	data := []byte("sl local_address rem_address st\n0: " + procEndpoint("192.0.2.10", 40000) + " " + procEndpoint("198.51.100.20", 443) + " 01\n")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tcp6"), []byte("sl local_address remote_address st\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotTCP(dir, dir, "before", []string{"192.0.2.10"}, []string{"192.0.2.10"})
	if err != nil || snapshot.Problem != "" || len(snapshot.Sockets) != 1 || snapshot.Taken.IsZero() {
		t.Fatalf("snapshot = %#v, error=%v", snapshot, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tcp-before.txt"))
	info, statErr := os.Stat(filepath.Join(dir, "tcp-before.txt"))
	if err != nil || statErr != nil || string(raw) != string(data) || info.Mode().Perm() != 0600 {
		t.Fatalf("raw bytes/permissions lost: read=%v, stat=%v", err, statErr)
	}
	missing, err := snapshotTCP(filepath.Join(dir, "missing"), dir, "after", nil, nil)
	if err != nil || missing.Problem == "" {
		t.Fatalf("unavailable snapshot was not diagnosed: %#v, %v", missing, err)
	}
	if _, err := snapshotTCP(dir, filepath.Join(dir, "missing-dir"), "snapshot", nil, nil); err == nil {
		t.Fatal("failed raw write accepted")
	}
	if err := os.WriteFile(source, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	corrupt, err := snapshotTCP(dir, dir, "corrupt", nil, nil)
	if err != nil || corrupt.Problem == "" || len(corrupt.Sockets) != 0 {
		t.Fatalf("corrupt snapshot was not diagnosed: %#v, %v", corrupt, err)
	}
	txt := formatReport(report{TCPBefore: snapshot, TCPAfter: missing, Names: map[string]string{"198.51.100.20": "idle.example"}})
	for _, value := range []string{"ESTABLISHED", "192.0.2.10:40000", "198.51.100.20:443", "idle.example", "+", "?", missing.Problem} {
		if !strings.Contains(txt, value) {
			t.Fatalf("missing %q in snapshot report:\n%s", value, txt)
		}
	}
}

func TestSocketSnapshotKeepsAvailableTableWhenOtherTableIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte("sl local_address rem_address st\n0: "+procEndpoint("192.0.2.10", 22)+" "+procEndpoint("198.51.100.30", 50000)+" 01\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tcp6"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotTCP(dir, dir, "before", []string{"192.0.2.10"}, []string{"192.0.2.10"})
	if err != nil || len(snapshot.Sockets) != 1 || !strings.Contains(snapshot.Problem, "tcp6") {
		t.Fatalf("valid partial snapshot was lost: %#v, %v", snapshot, err)
	}
	other := tcpSocket{Local: netip.MustParseAddrPort("192.0.2.10:40000"), Remote: netip.MustParseAddrPort("198.51.100.20:443")}
	after := tcpSnapshot{Taken: snapshot.Taken, Sockets: []tcpSocket{other}}
	var text strings.Builder
	writeSocketReport(&text, snapshot, after, nil)
	for _, want := range []string{"192.0.2.10:22 198.51.100.30:50000 + -", "192.0.2.10:40000 198.51.100.20:443 ? +"} {
		found := false
		for _, line := range strings.Split(text.String(), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && strings.Join(fields[:4], " ") == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("absence confused with unavailable snapshot, missing %q:\n%s", want, text.String())
		}
	}
}
