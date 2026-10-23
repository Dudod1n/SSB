package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureOfflineFiltersTCPAndUDPWithoutApplicationData(t *testing.T) {
	actual, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("offline capture check requires tcpdump")
	}
	actual, err = filepath.Abs(actual)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var pcap bytes.Buffer
	if err := binary.Write(&pcap, binary.LittleEndian, []uint32{0xa1b2c3d4, 0x00040002, 0, 0, 65535, 101}); err != nil {
		t.Fatal(err)
	}
	ipv4 := func(protocol byte, body []byte) []byte {
		ip := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0, 198, 51, 100, 12, 192, 0, 2, 10}
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)+len(body)))
		return append(ip, body...)
	}
	tcp := func(flags byte) []byte {
		return ipv4(6, []byte{0x9c, 0x40, 0, 53, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0})
	}
	dns := []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07private\x07example\x00\x00\x01\x00\x01")
	udp := append([]byte{0x9c, 0x41, 0, 53, 0, 0, 0, 0}, dns...)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	ipv6 := make([]byte, 40)
	ipv6[0], ipv6[6], ipv6[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(udp)))
	ipv6[23], ipv6[39] = 1, 2
	for _, packet := range [][]byte{tcp(2), tcp(2), tcp(0x12), tcp(0x10), ipv4(17, udp), ipv4(17, udp), append(ipv6, udp...)} {
		if err := binary.Write(&pcap, binary.LittleEndian, []uint32{1792756800, 0, uint32(len(packet)), uint32(len(packet))}); err != nil {
			t.Fatal(err)
		}
		pcap.Write(packet)
	}
	fixture := filepath.Join(dir, "packets.pcap")
	if err := os.WriteFile(fixture, pcap.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	// -r always reads this artificial file; no interface traffic is captured.
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte("#!/bin/sh\nexec \"$SSB_REAL_TCPDUMP\" -r \"$SSB_PCAP_FIXTURE\" \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSB_REAL_TCPDUMP", actual)
	t.Setenv("SSB_PCAP_FIXTURE", fixture)
	t.Setenv("PATH", dir)
	if err := capture(context.Background(), time.Second, dir); err != nil {
		diagnostic, _ := os.ReadFile(filepath.Join(dir, "capture.log"))
		t.Fatalf("offline capture: %v, %s", err, diagnostic)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "packets.log"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private")) || bytes.Contains(raw, []byte("example")) {
		t.Fatalf("UDP application data leaked into raw output: %s", raw)
	}
	var bad strings.Builder
	links, unparsed, err := parseCapture(bytes.NewReader(raw), []string{"192.0.2.10"}, []string{"192.0.2.10"}, &bad)
	if err != nil || len(links) != 2 || unparsed != 0 {
		t.Fatalf("offline parse: %#v, unparsed=%d, error=%v, raw=%s", links, unparsed, err, raw)
	}
	for _, connection := range links {
		if connection.Packets != 2 || connection.Port != 53 {
			t.Fatalf("SYN/ACK, ACK or IPv6 was counted, or UDP was lost: %#v", links)
		}
	}
}
