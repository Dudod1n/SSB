package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCollectionPipelineWithControlledTCPDump(t *testing.T) {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip("OS integration requires read access to interface metadata")
	}
	var snapshot []string
	for _, address := range interfaces {
		snapshot = append(snapshot, address.String())
	}
	_, addresses, _, err := selectAddresses(snapshot)
	if err != nil || len(addresses) == 0 {
		t.Skip("OS integration requires a non-excluded local IPv4 address")
	}
	dir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Error(err)
		}
	})
	script := "#!/bin/sh\nprintf 'IP 198.51.100.12.40000 > %s.22: tcp 0\\n' \"$SSB_TEST_LOCAL_IP\"\nprintf 'IP %s.40001 > 203.0.113.53.53: UDP, length 12\\n' \"$SSB_TEST_LOCAL_IP\"\n"
	if err := os.WriteFile(filepath.Join(dir, "tcpdump"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SSB_TEST_LOCAL_IP", addresses[0])
	previousResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("DNS disabled in controlled test")
	}}
	t.Cleanup(func() { net.DefaultResolver = previousResolver })
	var stages []string
	result, err := collectReport(context.Background(), time.Second, func(update collectionUpdate) error {
		stages = append(stages, update.Phase)
		return nil
	})
	if err != nil {
		t.Fatalf("controlled collection: %v", err)
	}
	if !reflect.DeepEqual(stages, []string{phasePrepare, phaseCapture, phaseParse, phaseDNS, phaseSave}) || len(result.Report.Links) != 2 || result.Path == "" {
		t.Fatal("stages, packet observations or final TXT missing")
	}
	if result.Report.Saved.IsZero() || result.Report.Saved.Before(result.Report.Finished) || result.Report.Saved.After(time.Now()) {
		t.Fatal("report save time must be recorded after capture")
	}
	automatic, err := os.ReadFile(result.Path)
	if err != nil || !bytes.Contains(automatic, []byte("Сохранён: "+result.Report.Saved.UTC().Format(time.RFC3339))) {
		t.Fatalf("automatic report lost its save time: %v", err)
	}
	exported, err := exportReport(dir, tuiModel{data: result, phase: phaseReady, group: 3, query: "no-match.example"})
	if err != nil {
		t.Fatal(err)
	}
	copy, err := os.ReadFile(exported)
	if err != nil || !bytes.Equal(automatic, copy) {
		t.Fatalf("filtered TUI export differs from automatic TXT: %v", err)
	}
	info, err := os.Stat(result.Directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("report directory permissions: %v", err)
	}
	if err := filepath.WalkDir(result.Directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if entry.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Errorf("wrong permissions for %s", filepath.Base(path))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	partial, err := collectReport(ctx, time.Second, func(update collectionUpdate) error {
		if update.Phase == phaseDNS {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || partial.Directory == "" || partial.Path != "" || partial.Directory == result.Directory {
		t.Fatal("canceled run overwrote an earlier report or lost raw directory")
	}
	if files, _ := filepath.Glob(filepath.Join(partial.Directory, "report_*.txt")); len(files) != 0 {
		t.Fatal("canceled run was saved as a complete report")
	}
	var output bytes.Buffer
	if err := collect(context.Background(), time.Second, &output); err != nil || !strings.Contains(output.String(), "Отчёт сохранён:") || strings.ContainsRune(output.String(), '\x1b') {
		t.Fatalf("plain collector output failed: %v", err)
	}
	_, path, ok := strings.Cut(output.String(), "\nОтчёт сохранён: ")
	plain, err := os.ReadFile(strings.TrimSpace(path))
	if !ok || err != nil || !bytes.Contains(output.Bytes(), plain) {
		t.Fatalf("plain output differs from its saved TXT: %v", err)
	}
}
