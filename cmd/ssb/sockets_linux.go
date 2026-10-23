package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type tcpSocket struct {
	Local, Remote netip.AddrPort
}

type tcpSnapshot struct {
	Taken   time.Time
	Sockets []tcpSocket
	Problem string
}

func snapshotMark(present bool, snapshot tcpSnapshot) string {
	if present {
		return "+"
	}
	if snapshot.Taken.IsZero() || snapshot.Problem != "" {
		return "?"
	}
	return "-"
}

func procAddrPort(value string) (netip.AddrPort, error) {
	address, port, ok := strings.Cut(value, ":")
	if !ok || (len(address) != 8 && len(address) != 32) || len(port) != 4 {
		return netip.AddrPort{}, fmt.Errorf("неверный формат адреса сокета")
	}
	number, portErr := strconv.ParseUint(port, 16, 16)
	if portErr != nil {
		return netip.AddrPort{}, fmt.Errorf("неверный порт сокета")
	}
	var octets [16]byte
	for i := 0; i < len(address); i += 8 {
		word, err := strconv.ParseUint(address[i:i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("неверный IP сокета")
		}
		binary.NativeEndian.PutUint32(octets[i/2:i/2+4], uint32(word))
	}
	ip := netip.AddrFrom16(octets).Unmap()
	if len(address) == 8 {
		ip = netip.AddrFrom4([4]byte(octets[:4]))
	}
	return netip.AddrPortFrom(ip, uint16(number)), nil
}

func parseTCPSockets(input io.Reader, all, published []string) ([]tcpSocket, error) {
	scanner := bufio.NewScanner(input)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("таблица TCP пуста: нет заголовка")
	}
	header := strings.Fields(scanner.Text())
	if len(header) < 4 || header[0] != "sl" || header[1] != "local_address" || (header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" {
		return nil, fmt.Errorf("неизвестный заголовок таблицы TCP")
	}
	seen := make(map[tcpSocket]bool)
	for line := 2; scanner.Scan(); line++ {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("неполная строка таблицы TCP: %d", line)
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("неверное состояние TCP в строке %d", line)
		}
		if state != 1 { // TCP_ESTABLISHED; listening and closing sockets are not open connections.
			continue
		}
		local, localErr := procAddrPort(fields[1])
		remote, remoteErr := procAddrPort(fields[2])
		if localErr != nil || remoteErr != nil {
			return nil, fmt.Errorf("неверный адрес сокета в строке %d", line)
		}
		if local.Addr().Is4() && remote.Addr().Is4() && slices.Contains(published, local.Addr().String()) && !slices.Contains(all, remote.Addr().String()) && !remote.Addr().IsLoopback() {
			seen[tcpSocket{Local: local, Remote: remote}] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sortedSockets(seen), nil
}

func sortedSockets(seen map[tcpSocket]bool) []tcpSocket {
	result := make([]tcpSocket, 0, len(seen))
	for socket := range seen {
		result = append(result, socket)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Local != result[j].Local {
			return result[i].Local.String() < result[j].Local.String()
		}
		return result[i].Remote.String() < result[j].Remote.String()
	})
	return result
}

func snapshotTCP(sourceDir, rawDir, phase string, all, published []string) (tcpSnapshot, error) {
	snapshot := tcpSnapshot{Taken: time.Now()}
	seen := make(map[tcpSocket]bool)
	var problems []string
	// shortcut: /proc is the simple snapshot API; use tcp_diag if a supported kernel removes it.
	for _, table := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(sourceDir, table))
		if err != nil {
			problems = append(problems, fmt.Sprintf("не удалось прочитать %s: %v", table, err))
			continue
		}
		if err := os.WriteFile(filepath.Join(rawDir, table+"-"+phase+".txt"), data, 0600); err != nil {
			return snapshot, err
		}
		sockets, err := parseTCPSockets(bytes.NewReader(data), all, published)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", table, err))
			continue
		}
		for _, socket := range sockets {
			seen[socket] = true
		}
	}
	snapshot.Sockets = sortedSockets(seen)
	snapshot.Problem = strings.Join(problems, "; ")
	return snapshot, nil
}
