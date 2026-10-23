package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type link struct {
	Source, Destination string
	Port                int
	Direction           string
	Protocol            string
	Packets             uint64
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		seen[value] = true
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func selectAddresses(snapshot []string) (all, addresses, cidrs []string, err error) {
	for _, value := range snapshot {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, nil, err
		}
		if !prefix.Addr().Is4() {
			continue
		}
		ip := prefix.Addr().String()
		all = append(all, ip)
		if ip != "127.0.0.1" && !strings.HasPrefix(ip, "172.") {
			addresses = append(addresses, ip)
			cidrs = append(cidrs, prefix.String())
		}
	}
	return uniqueStrings(all), uniqueStrings(addresses), uniqueStrings(cidrs), nil
}

func endpoint(value string) (string, int, bool) {
	position := strings.LastIndexByte(value, '.')
	if position < 0 {
		return "", 0, false
	}
	ip, err := netip.ParseAddr(value[:position])
	if err != nil || !ip.Is4() {
		return "", 0, false
	}
	port := value[position+1:]
	if port == "" || strings.IndexFunc(port, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
		return "", 0, false
	}
	number, err := strconv.ParseUint(port, 10, 16)
	return ip.String(), int(number), err == nil
}

func parseCapture(input io.Reader, all, published []string, bad io.Writer) ([]link, int, error) {
	own, allowed := make(map[string]bool), make(map[string]bool)
	for _, ip := range all {
		own[ip] = true
	}
	for _, ip := range published {
		allowed[ip] = true
	}
	seen := make(map[link]uint64)
	unparsed := 0
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		parsed := false
		for i := 1; i+2 < len(fields); i++ {
			if fields[i] != ">" {
				continue
			}
			source, _, sourceOK := endpoint(fields[i-1])
			destination, port, destinationOK := endpoint(strings.TrimSuffix(fields[i+1], ":"))
			if !sourceOK || !destinationOK {
				break
			}
			protocol := ""
			switch fields[i+2] {
			case "tcp":
				// The capture filter admits only SYN without ACK in quiet output.
				protocol = "TCP"
			case "UDP,":
				protocol = "UDP"
			case "Flags":
				if i+3 >= len(fields) {
					break
				}
				flags := fields[i+3]
				if strings.Contains(flags, "S") && !strings.Contains(flags, ".") {
					protocol = "TCP"
				} else {
					parsed = true
				}
			}
			if protocol == "" {
				break
			}
			parsed = true
			srcLocal := own[source] || strings.HasPrefix(source, "127.")
			dstLocal := own[destination] || strings.HasPrefix(destination, "127.")
			if !srcLocal && allowed[destination] {
				seen[link{Source: source, Destination: destination, Port: port, Direction: "incoming", Protocol: protocol}]++
			} else if allowed[source] && !dstLocal {
				seen[link{Source: source, Destination: destination, Port: port, Direction: "outgoing", Protocol: protocol}]++
			}
			break
		}
		if !parsed {
			unparsed++
			if _, err := fmt.Fprintln(bad, line); err != nil {
				return nil, unparsed, err
			}
		}
	}
	links := make([]link, 0, len(seen))
	for connection, count := range seen {
		connection.Packets = count
		links = append(links, connection)
	}
	sort.Slice(links, func(i, j int) bool {
		a, b := links[i], links[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Protocol < b.Protocol
	})
	return links, unparsed, scanner.Err()
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

func resolveNames(parent context.Context, ips []string, lookup func(context.Context, string) ([]string, error)) (map[string]string, string) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	result := make(map[string]string)
	for _, ip := range ips {
		if ctx.Err() != nil {
			return result, "budget_exhausted"
		}
		request, cancel := context.WithTimeout(ctx, 2*time.Second)
		names, _ := lookup(request, ip)
		cancel()
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			if name != ip && len(name) <= 253 && validName.MatchString(name) {
				result[ip] = name
				break
			}
		}
	}
	if ctx.Err() != nil {
		return result, "budget_exhausted"
	}
	return result, "complete"
}
