// ssb collects TCP/IPv4 SYN attempts and writes a private TXT report.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const captureFilter = "ip and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		fmt.Println("Использование: ssb [секунды]\nПо умолчанию 60 секунд. Нужны tcpdump и права на захват пакетов.\nРезультат: TXT-отчёт и каталог raw/; JSON и схемы не создаются.")
		return
	}
	duration, err := parseDuration(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := collect(ctx, duration, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func parseDuration(args []string) (time.Duration, error) {
	if len(args) == 0 {
		return time.Minute, nil
	}
	if len(args) == 1 && regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(args[0]) {
		seconds, err := strconv.ParseInt(args[0], 10, 64)
		if err == nil && seconds <= int64((1<<63-1)/time.Second) {
			return time.Duration(seconds) * time.Second, nil
		}
	}
	return 0, fmt.Errorf("использование: ssb [секунды]; длительность должна быть положительным целым числом")
}

func collect(ctx context.Context, duration time.Duration, out io.Writer) (err error) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return fmt.Errorf("не найдена команда tcpdump: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	var snapshot []string
	for _, address := range interfaces {
		snapshot = append(snapshot, address.String())
	}
	all, addresses, cidrs, err := selectAddresses(snapshot)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return fmt.Errorf("у ВМ не найдены IPv4-адреса после исключения 127.0.0.1 и 172.x.x.x")
	}
	dir, err := os.MkdirTemp(".", "tcp-report-"+time.Now().Format("20060102-150405")+"-")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w; данные сохранены в %s", err, dir)
		}
	}()
	raw := filepath.Join(dir, "raw")
	if err := os.Mkdir(raw, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(raw, "interface-addresses.txt"),
		[]byte(strings.Join(uniqueStrings(snapshot), "\n")+"\n"), 0600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Сбор новых TCP/IPv4-подключений: %.0f секунд. Каталог: %s\n", duration.Seconds(), dir); err != nil {
		return err
	}
	r := report{Hostname: hostname, Addresses: addresses, CIDRs: cidrs, Duration: duration, Started: time.Now()}
	if err := capture(ctx, duration, raw); err != nil {
		diagnostic, _ := os.ReadFile(filepath.Join(raw, "capture.log"))
		return fmt.Errorf("ошибка захвата (проверьте права на tcpdump): %w\n%s", err, diagnostic)
	}
	r.Finished = time.Now()
	packets, err := os.Open(filepath.Join(raw, "syn.log"))
	if err != nil {
		return err
	}
	bad, err := os.OpenFile(filepath.Join(raw, "parse-errors.txt"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		packets.Close()
		return err
	}
	r.Links, r.Unparsed, err = parseCapture(packets, all, addresses, bad)
	if err = errors.Join(err, packets.Close(), bad.Close()); err != nil {
		return err
	}
	diagnostic, err := os.ReadFile(filepath.Join(raw, "capture.log"))
	if err != nil {
		return err
	}
	r.Diagnostics = string(diagnostic)
	ips := append([]string{}, addresses...)
	for _, connection := range r.Links {
		ips = append(ips, connection.Source, connection.Destination)
	}
	r.Names, r.ResolutionStatus = resolveNames(ctx, uniqueStrings(ips), net.DefaultResolver.LookupAddr)
	if err := ctx.Err(); err != nil {
		return err
	}
	text := formatReport(r)
	name := filepath.Join(dir, "report_"+safeHostname(hostname)+".txt")
	if err := os.WriteFile(name+".tmp", []byte(text), 0600); err != nil {
		return err
	}
	if err := os.Rename(name+".tmp", name); err != nil {
		return err
	}
	if _, err := io.WriteString(out, text); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "\nОтчёт сохранён: %s\n", name)
	return err
}

func safeHostname(hostname string) string {
	name := regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(hostname, "_")
	if name == "" {
		return "unknown"
	}
	return name
}
