package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	phasePrepare = "Подготовка"
	phaseCapture = "Захват"
	phaseParse   = "Обработка"
	phaseDNS     = "Поиск имён"
	phaseSave    = "Сохранение"
	phaseReady   = "Готово"
	phaseError   = "Ошибка"
)

type collectionResult struct {
	Report          report
	Directory, Path string
}

type collectionUpdate struct {
	Phase string
	Data  collectionResult
}

type collectionFunc func(context.Context, time.Duration, func(collectionUpdate) error) (collectionResult, error)

func collect(ctx context.Context, duration time.Duration, out io.Writer) error {
	result, err := collectReport(ctx, duration, func(update collectionUpdate) error {
		if update.Phase == phaseCapture {
			_, err := fmt.Fprintf(out, "Сбор TCP SYN, UDP и установленных TCP/IPv4-соединений: %.0f секунд. Каталог: %s\n", duration.Seconds(), update.Data.Directory)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if _, err := io.WriteString(out, formatReport(result.Report)); err != nil {
		return fmt.Errorf("%w; данные сохранены в %s", err, result.Directory)
	}
	_, err = fmt.Fprintf(out, "\nОтчёт сохранён: %s\n", result.Path)
	return err
}

func collectReport(ctx context.Context, duration time.Duration, notify func(collectionUpdate) error) (result collectionResult, err error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := exec.LookPath("tcpdump"); err != nil {
		return result, fmt.Errorf("не найдена команда tcpdump: %w", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return result, err
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return result, err
	}
	var snapshot []string
	for _, address := range interfaces {
		snapshot = append(snapshot, address.String())
	}
	all, addresses, cidrs, err := selectAddresses(snapshot)
	if err != nil {
		return result, err
	}
	if len(addresses) == 0 {
		return result, fmt.Errorf("у ВМ не найдены IPv4-адреса после исключения 127.0.0.1 и 172.x.x.x")
	}
	result.Report = report{Hostname: hostname, Addresses: addresses, CIDRs: cidrs, Duration: duration}
	r := &result.Report
	dir, err := os.MkdirTemp(".", "tcp-report-"+time.Now().Format("20060102-150405")+"-")
	if err != nil {
		return result, err
	}
	result.Directory = dir
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w; данные сохранены в %s", err, dir)
		}
	}()
	publish := func(phase string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if notify != nil {
			return notify(collectionUpdate{Phase: phase, Data: result})
		}
		return nil
	}
	raw := filepath.Join(dir, "raw")
	if err := os.Mkdir(raw, 0700); err != nil {
		return result, err
	}
	if err := os.WriteFile(filepath.Join(raw, "interface-addresses.txt"), []byte(strings.Join(uniqueStrings(snapshot), "\n")+"\n"), 0600); err != nil {
		return result, err
	}
	if err := publish(phasePrepare); err != nil {
		return result, err
	}
	r.TCPBefore, err = snapshotTCP("/proc/net", raw, "before", all, addresses)
	if err != nil {
		return result, err
	}
	r.Started = time.Now()
	if err := publish(phaseCapture); err != nil {
		return result, err
	}
	if err := capture(ctx, duration, raw); err != nil {
		diagnostic, _ := os.ReadFile(filepath.Join(raw, "capture.log"))
		return result, fmt.Errorf("ошибка захвата (проверьте права на tcpdump): %w\n%s", err, diagnostic)
	}
	r.Finished = time.Now()
	if err := publish(phaseParse); err != nil {
		return result, err
	}
	r.TCPAfter, err = snapshotTCP("/proc/net", raw, "after", all, addresses)
	if err != nil {
		return result, err
	}
	packets, err := os.Open(filepath.Join(raw, "packets.log"))
	if err != nil {
		return result, err
	}
	bad, err := os.OpenFile(filepath.Join(raw, "parse-errors.txt"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		packets.Close()
		return result, err
	}
	r.Links, r.Unparsed, err = parseCapture(packets, all, addresses, bad)
	if err = errors.Join(err, packets.Close(), bad.Close()); err != nil {
		return result, err
	}
	diagnostic, err := os.ReadFile(filepath.Join(raw, "capture.log"))
	if err != nil {
		return result, err
	}
	r.Diagnostics = string(diagnostic)
	ips := append([]string{}, addresses...)
	for _, connection := range r.Links {
		ips = append(ips, connection.Source, connection.Destination)
	}
	for _, snapshot := range []tcpSnapshot{r.TCPBefore, r.TCPAfter} {
		for _, socket := range snapshot.Sockets {
			ips = append(ips, socket.Remote.Addr().String())
		}
	}
	if err := publish(phaseDNS); err != nil {
		return result, err
	}
	r.Names, r.ResolutionStatus = resolveNames(ctx, uniqueStrings(ips), net.DefaultResolver.LookupAddr)
	if err := publish(phaseSave); err != nil {
		return result, err
	}
	name := filepath.Join(dir, "report_"+safeHostname(hostname)+".txt")
	if err := os.WriteFile(name+".tmp", []byte(formatReport(*r)), 0600); err != nil {
		return result, err
	}
	if err := os.Rename(name+".tmp", name); err != nil {
		return result, err
	}
	result.Path = name
	return result, nil
}
