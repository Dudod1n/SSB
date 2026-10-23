// ssb collects TCP SYN and UDP observations plus established IPv4 sockets.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const version = "0.1.0-dev"
const captureFilter = "ip and ((tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or udp)"
const help = `Использование: ssb [--plain] [секунды]
По умолчанию 60 секунд. Нужны tcpdump и права на захват пакетов.
Сбор: TCP SYN, UDP/IPv4 и снимки установленных TCP/IPv4-соединений.
Результат: TXT-отчёт и каталог raw/; JSON и схемы не создаются.

В терминале запускается TUI: 1/2/3/4 или Tab — вид, ↑↓/j/k — строка,
/ — поиск, Esc — сброс, s — сортировка, r — новый захват,
e — полный TXT в текущий каталог, q или Ctrl+C — выход.
Нужен UTF-8 терминал от 45×19, желательно 100×30.
--plain, перенаправление вывода или TERM=dumb включают обычный текст.
--version — версия.`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("SSB v" + version + "\n" + help)
		return 0
	}
	if len(args) == 1 && args[0] == "--version" {
		fmt.Println("SSB v" + version)
		return 0
	}
	var durationArgs []string
	plainMode := false
	for _, arg := range args {
		if arg == "--plain" {
			plainMode = true
		} else {
			durationArgs = append(durationArgs, arg)
		}
	}
	duration, err := parseDuration(durationArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !plainMode && os.Getenv("TERM") != "" && os.Getenv("TERM") != "dumb" {
		old, inputErr := terminalState()
		_, _, outputErr := terminalSize()
		if inputErr == nil && outputErr == nil {
			code, err := interactive(old, newTUIModel(duration), collectReport)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Ошибка:", err)
				return 1
			}
			return code
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := collect(ctx, duration, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		return 1
	}
	return 0
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
	return 0, fmt.Errorf("использование: ssb [--plain] [секунды]; длительность должна быть положительным целым числом")
}

func safeHostname(hostname string) string {
	name := regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(hostname, "_")
	if name == "" {
		return "unknown"
	}
	return name
}
