package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type report struct {
	Hostname            string
	Addresses, CIDRs    []string
	Started, Finished   time.Time
	Saved               time.Time
	Duration            time.Duration
	Links               []link
	TCPBefore, TCPAfter tcpSnapshot
	Unparsed            int
	Diagnostics         string
	Names               map[string]string
	ResolutionStatus    string
}

func counter(diagnostic, suffix string) string {
	for _, line := range strings.Split(diagnostic, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && (fields[1] == "packet" || fields[1] == "packets") && strings.Join(fields[2:], " ") == suffix {
			if _, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
				return fields[0]
			}
		}
	}
	return "неизвестно"
}

func formatReport(r report) string {
	var text strings.Builder
	incoming, outgoing, packetWidth := 0, 0, 6
	for _, connection := range r.Links {
		switch connection.Direction {
		case "incoming":
			incoming++
		case "outgoing":
			outgoing++
		}
		packetWidth = max(packetWidth, len(strconv.FormatUint(connection.Packets, 10)))
	}
	saved := "неизвестно"
	if !r.Saved.IsZero() {
		saved = r.Saved.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(&text, "SSB v%s | ОТЧЁТ TCP/UDP IPv4\nСохранён: %s\n", version, saved)
	fmt.Fprintf(&text, "Хост запуска: %s (%s)\n", clean(r.Hostname), clean(strings.Join(r.Addresses, ", ")))
	fmt.Fprintf(&text, "Окно наблюдения: %g с\n", r.Finished.Sub(r.Started).Round(time.Millisecond).Seconds())
	fmt.Fprintf(&text, "Период: %s — %s | задано: %.0f с\n", r.Started.Format(time.RFC3339), r.Finished.Format(time.RFC3339), r.Duration.Seconds())
	fmt.Fprintf(&text, "IPv4/CIDR: %s\n", clean(strings.Join(r.CIDRs, ", ")))
	fmt.Fprintf(&text, "Всего обращений: %d | входящих: %d | исходящих: %d\n", incoming+outgoing, incoming, outgoing)
	for _, group := range []struct{ direction, title string }{{"incoming", "ВХОДЯЩИЕ"}, {"outgoing", "ИСХОДЯЩИЕ"}} {
		fmt.Fprintf(&text, "\n%s\n", group.title)
		fmt.Fprintf(&text, "%-16s %-16s %5s %-8s %*s %s\n", "Отправитель", "Получатель", "Порт", "Протокол", packetWidth, "Пакеты", "Имя удалённого узла")
		count := 0
		for _, connection := range r.Links {
			if connection.Direction != group.direction {
				continue
			}
			peer := connection.Source
			if group.direction == "outgoing" {
				peer = connection.Destination
			}
			name := clean(r.Names[peer])
			if name == "" {
				name = "-"
			}
			fmt.Fprintf(&text, "%-16s %-16s %5d %-8s %*d %s\n", connection.Source, connection.Destination, connection.Port, connection.Protocol, packetWidth, connection.Packets, name)
			count++
		}
		if count == 0 {
			fmt.Fprintln(&text, "За время наблюдения обращений не обнаружено.")
		}
	}
	writeSocketReport(&text, r.TCPBefore, r.TCPAfter, r.Names)
	fmt.Fprintln(&text, "\nОбращения — строки таблиц захвата: протокол, IP отправителя/получателя и порт назначения. Порты отправителей остаются в raw/packets.log.")
	fmt.Fprintln(&text, "Пакеты: TCP — SYN без ACK, UDP — наблюдаемые дейтаграммы. Повторы включены; счётчик не доказывает успешность TCP или доставку UDP.")
	fmt.Fprintln(&text, "Источник имён: /etc/hosts и системные DNS-серверы через Go; «-» — имя не получено.")
	if r.ResolutionStatus == "budget_exhausted" {
		fmt.Fprintln(&text, "Бюджет поиска имён исчерпан: часть IP осталась без имени.")
	}
	fmt.Fprintln(&text, "Установленные TCP взяты из /proc/net/tcp и tcp6 (IPv4-mapped) в начале и конце захвата в текущем сетевом пространстве имён, включая соединения без трафика.")
	fmt.Fprintln(&text, "Инициатор ранее открытого соединения неизвестен. Два снимка не доказывают непрерывность; соединения, жившие только между снимками, могли не попасть в таблицу.")
	fmt.Fprintln(&text, "IPv6, локальные обращения и транзит не учитываются. Адреса ВМ 127.0.0.1 и 172.x.x.x и обращения через них исключены.")
	fmt.Fprintf(&text, "Адреса ВМ взяты на старте. Неразобранных строк захвата: %d\n", r.Unparsed)
	fmt.Fprintf(&text, "Захвачено пакетов: %s; получено фильтром: %s; потеряно ядром: %s.\n", counter(r.Diagnostics, "captured"), counter(r.Diagnostics, "received by filter"), counter(r.Diagnostics, "dropped by kernel"))
	if r.Diagnostics != "" {
		fmt.Fprintln(&text, "\nДиагностика захвата (включая потери пакетов):")
		for _, diagnostic := range strings.Split(strings.TrimSuffix(r.Diagnostics, "\n"), "\n") {
			fmt.Fprintln(&text, clean(diagnostic))
		}
	}
	return text.String()
}

func writeSocketReport(text *strings.Builder, before, after tcpSnapshot, names map[string]string) {
	fmt.Fprintln(text, "\nУСТАНОВЛЕННЫЕ TCP-СОЕДИНЕНИЯ (ESTABLISHED)")
	seen := make(map[tcpSocket]bool)
	presence := make(map[tcpSocket][2]bool)
	for i, snapshot := range []tcpSnapshot{before, after} {
		label := "Начало"
		if i == 1 {
			label = "Конец"
		}
		if snapshot.Taken.IsZero() {
			fmt.Fprintf(text, "%s: снимок не выполнялся.\n", label)
		} else if snapshot.Problem != "" {
			fmt.Fprintf(text, "%s (%s): снимок неполный/недоступен — %s\n", label, snapshot.Taken.Format(time.RFC3339), clean(snapshot.Problem))
		} else {
			fmt.Fprintf(text, "%s (%s): снимок получен, соединений: %d.\n", label, snapshot.Taken.Format(time.RFC3339), len(snapshot.Sockets))
		}
		for _, socket := range snapshot.Sockets {
			seen[socket] = true
			marks := presence[socket]
			marks[i] = true
			presence[socket] = marks
		}
	}
	if len(seen) == 0 {
		fmt.Fprintln(text, "В доступных снимках установленных внешних соединений не найдено.")
		return
	}
	fmt.Fprintf(text, "%-22s %-22s %-6s %-6s %s\n", "Локальный адрес", "Удалённый адрес", "Начало", "Конец", "Имя удалённого узла")
	for _, socket := range sortedSockets(seen) {
		name := clean(names[socket.Remote.Addr().String()])
		if name == "" {
			name = "-"
		}
		marks := presence[socket]
		fmt.Fprintf(text, "%-22s %-22s %-6s %-6s %s\n", socket.Local, socket.Remote, snapshotMark(marks[0], before), snapshotMark(marks[1], after), name)
	}
	fmt.Fprintln(text, "+ — есть в снимке; - — не найден; ? — снимок неполный/недоступен. Локальный/удалённый адреса не определяют инициатора.")
}
