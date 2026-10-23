package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type report struct {
	Hostname            string
	Addresses, CIDRs    []string
	Started, Finished   time.Time
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
	fmt.Fprintf(&text, "ОТЧЁТ TCP/UDP IPv4: %s — %s\n", r.Started.Format(time.RFC3339), r.Finished.Format(time.RFC3339))
	fmt.Fprintf(&text, "ВМ: %s\nЗаданная длительность: %.0f секунд\n", r.Hostname, r.Duration.Seconds())
	fmt.Fprintf(&text, "IPv4-адреса ВМ: %s\nIPv4-адреса ВМ с масками (CIDR): %s\n", strings.Join(r.Addresses, ","), strings.Join(r.CIDRs, ","))
	for _, group := range []struct{ direction, title, first, second string }{
		{"incoming", "ВХОДЯЩИЕ: внешний отправитель → ВМ", "REMOTE_IP", "VM_IP"},
		{"outgoing", "ИСХОДЯЩИЕ: ВМ → внешний получатель", "VM_IP", "REMOTE_IP"},
	} {
		fmt.Fprintf(&text, "\n%s\n", group.title)
		var peers []string
		ports := make(map[int]bool)
		for _, connection := range r.Links {
			if connection.Direction != group.direction {
				continue
			}
			if len(peers) == 0 {
				fmt.Fprintf(&text, "%-18s %-18s %-8s %-5s %s\n", group.first, group.second, "DST_PORT", "PROTO", "ПАКЕТЫ")
			}
			fmt.Fprintf(&text, "%-18s %-18s %-8d %-5s %d\n", connection.Source, connection.Destination, connection.Port, connection.Protocol, connection.Packets)
			peer := connection.Source
			if group.direction == "outgoing" {
				peer = connection.Destination
			}
			peers = append(peers, peer)
			ports[connection.Port] = true
		}
		if len(peers) == 0 {
			fmt.Fprintln(&text, "За время наблюдения обращений не обнаружено.")
			continue
		}
		var numbers []int
		for port := range ports {
			numbers = append(numbers, port)
		}
		sort.Ints(numbers)
		var labels []string
		for _, port := range numbers {
			labels = append(labels, strconv.Itoa(port))
		}
		fmt.Fprintf(&text, "Уникальные удалённые IP: %s\nУникальные порты назначения: %s\n", strings.Join(uniqueStrings(peers), ","), strings.Join(labels, ","))
	}
	writeSocketReport(&text, r.TCPBefore, r.TCPAfter, r.Names)
	fmt.Fprintln(&text, "\nИМЕНА ХОСТОВ ПО IP")
	for _, group := range []struct{ direction, title string }{{"incoming", "Входящие"}, {"outgoing", "Исходящие"}} {
		fmt.Fprintf(&text, "\n%s\n", group.title)
		var peers []string
		for _, connection := range r.Links {
			if connection.Direction == group.direction {
				peer := connection.Source
				if group.direction == "outgoing" {
					peer = connection.Destination
				}
				peers = append(peers, peer)
			}
		}
		if len(peers) == 0 {
			fmt.Fprintln(&text, "За время наблюдения обращений не обнаружено.")
			continue
		}
		fmt.Fprintf(&text, "%-18s %s\n", "IP", "HOSTNAME")
		for _, ip := range uniqueStrings(peers) {
			name := r.Names[ip]
			if name == "" {
				name = "-"
			}
			fmt.Fprintf(&text, "%-18s %s\n", ip, name)
		}
	}
	fmt.Fprintln(&text, "Источник имён: /etc/hosts и системные DNS-серверы через Go; «-» — имя не получено.")
	if r.ResolutionStatus == "budget_exhausted" {
		fmt.Fprintln(&text, "Бюджет поиска имён исчерпан: часть IP осталась без имени.")
	}
	fmt.Fprintln(&text, "\nСтрока захвата объединяет протокол, IP отправителя/получателя и порт назначения; порты отправителей остаются в raw/packets.log.")
	fmt.Fprintln(&text, "ПАКЕТЫ: для TCP — SYN без ACK, для UDP — наблюдаемые дейтаграммы. Повторы включены в счётчик.")
	fmt.Fprintln(&text, "Число пакетов не равно числу подключений: возможны повторы SYN и дубли при захвате. Счётчики не подтверждают успешность TCP или доставку UDP.")
	fmt.Fprintln(&text, "Установленные TCP взяты из /proc/net/tcp и tcp6 (IPv4-mapped) в начале и конце захвата в текущем сетевом пространстве имён, включая соединения без трафика.")
	fmt.Fprintln(&text, "Инициатор ранее открытого соединения неизвестен. Два снимка не доказывают непрерывность; соединения, жившие только между снимками, могли не попасть в таблицу.")
	fmt.Fprintln(&text, "IPv6, локальные обращения и транзит не учитываются.")
	fmt.Fprintln(&text, "Адреса ВМ 127.0.0.1 и 172.x.x.x и обращения через них исключены.")
	fmt.Fprintf(&text, "Адреса ВМ взяты на старте. Неразобранных строк захвата: %d\n", r.Unparsed)
	fmt.Fprintf(&text, "Захвачено пакетов: %s; получено фильтром: %s; потеряно ядром: %s.\n", counter(r.Diagnostics, "captured"), counter(r.Diagnostics, "received by filter"), counter(r.Diagnostics, "dropped by kernel"))
	fmt.Fprintf(&text, "\nДиагностика захвата (включая потери пакетов):\n%s", r.Diagnostics)
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
			fmt.Fprintf(text, "%s (%s): снимок неполный/недоступен — %s\n", label, snapshot.Taken.Format(time.RFC3339), snapshot.Problem)
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
	fmt.Fprintf(text, "%-22s %-22s %-6s %-6s %s\n", "LOCAL", "REMOTE", "НАЧАЛО", "КОНЕЦ", "REMOTE_HOSTNAME")
	for _, socket := range sortedSockets(seen) {
		name := names[socket.Remote.Addr().String()]
		if name == "" {
			name = "-"
		}
		marks := presence[socket]
		fmt.Fprintf(text, "%-22s %-22s %-6s %-6s %s\n", socket.Local, socket.Remote, snapshotMark(marks[0], before), snapshotMark(marks[1], after), name)
	}
	fmt.Fprintln(text, "+ — есть в снимке; - — не найден; ? — снимок неполный/недоступен. LOCAL/REMOTE не определяют инициатора.")
}
