package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
)

var groups = []string{"Все", "Входящие", "Исходящие", "Открытые TCP"}

type viewRow struct {
	source, target, name, protocol, kind, direction string
	port, localPort                                 int
	packets                                         uint64
	before, after                                   string
}

type tuiModel struct {
	ip, hostname    string
	data            collectionResult
	phase           string
	busy            bool
	failure         error
	group, selected int
	query           string
	editing, sortIP bool
	notice          string
	noticeError     bool
}

func (m tuiModel) filtered() []viewRow {
	r := m.data.Report
	var values []viewRow
	for _, link := range r.Links {
		if m.group == 3 || (m.group == 1 && link.Direction != "incoming") || (m.group == 2 && link.Direction != "outgoing") {
			continue
		}
		peer := link.Destination
		if link.Direction == "incoming" {
			peer = link.Source
		}
		kind := "SYN"
		if link.Protocol == "UDP" {
			kind = "UDP"
		}
		values = append(values, viewRow{source: link.Source, target: link.Destination, name: r.Names[peer], protocol: link.Protocol, kind: kind, direction: link.Direction, port: link.Port, packets: link.Packets})
	}
	if m.group == 0 || m.group == 3 {
		seen := make(map[tcpSocket][2]bool)
		for i, snapshot := range []tcpSnapshot{r.TCPBefore, r.TCPAfter} {
			for _, socket := range snapshot.Sockets {
				marks := seen[socket]
				marks[i] = true
				seen[socket] = marks
			}
		}
		for socket, marks := range seen {
			values = append(values, viewRow{source: socket.Local.Addr().String(), target: socket.Remote.Addr().String(), port: int(socket.Remote.Port()), localPort: int(socket.Local.Port()), name: r.Names[socket.Remote.Addr().String()], protocol: "TCP", kind: "ESTABLISHED", before: snapshotMark(marks[0], r.TCPBefore), after: snapshotMark(marks[1], r.TCPAfter)})
		}
	}
	query := strings.ToLower(m.query)
	result := make([]viewRow, 0, len(values))
	for _, value := range values {
		text := fmt.Sprintf("%s %s %d %d %s %s %s", value.source, value.target, value.port, value.localPort, value.name, value.protocol, value.kind)
		if strings.Contains(strings.ToLower(text), query) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if m.sortIP && a.target != b.target {
			left, leftErr := netip.ParseAddr(a.target)
			right, rightErr := netip.ParseAddr(b.target)
			if leftErr == nil && rightErr == nil {
				return left.Less(right)
			}
			return a.target < b.target
		}
		if a.port != b.port {
			return a.port < b.port
		}
		if a.source != b.source {
			return a.source < b.source
		}
		if a.target != b.target {
			return a.target < b.target
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.localPort < b.localPort
	})
	return result
}

func (m *tuiModel) key(key string) bool {
	if key == "esc" {
		m.query, m.editing, m.selected = "", false, 0
		return false
	}
	if m.editing {
		switch key {
		case "enter":
			m.editing = false
		case "backspace":
			runes := []rune(m.query)
			if len(runes) > 0 {
				m.query = string(runes[:len(runes)-1])
			}
		default:
			runes := []rune(key)
			if len(runes) == 1 && !unicode.IsControl(runes[0]) && len([]rune(m.query)) < 80 {
				m.query += key
			}
		}
		m.selected = 0
		return false
	}
	switch key {
	case "q":
		return true
	case "1", "2", "3", "4":
		m.group, m.selected = int(key[0]-'1'), 0
	case "tab":
		m.group, m.selected = (m.group+1)%len(groups), 0
	case "/":
		m.editing = true
	case "s":
		m.sortIP, m.selected = !m.sortIP, 0
	case "up", "k":
		m.selected = max(0, m.selected-1)
	case "down", "j":
		m.selected = min(max(0, len(m.filtered())-1), m.selected+1)
	}
	return false
}

func captureStatus(m tuiModel, now time.Time) line {
	r := m.data.Report
	if m.phase == phaseCapture && !r.Started.IsZero() {
		elapsed := max(time.Duration(0), min(now.Sub(r.Started), r.Duration))
		fraction := float64(elapsed) / float64(max(time.Nanosecond, r.Duration))
		filled := min(15, int(16*fraction))
		bar := strings.Repeat("=", filled) + ">" + strings.Repeat("-", 15-filled)
		return line{{"text", " Захват: ["}, {"accent", bar}, {"text", fmt.Sprintf("] %d/%d с", elapsed/time.Second, r.Duration/time.Second)}}
	}
	if !r.Finished.IsZero() {
		text := fmt.Sprintf(" Захват: Выполнен (%.0f секунд)", r.Finished.Sub(r.Started).Seconds())
		if m.phase != phaseReady {
			text += " · " + m.phase
		}
		return row(text, "text")
	}
	return row(" Захват: "+m.phase, "text")
}

func renderTUI(m tuiModel, width, height int, now time.Time) []line {
	width, height = max(1, width), max(1, height)
	var rows []line
	if width < 44 || height < 18 {
		rows = []line{row("SSB v"+version, "accent"), row("Нужно окно от 45×19. Увеличьте терминал.", "text"), row("q / Ctrl+C — выход", "muted")}
	} else {
		values := m.filtered()
		selected := min(max(0, m.selected), max(0, len(values)-1))
		ip, hostname := m.ip, m.hostname
		if ip == "" && len(m.data.Report.Addresses) > 0 {
			ip = m.data.Report.Addresses[0]
		}
		if ip == "" {
			ip = "—"
		}
		if hostname == "" {
			hostname = m.data.Report.Hostname
		}
		if hostname == "" {
			hostname = "—"
		}
		query, queryRole := m.query, "text"
		if m.editing {
			query += "_"
		} else if query == "" {
			query, queryRole = "IP, порт, имя или протокол", "muted"
		}
		rows = []line{row(fmt.Sprintf(" SSB v%s - %s %s", version, ip, hostname), "accent"), captureStatus(m, now), {{"accent", " Поиск: "}, {queryRole, query}}}
		detail, name := " Совпадений нет.", ""
		if len(values) > 0 {
			value := values[selected]
			label := "исходящие"
			if value.direction == "incoming" {
				label = "входящие"
			}
			detail = fmt.Sprintf(" %s → %s:%d", value.source, value.target, value.port)
			name = fmt.Sprintf(" %s · %s · %s, пакеты: %d", value.name, label, value.kind, value.packets)
			if value.name == "" {
				name = strings.Replace(name, "  ·", " Имя не получено ·", 1)
			}
			if value.kind == "ESTABLISHED" {
				detail = fmt.Sprintf(" LOCAL %s:%d ↔ REMOTE %s:%d", value.source, value.localPort, value.target, value.port)
				name = fmt.Sprintf(" ESTABLISHED · начало: %s · конец: %s · %s", value.before, value.after, value.name)
			}
		} else if m.busy {
			detail = " Ожидаю результаты сбора…"
		} else if m.failure != nil {
			detail = " " + m.failure.Error()
		}
		rows = append(rows, top("Детали выбранной строки", width), inside(row(detail, "text"), width), inside(row(name, "accent"), width), bottom(width))
		order := "порт"
		if m.sortIP {
			order = "IP"
		}
		hints := []string{"1: все  2: входящие  3: исходящие  4: открытые TCP", "↑↓/j/k: строка  Tab: вид  /: поиск  Esc: сброс", fmt.Sprintf("s: сортировка (%s)  r: захват  e: TXT  q/Ctrl+C: выход", order)}
		if width < 68 {
			hints = []string{"1: все  2: входящие  3: исходящие", "4: открытые TCP  Tab: вид  ↑↓/j/k: строка", fmt.Sprintf("/: поиск  Esc: сброс  s: сорт(%s)", order), "r: захват  e: TXT  q/Ctrl+C: выход"}
		}
		if m.editing {
			hints = []string{"Ввод: IP, порт, имя или протокол", "Enter: применить  Esc: очистить", "Backspace: стереть  Ctrl+C: выход"}
		}
		navigation := []line{top("Навигация", width)}
		for _, hint := range hints {
			navigation = append(navigation, inside(row(" "+hint, "accent"), width))
		}
		navigation = append(navigation, bottom(width))
		notice, noticeError := m.notice, m.noticeError
		if notice == "" && m.phase == phaseReady {
			notice = "TXT: " + m.data.Path
			if m.data.Report.Unparsed > 0 || m.data.Report.TCPBefore.Problem != "" || m.data.Report.TCPAfter.Problem != "" {
				notice = "Есть пропуски данных; подробности в TXT. " + notice
				noticeError = true
			}
		}
		if notice != "" {
			role := "good"
			if noticeError {
				role = "warn"
			}
			navigation = append([]line{row(" "+notice, role)}, navigation...)
		}
		bodyCount := max(0, height-len(rows)-len(navigation)-3)
		offset := max(0, selected-bodyCount+1)
		header := "  DIR УДАЛЁННЫЙ IP    ПОРТ ПРОТ КОЛ-ВО"
		if width >= 88 {
			header = "  DIR ОТПРАВИТЕЛЬ     ПОЛУЧАТЕЛЬ       ПОРТ ПРОТ ПАКЕТЫ СТАТУС ИМЯ"
		}
		rows = append(rows, top(fmt.Sprintf("Наблюдения / %s · %s · %d", groups[m.group], m.phase, len(values)), width), inside(row(header, "head"), width))
		for index := 0; index < bodyCount; index++ {
			parts := row("", "text")
			position := offset + index
			if position < len(values) {
				value := values[position]
				direction, peer := "OUT", value.target
				if value.direction == "incoming" {
					direction, peer = "IN ", value.source
				} else if value.direction == "" {
					direction = " ? "
				}
				marker, role := "  ", "text"
				if position == selected {
					marker, role = "> ", "selected"
				} else if value.direction == "incoming" {
					role = "good"
				}
				count := fmt.Sprint(value.packets)
				if value.kind == "ESTABLISHED" {
					count = "—"
				}
				text := fmt.Sprintf("%s%s %-15s %5d %-3s %s", marker, direction, peer, value.port, value.protocol, count)
				if width >= 88 {
					kind := value.kind
					if kind == "ESTABLISHED" {
						kind = "ESTAB"
					}
					text = fmt.Sprintf("%s%s %-15s %-15s %5d %-3s %6s %-5s %s", marker, direction, value.source, value.target, value.port, value.protocol, count, kind, value.name)
				}
				parts = row(text, role)
			} else if index == 0 {
				text := "Совпадений нет. Esc очистит поиск."
				if m.busy {
					text = "Результаты появятся после захвата."
				}
				parts = row(text, "muted")
			}
			rows = append(rows, inside(parts, width))
		}
		rows = append(rows, bottom(width))
		rows = append(rows, navigation...)
	}
	rows = rows[:min(height, len(rows))]
	for index := range rows {
		rows[index] = fit(rows[index], width)
	}
	return rows
}

var colors = map[string]string{
	"text":     "\x1b[38;2;209;221;242m\x1b[48;2;16;24;42m",
	"muted":    "\x1b[38;2;146;159;189m\x1b[48;2;16;24;42m",
	"accent":   "\x1b[38;2;124;207;255m\x1b[48;2;16;24;42m",
	"good":     "\x1b[38;2;161;216;181m\x1b[48;2;16;24;42m",
	"warn":     "\x1b[38;2;235;208;142m\x1b[48;2;16;24;42m",
	"border":   "\x1b[38;2;113;141;199m\x1b[48;2;16;24;42m",
	"head":     "\x1b[38;2;209;221;242m\x1b[48;2;52;52;91m",
	"selected": "\x1b[38;2;209;221;242m\x1b[48;2;38;63;101m",
}

type span struct{ role, text string }
type line []span

func row(text, role string) line { return line{{role, text}} }

func clean(text string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			return -1
		}
		return char
	}, text)
}

// shortcut: emoji clusters vary by terminal; use a grapheme width table if emoji labels are added.
func cellWidth(char rune) int {
	if unicode.In(char, unicode.Mn, unicode.Me) {
		return 0
	}
	if char >= 0x1100 && (char <= 0x115f || char == 0x2329 || char == 0x232a ||
		(char >= 0x2e80 && char <= 0xa4cf && char != 0x303f) ||
		(char >= 0xac00 && char <= 0xd7a3) || (char >= 0xf900 && char <= 0xfaff) ||
		(char >= 0xfe10 && char <= 0xfe19) || (char >= 0xfe30 && char <= 0xfe6f) ||
		(char >= 0xff00 && char <= 0xff60) || (char >= 0xffe0 && char <= 0xffe6) ||
		(char >= 0x1f300 && char <= 0x1faff) || (char >= 0x20000 && char <= 0x3fffd)) {
		return 2
	}
	return 1
}

func fit(parts line, width int) line {
	remaining := max(0, width)
	var result line
	lastRole := "text"
	for _, part := range parts {
		var text strings.Builder
		for _, char := range clean(part.text) {
			cells := cellWidth(char)
			if cells > remaining {
				break
			}
			text.WriteRune(char)
			remaining -= cells
		}
		if text.Len() > 0 {
			result = append(result, span{part.role, text.String()})
		}
		lastRole = part.role
		if remaining == 0 {
			break
		}
	}
	if remaining > 0 {
		if lastRole != "selected" && lastRole != "head" {
			lastRole = "text"
		}
		result = append(result, span{lastRole, strings.Repeat(" ", remaining)})
	}
	return result
}

func top(title string, width int) line {
	return fit(row("╭─ "+title+" "+strings.Repeat("─", max(0, width-len([]rune(title))-5))+"╮", "border"), width)
}

func bottom(width int) line {
	return row("╰"+strings.Repeat("─", max(0, width-2))+"╯", "border")
}

func inside(parts line, width int) line {
	return append(append(line{{"border", "│"}}, fit(parts, width-2)...), span{"border", "│"})
}

func plain(rows []line) string {
	var result strings.Builder
	for index, row := range rows {
		if index > 0 {
			result.WriteByte('\n')
		}
		for _, part := range row {
			result.WriteString(part.text)
		}
	}
	return result.String()
}
