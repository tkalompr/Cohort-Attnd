package main

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---------------------------- FORMATTING --------------------------------------//
const (
	BoldRed    = "\033[1;31m" // bold red
	BoldYellow = "\033[1;33m" // bold yellow
	Reset      = "\033[0m"
	Yellow     = "\033[0;33m"
)

// ============================= helpers ========================================//

// readLine prompts the user and reads a single line from stdin (trimmed).
func readLine(prompt string) string {
	fmt.Print(prompt)
	in := bufio.NewReader(os.Stdin)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

// fileExists checks if a path points to an existing regular file.
func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// stripBOM removes a UTF-8 BOM prefix if present.
func stripBOM(s string) string {
	const bom = "\uFEFF"
	return strings.TrimPrefix(s, bom)
}

// ============================ domain types ====================================//

type RecordType int

const (
	UnlockWithApp RecordType = iota
	Locked
	UnlockWithPassword
)

func (rt RecordType) String() string {
	switch rt {
	case UnlockWithApp:
		return "unlock with app"
	case Locked:
		return "locked"
	case UnlockWithPassword:
		return "unlock with password"
	default:
		return "unknown"
	}
}

// From string to enum (for CSV parsing)
func ParseRecordType(s string) RecordType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "unlock with app":
		return UnlockWithApp
	case "locked":
		return Locked
	case "unlock with password":
		return UnlockWithPassword
	default:
		return -1
	}
}

type ActionsOps interface {
	SelectPeriod(from, to string) ([]Action, error)
	DuplicateRemover([]Action) ([]Action, error)
}

type ActionList []Action

// Data from every day key usage
type Action struct {
	Username   string
	RecordType RecordType
	Timestamp  string // original string as read from CSV (e.g. "02/05/2025 00:37:12" or "2025-05-02 00:37")
}

// Data for all the selected from user session (placeholders keeping your structs)
type InputSession struct {
	MonthsOfSession []int
	Count           int
}

type SessionPerMonth struct {
	WeeksOfSession []int
	Count          int
}

type User struct {
	Login string
	Name  string
	InputSession
	SessionPerMonth
	CountPerWeek int
	Days         string
}

// ============================= USERS READER ===================================//

// Reader reads USERS.txt where each user is 2 lines: login then full name.
func Reader(path string) ([]User, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Failed to open users file"+Reset, ":", err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var users []User
	var cur *User
	state := 0 // 0: waiting Login, 1: waiting for full name

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = stripBOM(line)
		if line == "" {
			continue
		}

		switch state {
		case 0: // Login
			cur = &User{Login: line}
			state = 1
		case 1: // Name
			cur.Name = line
			users = append(users, *cur)
			cur = nil
			state = 0
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Failed to scan users file"+Reset, ":", err)
		return nil, err
	}

	if state == 1 && cur != nil {
		fmt.Fprintln(os.Stderr, Yellow+"Warning:"+Reset, "last user is missing a Name line; skipping")
	}

	return users, nil
}

// ============================= CSV READER =====================================//

// ReadFileGeneric: reads .csv (lightweight). If extension is wrong, we still try CSV.
func ReadFileGeneric(path string) ([]Action, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".csv":
		return CSVReader(path)
	default:
		// try CSV anyway (in case of wrong extension)
		if acts, err := CSVReader(path); err == nil {
			return acts, nil
		}
		return nil, fmt.Errorf("unsupported file format: %s (expected .csv)", ext)
	}
}

// CSVReader reads CSV (auto delimiter: , ; \t |) and returns []Action
func CSVReader(path string) ([]Action, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)

	// Peek first line to detect delimiter
	firstLine, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	sep := detectSep(firstLine)

	// Rebuild reader including the first line
	r := csv.NewReader(io.MultiReader(strings.NewReader(firstLine), br))
	r.Comma = sep
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("empty csv")
	}

	// strip BOM in the first cell if present
	if len(records[0]) > 0 {
		records[0][0] = stripBOM(records[0][0])
	}

	// Header detection
	hasHeader := looksLikeHeader(records[0])
	idxTime, idxUser, idxType := -1, -1, -1
	if hasHeader {
		for i, h := range records[0] {
			h = strings.ToLower(stripBOM(strings.TrimSpace(h)))
			switch {
			case strings.Contains(h, "time") || strings.Contains(h, "date"):
				if idxTime == -1 {
					idxTime = i
				}
			case strings.Contains(h, "user") || strings.Contains(h, "login"):
				if idxUser == -1 {
					idxUser = i
				}
			case strings.Contains(h, "type") || strings.Contains(h, "record"):
				if idxType == -1 {
					idxType = i
				}
			}
		}
	} else {
		// default order: datetime, username, type
		if len(records[0]) >= 1 {
			idxTime = 0
		}
		if len(records[0]) >= 2 {
			idxUser = 1
		}
		if len(records[0]) >= 3 {
			idxType = 2
		}
	}

	if idxTime == -1 {
		return nil, fmt.Errorf("could not detect time/date column")
	}
	if idxUser == -1 {
		return nil, fmt.Errorf("could not detect user column")
	}

	start := 0
	if hasHeader {
		start = 1
	}

	actions := make([]Action, 0, len(records)-start)
	for _, row := range records[start:] {
		// skip fully empty
		allEmpty := true
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				allEmpty = false
				break
			}
		}
		if allEmpty {
			continue
		}

		if idxTime >= len(row) || idxUser >= len(row) {
			continue
		}
		ts := strings.TrimSpace(stripBOM(row[idxTime]))
		user := strings.TrimSpace(row[idxUser])

		rt := RecordType(-1)
		if idxType >= 0 && idxType < len(row) {
			rt = ParseRecordType(row[idxType])
		}

		actions = append(actions, Action{
			Username:   user,
			RecordType: rt,
			Timestamp:  ts,
		})
	}
	return actions, nil
}

// detectSep finds likely delimiter from the first line
func detectSep(s string) rune {
	candidates := []rune{',', ';', '\t', '|'}
	best := ','
	bestCount := -1
	for _, c := range candidates {
		cnt := strings.Count(s, string(c))
		if cnt > bestCount {
			bestCount = cnt
			best = c
		}
	}
	return best
}

func looksLikeHeader(cols []string) bool {
	foundKeyword := false
	for _, c := range cols {
		lc := strings.ToLower(stripBOM(strings.TrimSpace(c)))
		if lc == "" {
			continue
		}
		if strings.Contains(lc, "time") || strings.Contains(lc, "date") ||
			strings.Contains(lc, "user") || strings.Contains(lc, "login") ||
			strings.Contains(lc, "type") || strings.Contains(lc, "record") {
			foundKeyword = true
		}
		// contains odd symbols → likely header
		if !isLikelyDataCell(lc) {
			foundKeyword = true
		}
	}
	return foundKeyword
}

func isLikelyDataCell(s string) bool {
	for _, r := range s {
		if r == ':' || r == '/' || r == '-' || r == ' ' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r == '_' || r == '.' {
			continue
		}
		if !utf8.ValidRune(r) {
			return false
		}
	}
	return true
}

// ============================ string-only time logic ===========================//

// CountByUser returns how many actions per username.
func CountByUser(actions []Action) map[string]int {
	m := make(map[string]int, 64)
	for _, a := range actions {
		m[a.Username]++
	}
	return m
}

// --- helpers for string-only date/hour handling ---

func isLeap(y int) bool {
	if y%400 == 0 {
		return true
	}
	if y%100 == 0 {
		return false
	}
	return y%4 == 0
}

func daysInMonth(y, m int) int {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeap(y) {
			return 29
		}
		return 28
	default:
		return 30
	}
}

// parseDateHour accepts "YYYY-MM-DD HH:MM[:SS]" OR "DD/MM/YYYY HH:MM[:SS]"
func parseDateHour(ts string) (y, m, d, hh int, ok bool) {
	parts := strings.Split(ts, " ")
	if len(parts) < 2 {
		return
	}
	date, timePart := parts[0], parts[1]

	// hour
	hms := strings.Split(timePart, ":")
	if len(hms) < 2 {
		return
	}
	hour, err := strconv.Atoi(hms[0])
	if err != nil {
		return
	}

	// date formats
	if strings.Contains(date, "-") {
		// YYYY-MM-DD
		dparts := strings.Split(date, "-")
		if len(dparts) != 3 {
			return
		}
		yi, err1 := strconv.Atoi(dparts[0])
		mi, err2 := strconv.Atoi(dparts[1])
		di, err3 := strconv.Atoi(dparts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			return
		}
		return yi, mi, di, hour, true
	}

	if strings.Contains(date, "/") {
		// DD/MM/YYYY
		dparts := strings.Split(date, "/")
		if len(dparts) != 3 {
			return
		}
		di, err1 := strconv.Atoi(dparts[0])
		mi, err2 := strconv.Atoi(dparts[1])
		yi, err3 := strconv.Atoi(dparts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			return
		}
		return yi, mi, di, hour, true
	}

	return
}

func prevDay(y, m, d int) (int, int, int) {
	d--
	if d >= 1 {
		return y, m, d
	}
	// previous month
	m--
	if m >= 1 {
		return y, m, daysInMonth(y, m)
	}
	// previous year
	y--
	return y, 12, 31
}

func fmtYYYYMMDD(y, m, d int) string {
	var b strings.Builder
	b.Grow(10)
	b.WriteString(strconv.Itoa(y))
	b.WriteByte('-')
	if m < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.Itoa(m))
	b.WriteByte('-')
	if d < 10 {
		b.WriteByte('0')
	}
	b.WriteString(strconv.Itoa(d))
	return b.String()
}

// bucketDateString applies the 01:00→01:00 “day” rule (no timezones needed).
// If hour >= 1 → same date; if hour == 0 → previous date.
func bucketDateString(ts string) (string, bool) {
	y, m, d, hh, ok := parseDateHour(ts)
	if !ok {
		return "", false
	}
	if hh >= 1 {
		return fmtYYYYMMDD(y, m, d), true
	}
	py, pm, pd := prevDay(y, m, d)
	return fmtYYYYMMDD(py, pm, pd), true
}

// validateYMD ensures "YYYY-MM-DD" format length and basic sanity.
func validateYMD(s string) bool {
	if len(s) != 10 {
		return false
	}
	if s[4] != '-' || s[7] != '-' {
		return false
	}
	_, errY := strconv.Atoi(s[0:4])
	_, errM := strconv.Atoi(s[5:7])
	_, errD := strconv.Atoi(s[8:10])
	return errY == nil && errM == nil && errD == nil
}

// ============================ METHODS =========================================//

// SelectPeriod keeps actions whose bucketDate is within [from,to] inclusive.
// from/to must be "YYYY-MM-DD".
func (a ActionList) SelectPeriod(from, to string) ([]Action, error) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if !validateYMD(from) || !validateYMD(to) {
		return nil, errors.New("from/to must be in YYYY-MM-DD format")
	}

	out := make([]Action, 0, len(a))
	for _, act := range a {
		bd, ok := bucketDateString(act.Timestamp)
		if !ok {
			// skip unparsable timestamp
			continue
		}
		if bd < from {
			continue
		}
		if bd > to {
			continue
		}
		out = append(out, act)
	}
	return out, nil
}

// DuplicateRemover removes duplicates per (username, bucketDate, exact timestamp).
func (a ActionList) DuplicateRemover(actionsInput []Action) ([]Action, error) {
	seen := make(map[string]struct{}, len(actionsInput))
	out := make([]Action, 0, len(actionsInput))

	for _, act := range actionsInput {
		bd, ok := bucketDateString(act.Timestamp)
		if !ok {
			continue
		}
		// Key per user + bucket day + full original timestamp string.
		key := act.Username + "\x00" + bd + "\x00" + act.Timestamp
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, act)
	}
	return out, nil
}

// UNIQUE per (user, bucketDate): κρατάει μόνο την 1η εγγραφή της μέρας
func (a ActionList) UniquePerUserPerDay(actions []Action) ([]Action, error) {
	seen := make(map[string]struct{}, len(actions))
	out := make([]Action, 0, len(actions))
	for _, act := range actions {
		bd, ok := bucketDateString(act.Timestamp)
		if !ok {
			continue
		}
		key := act.Username + "\x00" + bd // ΠΡΟΣΟΧΗ: ΧΩΡΙΣ timestamp
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, act)
	}
	return out, nil
}

// indexUsers builds a map[login]fullName from USERS.txt entries.
func indexUsers(users []User) map[string]string {
	m := make(map[string]string, len(users))
	for _, u := range users {
		m[u.Login] = u.Name
	}
	return m
}

// ============================ MAIN FUNCTION ===================================//

func main() {
	// --- Interactive inputs ---
	usersPath := readLine("Path to USERS.txt (default ./USERS.txt): ")
	if usersPath == "" {
		usersPath = "./1.txt"
	}
	if !fileExists(usersPath) {
		fmt.Fprintln(os.Stderr, BoldRed+"Error: USERS.txt not found at "+usersPath+Reset)
		return
	}

	csvPath := readLine("Path to TTLock CSV file (.csv): ")
	if csvPath == "" {
		csvPath = "./all.csv"
	}
	if !fileExists(csvPath) {
		fmt.Fprintln(os.Stderr, BoldRed+"Error: file not found at "+csvPath+Reset)
		return
	}

	fromStr := readLine("From date [YYYY-MM-DD] (required): ")
	if fromStr == "" {
		fromStr = "2025-05-01"
	}
	toStr := readLine("To date   [YYYY-MM-DD] (required): ")
	if toStr == "" {
		toStr = "2025-05-30"
	}
	if strings.TrimSpace(fromStr) == "" || strings.TrimSpace(toStr) == "" {
		fmt.Fprintln(os.Stderr, BoldRed+"Error: from/to are required."+Reset)
		return
	}

	// Optional: a single user or ALL
	userFilter := readLine("Username to include (type ALL for everyone): ")
	if userFilter == "" {
		userFilter = "ALL"
	}

	fmt.Println(BoldYellow + "...Loading data..." + Reset)

	// 1) Load users
	users, err := Reader(usersPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Error: USERS.txt cannot be read:"+Reset, err)
		return
	}
	fmt.Printf("Loaded %d users from %s\n", len(users), filepath.Base(usersPath))

	// 2) Load actions from CSV
	actions, err := ReadFileGeneric(csvPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Error: CSV cannot be read:"+Reset, err)
		return
	}
	fmt.Printf("Loaded %d raw actions from %s\n", len(actions), filepath.Base(csvPath))

	// 3) Filter by user if not ALL.
	if strings.ToUpper(userFilter) != "ALL" {
		filtered := make([]Action, 0, len(actions))
		for _, a := range actions {
			if a.Username == userFilter {
				filtered = append(filtered, a)
			}
		}
		fmt.Printf("User filter %q applied: %d → %d actions\n", userFilter, len(actions), len(filtered))
		actions = filtered
	}

	// 4) Select period using 01:00→01:00 buckets (string-only)
	selected, err := (ActionList(actions)).SelectPeriod(fromStr, toStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Error in SelectPeriod:"+Reset, err)
		return
	}
	fmt.Printf("After period %s..%s: %d actions\n", fromStr, toStr, len(selected))

	// 5) Remove duplicates within the bucket days
	cleaned, err := (ActionList(selected)).UniquePerUserPerDay(selected)
	if err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Error in DuplicateRemover:"+Reset, err)
		return
	}
	fmt.Printf("After duplicate removal: %d actions\n", len(cleaned))

	// 6) Count per user
	counts := CountByUser(cleaned)
	if strings.ToUpper(userFilter) != "ALL" {
		fmt.Printf("Occurrences for %q: %d\n", userFilter, counts[userFilter])
	} else {
		type kv struct {
			user string
			n    int
		}
		var list []kv
		for u, n := range counts {
			list = append(list, kv{u, n})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		fmt.Println("Occurrences per user (after filters & de-dup):")
		for _, it := range list {
			fmt.Printf("- %s: %d\n", it.user, it.n)
		}
	}

	// 7) Sample print
	printSample(cleaned, 10)

	fmt.Println(BoldYellow + "...Done. CSV pipeline complete." + Reset)
}

func printSample(actions []Action, n int) {
	if n > len(actions) {
		n = len(actions)
	}
	fmt.Println("==== Sample of actions ====")
	for i := 0; i < n; i++ {
		a := actions[i]
		fmt.Printf("%s | %-18s | %s\n", a.Timestamp, a.Username, a.RecordType.String())
	}
	if len(actions) > n {
		fmt.Printf("... and %d more\n", len(actions)-n)
	}
}
