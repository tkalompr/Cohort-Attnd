package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

//
// =================== CONFIG ===================
//

const (
	// Files & prompts
	defaultUsersPath = "./1.txt"
	defaultCSVPath   = "./all.csv"

	// Hasura/GraphQL
	ENDPOINT = "https://platform.zone01.gr/api/graphql-engine/v1/graphql"
	EVENT_ID = 200
)

var ORIGIN_EVENT_IDS = []int{200, 20, 54, 73, 123}

// Known TTLock username typos → correct logins (case-insensitive)
var loginAliases = map[string]string{
	"vstafeno":  "vstefano",
	"daslamak":  "daslamac",
	"kpetrouts": "kpetrout",
}

// normalizeLoginLike trims, lowercases and applies alias fixes.
// (Safe to call for plain logins or free-form "names"; if it's not a
// known bad login, it just returns the cleaned string.)
func normalizeLoginLike(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if fixed, ok := loginAliases[t]; ok {
		return fixed
	}
	return t
}

// Exclusions (same rules you used in Apps Script)
const EXCLUDE_TOTALS_PREFIX = "/athens/piscine-go"
const EXCLUDE_LEVEL_PREFIX = "/athens/piscine-go"

// Levels table
const MAX_LEVEL = 128

// Gitea
const (
	GITEA_BASE = "https://platform.zone01.gr/git/api/v1"
	GITEA_TZ   = "Europe/Athens"
)

//
// =================== MODELS ===================
//

// User lines come from 1.txt (login then name)
type User struct {
	Login string
	Name  string
}

// Aggregated result for each user
type AggUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`

	AttendanceCount int     `json:"attendance_count"`
	TotalXP         int     `json:"total_xp"`
	TotalProjects   int     `json:"total_projects"`
	Level           int     `json:"level"`
	LevelProgress   float64 `json:"level_progress"`
	ExpectedLevel   float64 `json:"expected_level"`

	LastCommitDate      string `json:"last_commit_date"`    // YYYY-MM-DD
	GoReloadedCreatedAt string `json:"go_reloaded_created"` // YYYY-MM-DD

	// NEW flags
	LvlOK  bool `json:"lvl"`
	AttOK  bool `json:"att"`
	PushOK bool `json:"push"`
	//Status
	Status string `json:"status"` // ok | bocal | phonecall
}

//
// =================== TERM COLORS ===================
//

const (
	BoldRed    = "\033[1;31m"
	BoldYellow = "\033[1;33m"
	Reset      = "\033[0m"
	Yellow     = "\033[0;33m"
)

//
// =================== .env loader ===================
//

func LoadDotEnv(paths ...string) (string, error) {
	if len(paths) == 0 {
		paths = []string{".env"}
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("open %s: %w", p, err)
		}
		defer f.Close()
		env, err := parseDotEnv(f)
		if err != nil {
			return "", fmt.Errorf("parse %s: %w", p, err)
		}
		for k, v := range env {
			_ = os.Setenv(k, v)
		}
		return p, nil
	}
	return "", os.ErrNotExist
}

func parseDotEnv(r io.Reader) (map[string]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	env := make(map[string]string)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		if key == "" {
			continue
		}
		val := strings.TrimSpace(line[i+1:])
		// quoted?
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			if unq, err := strconv.Unquote(val); err == nil {
				val = unq
			} else {
				val = val[1 : len(val)-1]
			}
		} else {
			// inline comment
			if j := indexUnquotedHash(val); j >= 0 {
				val = strings.TrimSpace(val[:j])
			}
		}
		// expand $VAR
		val = os.Expand(val, func(v string) string {
			if x, ok := env[v]; ok {
				return x
			}
			return os.Getenv(v)
		})
		env[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return env, nil
}

func indexUnquotedHash(s string) int {
	inS, inD, esc := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '\'' && !inD {
			inS = !inS
			continue
		}
		if c == '"' && !inS {
			inD = !inD
			continue
		}
		if c == '#' && !inS && !inD {
			return i
		}
	}
	return -1
}

//
// =================== USERS.txt ===================
//

func readUsersTxt(path string) ([]User, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var users []User
	var cur *User
	state := 0 // 0: expect login, 1: expect full name
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, "\uFEFF")
		if line == "" {
			continue
		}
		if state == 0 {
			cur = &User{Login: line}
			state = 1
		} else {
			cur.Name = line
			users = append(users, *cur)
			state = 0
			cur = nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

//
// =================== CSV → Actions ===================
//

type RecordType int

const (
	UnlockWithApp RecordType = iota
	Locked
	UnlockWithPassword
)

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

type Action struct {
	Username   string
	RecordType RecordType
	Timestamp  string // "YYYY-MM-DD HH:MM[:SS]" OR "DD/MM/YYYY HH:MM[:SS]"
}

func readTTLockCSV(path string) ([]Action, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	first, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	sep := detectSep(first)

	r := csv.NewReader(io.MultiReader(strings.NewReader(first), br))
	r.Comma = sep
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty csv")
	}
	// strip BOM
	if len(rows[0]) > 0 {
		rows[0][0] = strings.TrimPrefix(rows[0][0], "\uFEFF")
	}

	// header?
	idxTime, idxUser, idxType := -1, -1, -1
	if looksLikeHeader(rows[0]) {
		for i, h := range rows[0] {
			l := strings.ToLower(strings.TrimSpace(h))
			switch {
			case strings.Contains(l, "time") || strings.Contains(l, "date"):
				if idxTime < 0 {
					idxTime = i
				}
			case strings.Contains(l, "user") || strings.Contains(l, "login"):
				if idxUser < 0 {
					idxUser = i
				}
			case strings.Contains(l, "type") || strings.Contains(l, "record"):
				if idxType < 0 {
					idxType = i
				}
			}
		}
		rows = rows[1:]
	} else {
		if len(rows[0]) >= 1 {
			idxTime = 0
		}
		if len(rows[0]) >= 2 {
			idxUser = 1
		}
		if len(rows[0]) >= 3 {
			idxType = 2
		}
	}
	if idxTime < 0 || idxUser < 0 {
		return nil, fmt.Errorf("could not detect time/user columns")
	}

	actions := make([]Action, 0, len(rows))
	for _, row := range rows {
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
		ts := strings.TrimSpace(row[idxTime])
		un := normalizeLoginLike(row[idxUser])

		rt := RecordType(-1)
		if idxType >= 0 && idxType < len(row) {
			rt = ParseRecordType(row[idxType])
		}
		if rt == UnlockWithApp || rt == Locked {
			actions = append(actions, Action{Username: un, RecordType: rt, Timestamp: ts})
		}
	}
	return actions, nil
}

func detectSep(s string) rune {
	candidates := []rune{',', ';', '\t', '|'}
	best := ','
	bestCnt := -1
	for _, c := range candidates {
		cnt := strings.Count(s, string(c))
		if cnt > bestCnt {
			bestCnt = cnt
			best = c
		}
	}
	return best
}

func looksLikeHeader(cols []string) bool {
	found := false
	for _, c := range cols {
		l := strings.ToLower(strings.TrimSpace(c))
		if l == "" {
			continue
		}
		if strings.Contains(l, "time") || strings.Contains(l, "date") ||
			strings.Contains(l, "user") || strings.Contains(l, "login") ||
			strings.Contains(l, "type") || strings.Contains(l, "record") {
			found = true
		}
		if !isLikelyDataCell(l) {
			found = true
		}
	}
	return found
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

// ------------- 01:00→01:00 buckets (string-only) --------------

func parseDateHour(ts string) (y, m, d, hh int, ok bool) {
	parts := strings.Split(ts, " ")
	if len(parts) < 2 {
		return
	}
	date, timePart := parts[0], parts[1]

	hms := strings.Split(timePart, ":")
	if len(hms) < 2 {
		return
	}
	hh, _ = strconv.Atoi(hms[0])

	// YYYY-MM-DD
	if strings.Contains(date, "-") {
		dp := strings.Split(date, "-")
		if len(dp) != 3 {
			return
		}
		yi, e1 := strconv.Atoi(dp[0])
		mi, e2 := strconv.Atoi(dp[1])
		di, e3 := strconv.Atoi(dp[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return
		}
		return yi, mi, di, hh, true
	}
	// DD/MM/YYYY
	if strings.Contains(date, "/") {
		dp := strings.Split(date, "/")
		if len(dp) != 3 {
			return
		}
		di, e1 := strconv.Atoi(dp[0])
		mi, e2 := strconv.Atoi(dp[1])
		yi, e3 := strconv.Atoi(dp[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return
		}
		return yi, mi, di, hh, true
	}
	return
}

func daysInMonth(y, m int) int {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		// leap?
		if y%400 == 0 || (y%4 == 0 && y%100 != 0) {
			return 29
		}
		return 28
	default:
		return 30
	}
}
func prevDay(y, m, d int) (int, int, int) {
	d--
	if d >= 1 {
		return y, m, d
	}
	m--
	if m >= 1 {
		return y, m, daysInMonth(y, m)
	}
	y--
	return y, 12, 31
}
func fmtYYYYMMDD(y, m, d int) string {
	return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
}
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

func validateYMD(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	_, e1 := strconv.Atoi(s[:4])
	_, e2 := strconv.Atoi(s[5:7])
	_, e3 := strconv.Atoi(s[8:10])
	return e1 == nil && e2 == nil && e3 == nil
}

// SelectPeriod keeps actions whose bucket date is within [from..to]
func selectPeriod(actions []Action, from, to string) []Action {
	if !validateYMD(from) || !validateYMD(to) {
		return nil
	}
	out := make([]Action, 0, len(actions))
	for _, a := range actions {
		bd, ok := bucketDateString(a.Timestamp)
		if !ok {
			continue
		}
		if bd < from || bd > to {
			continue
		}
		out = append(out, a)
	}
	return out
}

// UniquePerUserPerDay: keep only the 1st entry per (username, bucketDate)
func uniquePerUserPerDay(actions []Action) []Action {
	seen := make(map[string]struct{}, len(actions))
	out := make([]Action, 0, len(actions))
	for _, a := range actions {
		bd, ok := bucketDateString(a.Timestamp)
		if !ok {
			continue
		}
		key := a.Username + "\x00" + bd
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
}

//
// =================== Hasura: XP & Levels ===================
//

type gqlResp struct {
	Data struct {
		User []struct {
			Login string  `json:"login"`
			Xps   []xpRow `json:"xps"`
		} `json:"user"`
	} `json:"data"`
	Errors any `json:"errors"`
}
type xpRow struct {
	Path   string  `json:"path"`
	Amount float64 `json:"amount"`
}

func fetchUserXps(client *http.Client, endpoint, adminSecret, login string, eventID int, originIDs []int) ([]xpRow, error) {
	query := `
	query($login:String!, $eventId:Int!, $originIds:[Int!]!) {
	  user(where: {login:{_eq:$login}, events:{eventId:{_eq:$eventId}}}) {
	    login
	    xps(
	      where: { originEventId: { _in: $originIds } }
	      order_by: { amount: asc }
	    ) {
	      path
	      amount
	    }
	  }
	}`
	vars := map[string]any{"login": login, "eventId": eventID, "originIds": originIDs}
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})

	req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-hasura-admin-secret", adminSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GraphQL HTTP %d: %s", resp.StatusCode, string(b))
	}

	var out gqlResp
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out.Errors != nil {
		return nil, fmt.Errorf("GraphQL returned errors: %v", out.Errors)
	}
	if len(out.Data.User) == 0 {
		return nil, fmt.Errorf("no user (or not in event %d): %s", eventID, login)
	}
	return out.Data.User[0].Xps, nil
}

type levelRow struct {
	Level int
	Base  int
	Total int
	Cumul int
}

func buildLevels() []levelRow {
	levels := make([]levelRow, 0, MAX_LEVEL+1)
	var xpIndex float64
	cumul := 0
	for i := 0; i <= MAX_LEVEL; i++ {
		req := float64(i)*0.66 + 1.0
		base := (i+2)*150 + 50
		total := int(round(req * float64(base)))
		cumul += total
		xpIndex += req
		levels = append(levels, levelRow{
			Level: i, Base: base, Total: total, Cumul: cumul,
		})
	}
	return levels
}
func round(f float64) float64 {
	if f >= 0 {
		return float64(int64(f + 0.5))
	}
	return float64(int64(f - 0.5))
}

type levelInfo struct {
	Level            int
	XpInCurrentLevel int
	XpToNextLevel    int
	ThisLevelTotal   int
	Progress         float64
}

func levelFromTotalXp(xp int, levels []levelRow) levelInfo {
	for i := 0; i < len(levels); i++ {
		if xp < levels[i].Cumul {
			prevCumul := 0
			if i > 0 {
				prevCumul = levels[i-1].Cumul
			}
			inLevel := xp - prevCumul
			toNext := levels[i].Cumul - xp
			total := levels[i].Total
			prog := 1.0
			if total > 0 {
				prog = float64(inLevel) / float64(total)
			}
			return levelInfo{
				Level:            i,
				XpInCurrentLevel: inLevel,
				XpToNextLevel:    toNext,
				ThisLevelTotal:   total,
				Progress:         prog,
			}
		}
	}
	last := levels[len(levels)-1]
	return levelInfo{Level: last.Level, XpInCurrentLevel: last.Total, XpToNextLevel: 0, ThisLevelTotal: last.Total, Progress: 1}
}

func totalsForXps(xps []xpRow, excludePrefix string) (totalXP int, totalProjects int) {
	for _, x := range xps {
		if strings.HasPrefix(x.Path, excludePrefix) {
			continue
		}
		totalXP += int(x.Amount)
		totalProjects++
	}
	return
}
func totalsForXpsOnly(xps []xpRow, excludePrefix string) (totalXP int) {
	for _, x := range xps {
		if strings.HasPrefix(x.Path, excludePrefix) {
			continue
		}
		totalXP += int(x.Amount)
	}
	return
}

//
// =================== helpers ===================

func parseYMD(s string, loc *time.Location) time.Time {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return time.Time{}
	}
	t, err := time.ParseInLocation("2006-01-02", s, loc)
	if err != nil {
		return time.Time{}
	}
	return t
}

func statusFromFlags(lvl, push, att bool) string {
	// Mapping (8 cases):
	// 1) T T T -> ok
	// 2) T T F -> ok
	// 3) F T T -> ok
	// 4) T F T -> bocal
	// 5) T F F -> bocal
	// 6) F F T -> phonecall
	// 7) F T F -> phonecall
	// 8) F F F -> phonecall
	if (lvl && push && att) || (lvl && push && !att) || (!lvl && push && att) {
		return "ok"
	}
	if (lvl && !push && att) || (lvl && !push && !att) {
		return "bocal"
	}
	return "phonecall"
}

// monthsBetween counts full months from a -> b, rounding down when the day-of-month hasn't been reached yet.
func monthsBetween(a, b time.Time) int {
	if b.Before(a) {
		return 0
	}
	y1, m1, d1 := a.Date()
	y2, m2, d2 := b.Date()
	months := (y2-y1)*12 + int(m2-m1)
	if d2 < d1 {
		months--
	}
	if months < 0 {
		return 0
	}
	return months
}

// monthsSpanInclusive counts calendar months crossed by [from..to] (e.g., Sep..Nov => 3).
func monthsSpanInclusive(from, to time.Time) int {
	if to.Before(from) {
		return 0
	}
	y1, m1, _ := from.Date()
	y2, m2, _ := to.Date()
	return (y2-y1)*12 + int(m2-m1) + 1
}

// tiny pretty flag for the table
func boolFlag(b bool) string {
	if b {
		return "✓"
	}
	return "·"
}

func repoTimes(client *http.Client, base, owner, repo, token string) (created, updated, pushed time.Time, err error) {
	u := stringsTrimRightSlash(base) + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)

	var m map[string]any
	if err := getJSONAuth(client, u, token, &m); err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	created = pickTime(m, "created", "created_at", "created_unix")
	updated = pickTime(m, "updated", "updated_at", "updated_unix")
	pushed = pickTime(m, "pushed_at", "pushed", "pushed_unix", "last_pushed")
	return
}

func pickTime(m map[string]any, keys ...string) time.Time {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if tt := parseAnyTime(t); !tt.IsZero() {
					return tt
				}
			case float64: // JSON numbers come as float64
				if t > 0 {
					return time.Unix(int64(t), 0)
				}
			}
		}
	}
	return time.Time{}
}

func getJSONAuth(client *http.Client, urlStr, token string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, urlStr, nil)
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, urlStr, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func stringsTrimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func parseAnyTime(s string) time.Time {
	fmts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05-0700",
		"2006-01-02 15:04:05 -0700 MST",
	}
	for _, f := range fmts {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// last commit date for given login (searches by email and login)
func giteaLatestCommitDate(client *http.Client, base, token, login string) (string, error) {
	user, err := giteaGetUser(client, base, token, login)
	if err != nil {
		return "", err
	}
	email := user.Email
	repos, err := giteaCollectRepos(client, base, token, user.ID, login)
	if err != nil {
		return "", err
	}
	if len(repos) == 0 {
		return "", nil
	}

	loc, _ := time.LoadLocation(GITEA_TZ)
	var best time.Time
	for _, r := range repos {
		if r.Empty {
			continue
		}
		ts, err := latestCommitInRepoForAuthor(client, base, token, r.Owner, r.Name, r.DefaultBranch, login, email)
		if err != nil || ts.IsZero() {
			continue
		}
		if best.IsZero() || ts.After(best) {
			best = ts
		}
	}
	if best.IsZero() {
		return "", nil
	}
	if loc == nil {
		loc = time.Local
	}
	return best.In(loc).Format("2006-01-02"), nil
}

type gUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

func giteaGetUser(client *http.Client, base, token, login string) (gUser, error) {
	var out gUser
	u := stringsTrimRightSlash(base) + "/users/" + url.PathEscape(login)
	var m map[string]any
	if err := getJSONAuth(client, u, token, &m); err != nil {
		return out, err
	}
	if id, ok := m["id"].(float64); ok {
		out.ID = int64(id)
	}
	out.Login, _ = m["login"].(string)
	out.Email, _ = m["email"].(string)
	if out.ID == 0 {
		return out, fmt.Errorf("user lookup failed for %s: %#v", login, m)
	}
	return out, nil
}

type gRepo struct {
	FullName      string
	Owner         string
	Name          string
	Empty         bool
	DefaultBranch string
}

func giteaCollectRepos(client *http.Client, base, token string, uid int64, login string) ([]gRepo, error) {
	all := map[string]gRepo{}
	pull := func(path string) ([]map[string]any, error) {
		page := 1
		var out []map[string]any
		for {
			sep := "?"
			if strings.Contains(path, "?") {
				sep = "&"
			}
			u := stringsTrimRightSlash(base) + path + fmt.Sprintf("%slimit=%d&page=%d", sep, 50, page)
			var j any
			if err := getJSONAuth(client, u, token, &j); err != nil {
				return out, err
			}
			arr, ok := j.([]any)
			if !ok || len(arr) == 0 {
				break
			}
			for _, it := range arr {
				if m, ok := it.(map[string]any); ok {
					out = append(out, m)
				}
			}
			if len(arr) < 50 {
				break
			}
			page++
		}
		return out, nil
	}
	a, err := pull("/repos/search?uid=" + url.QueryEscape(strconv.FormatInt(uid, 10)) + "&private=true")
	if err != nil {
		return nil, err
	}
	b, err := pull("/users/" + url.PathEscape(login) + "/repos")
	if err != nil {
		return nil, err
	}
	parse := func(m map[string]any) {
		full, _ := m["full_name"].(string)
		owner := ""
		if o, ok := m["owner"].(map[string]any); ok {
			owner, _ = o["login"].(string)
		}
		name, _ := m["name"].(string)
		if full == "" && owner != "" && name != "" {
			full = owner + "/" + name
		}
		if full == "" {
			return
		}
		if _, seen := all[full]; seen {
			return
		}
		empty, _ := m["empty"].(bool)
		def, _ := m["default_branch"].(string)
		if owner == "" && full != "" {
			parts := strings.SplitN(full, "/", 2)
			if len(parts) == 2 {
				owner, name = parts[0], parts[1]
			}
		}
		all[full] = gRepo{FullName: full, Owner: owner, Name: name, Empty: empty, DefaultBranch: def}
	}
	for _, m := range a {
		parse(m)
	}
	for _, m := range b {
		parse(m)
	}
	out := make([]gRepo, 0, len(all))
	for _, v := range all {
		out = append(out, v)
	}
	if len(out) > 30 {
		out = out[:30]
	}
	return out, nil
}

func latestCommitInRepoForAuthor(client *http.Client, base, token, owner, name, defaultBranch, login, email string) (time.Time, error) {
	shaParam := ""
	if defaultBranch != "" {
		shaParam = "&sha=" + url.QueryEscape(defaultBranch)
	}
	basePath := fmt.Sprintf("/repos/%s/%s/commits?limit=%d&page=1%s",
		url.PathEscape(owner), url.PathEscape(name), 1, shaParam)

	attempts := []string{}
	if strings.Contains(email, "@") {
		attempts = append(attempts, basePath+"&author="+url.QueryEscape(email))
	}
	attempts = append(attempts, basePath+"&author="+url.QueryEscape(login))

	for _, path := range attempts {
		u := stringsTrimRightSlash(base) + path
		var j any
		if err := getJSONAuth(client, u, token, &j); err != nil {
			continue
		}
		arr, ok := j.([]any)
		if !ok || len(arr) == 0 {
			continue
		}
		m, _ := arr[0].(map[string]any)
		var iso string
		if cm, ok := m["commit"].(map[string]any); ok {
			if comm, ok := cm["committer"].(map[string]any); ok {
				if d, ok := comm["date"].(string); ok && d != "" {
					iso = d
				}
			}
			if iso == "" {
				if auth, ok := cm["author"].(map[string]any); ok {
					if d, ok := auth["date"].(string); ok && d != "" {
						iso = d
					}
				}
			}
		}
		if iso == "" {
			continue
		}
		if t := parseAnyTime(iso); !t.IsZero() {
			return t, nil
		}
	}
	return time.Time{}, nil
}

// (kept but unused; safe to remove if you want)
// func latestUserCommitActivity(...) { ... }

//
// =================== MAIN ===================
//

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	in := bufio.NewReader(os.Stdin)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func main() {
	_, _ = LoadDotEnv(".env", filepath.Join("..", ".env"))

	hasuraSecret := os.Getenv("HASURA_ADMIN_KEY")
	if hasuraSecret == "" {
		die("HASURA_ADMIN_KEY is empty (set it in .env)")
	}
	giteaToken := os.Getenv("GITEA_TOKEN")

	httpClient := &http.Client{Timeout: 20 * time.Second}

	// ---- Inputs ----
	usersPath := readLine(fmt.Sprintf("Path to USERS.txt (default %s): ", defaultUsersPath)) // TODO ftch it from graphQl
	if usersPath == "" {
		usersPath = defaultUsersPath
	}
	if !fileExists(usersPath) {
		die("USERS file not found at %s", usersPath)
	}

	//read csv file from ttlock
	csvPath := readLine(fmt.Sprintf("Path to TTLock CSV (default %s): ", defaultCSVPath))
	if csvPath == "" {
		csvPath = defaultCSVPath
	}
	if !fileExists(csvPath) {
		die("CSV not found at %s", csvPath)
	}

	//give dates
	fromStr := "2025-08-01" //Just for testing     readLine("From date [YYYY-MM-DD]: ")
	toStr := "2025-10-30"   //Same here     readLine("To   date [YYYY-MM-DD]: ")
	if !validateYMD(fromStr) || !validateYMD(toStr) {
		die("from/to must be in YYYY-MM-DD format")
	}

	athensTZ, _ := time.LoadLocation(GITEA_TZ)
	fromDate, err := time.ParseInLocation("2006-01-02", fromStr, athensTZ)
	if err != nil {
		die("bad from date: %v", err)
	}
	toDate, err := time.ParseInLocation("2006-01-02", toStr, athensTZ)
	if err != nil {
		die("bad to date: %v", err)
	}
	monthsWindow := monthsSpanInclusive(fromDate, toDate)
	now := time.Now().In(athensTZ)

	//save users and tt lock actions
	fmt.Println(BoldYellow + "...Loading users & CSV..." + Reset)
	users, err := readUsersTxt(usersPath)
	if err != nil {
		die("readUsersTxt: %v", err)
	}
	actions, err := readTTLockCSV(csvPath)
	if err != nil {
		die("readTTLockCSV: %v", err)
	}

	// Attendance pipeline
	selected := selectPeriod(actions, fromStr, toStr)
	cleaned := uniquePerUserPerDay(selected)

	// Count attendance per user with a flexible matcher (login OR name OR contains)
	attendanceCounts := make(map[string]int, len(users))
	for _, u := range users {
		lkey := strings.ToLower(u.Login)
		nkey := strings.ToLower(u.Name)
		cnt := 0
		for _, a := range cleaned {
			au := normalizeLoginLike(a.Username)

			if au == lkey || au == nkey || strings.Contains(au, lkey) || (nkey != "" && strings.Contains(au, nkey)) {
				cnt++
			}
		}
		attendanceCounts[u.Login] = cnt
	}

	// Build levels once
	levels := buildLevels()

	// Aggregate per user
	// Concurrency limit (tune as needed; 8–16 is usually safe)
	const maxWorkers = 16

	results := make([]AggUser, len(users))

	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for i, u := range users {
		i, u := i, u // capture loop vars
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}        // acquire a slot
			defer func() { <-sem }() // release

			sum := AggUser{
				Login:           u.Login,
				Name:            u.Name,
				AttendanceCount: attendanceCounts[u.Login],
			}

			// ----- Hasura XP/Level -----
			if xps, err := fetchUserXps(httpClient, ENDPOINT, hasuraSecret, u.Login, EVENT_ID, ORIGIN_EVENT_IDS); err == nil {
				sum.TotalXP, sum.TotalProjects = totalsForXps(xps, EXCLUDE_TOTALS_PREFIX)
				levelXp := totalsForXpsOnly(xps, EXCLUDE_LEVEL_PREFIX)
				li := levelFromTotalXp(levelXp, levels)
				sum.Level = li.Level
				sum.LevelProgress = li.Progress
			} else {
				fmt.Fprintf(os.Stderr, "warn: GraphQL for %s: %v\n", u.Login, err)
			}

			// ----- Gitea (optional) -----
			if giteaToken != "" {
				if d, err := giteaLatestCommitDate(httpClient, GITEA_BASE, giteaToken, u.Login); err == nil {
					sum.LastCommitDate = d // YYYY-MM-DD in GITEA_TZ
				} else {
					fmt.Fprintf(os.Stderr, "warn: giteaLatestCommitDate(%s): %v\n", u.Login, err)
				}

				if created, _, _, err := repoTimes(httpClient, GITEA_BASE, u.Login, "go-reloaded", giteaToken); err == nil && !created.IsZero() {
					if loc, _ := time.LoadLocation(GITEA_TZ); loc != nil {
						sum.GoReloadedCreatedAt = created.In(loc).Format("2006-01-02")
					} else {
						sum.GoReloadedCreatedAt = created.Local().Format("2006-01-02")
					}
				}
			}
			// --- Flags + Expected Level ---
			sum.AttOK = sum.AttendanceCount >= monthsWindow*10

			// default
			sum.ExpectedLevel = 0
			sum.LvlOK = false
			sum.PushOK = false

			// lvl: Level ≥ months_since(go-reloaded created) * 2
			if strings.TrimSpace(sum.GoReloadedCreatedAt) != "" {
				if created, err := time.ParseInLocation("2006-01-02", sum.GoReloadedCreatedAt, athensTZ); err == nil {
					months := monthsBetween(created, now)
					expected := 2 * float64(months)
					sum.ExpectedLevel = expected // <-- MISSING LINE
					sum.LvlOK = float64(sum.Level) >= expected
				}
			}

			// push: last push < 30 days from now
			if strings.TrimSpace(sum.LastCommitDate) != "" {
				if last, err := time.ParseInLocation("2006-01-02", sum.LastCommitDate, athensTZ); err == nil {
					sum.PushOK = now.Sub(last) < 30*24*time.Hour
				}
			}

			// derive status
			sum.Status = statusFromFlags(sum.LvlOK, sum.PushOK, sum.AttOK)

			results[i] = sum
		}()
	}

	wg.Wait()

	// Sort by login for stable output (kept as-is)
	sort.Slice(results, func(i, j int) bool { return results[i].Login < results[j].Login })

	// Partition by status
	var oks, bocals, calls []AggUser
	var oksCount, bocalsCount, callsCount int
	for _, r := range results {

		switch r.Status {
		case "ok":
			oks = append(oks, r)
			oksCount++
		case "bocal":
			bocals = append(bocals, r)
			bocalsCount++
		default:
			calls = append(calls, r) // phonecall
			callsCount++
		}
	}

	// ---- 1) List those with status ok ----
	fmt.Println()
	fmt.Println(BoldYellow + "OK" + Reset)
	fmt.Printf("\n%v students are in a good level\n\n", oksCount)
	for _, r := range oks {
		fmt.Printf("- %s (%s)\n", r.Login, truncate(r.Name, 22))
	}

	// ---- 2) Table for status bocal ----
	fmt.Println()
	fmt.Println(BoldYellow + "BOCAL" + Reset)
	fmt.Printf("\n%v students for audits from Bocals\n\n", bocalsCount)
	fmt.Printf("%-14s | %8s | %5s | %8s | %-10s | %-3s | %-3s | %-5s\n",
		"login", "attend", "level", "exp_lvl", "last_push", "lvl", "att", "push")
	fmt.Println(strings.Repeat("-", 78))
	for _, r := range bocals {
		fmt.Printf("%-14s | %8d | %5d | %8.1f | %-10s | %-3s | %-3s | %-5s\n",
			r.Login, r.AttendanceCount, r.Level, r.ExpectedLevel, emptyDash(r.LastCommitDate),
			boolFlag(r.LvlOK), boolFlag(r.AttOK), boolFlag(r.PushOK))
	}

	// ---- 3) Table (same header as before) for status phonecall ----
	fmt.Println()
	fmt.Println(BoldYellow + "PHONECALL" + Reset)
	fmt.Printf("\n%v students for phone call\n\n", callsCount)
	fmt.Printf("%-14s | %-22s | %8s | %9s | %6s | %5s | %5s | %-10s | %-18s | %-3s | %-3s | %-5s\n",
		"login", "name", "attend", "total_xp", "level", "exp_lvl", "proj", "last_git", "go-reloaded_created", "lvl", "att", "push")
	fmt.Println(strings.Repeat("-", 140))
	// helper (near your helpers)

	// ---- sort PHONECALL by last push (oldest first; empty treated as oldest) ----
	sort.SliceStable(calls, func(i, j int) bool {
		ti := parseYMD(calls[i].LastCommitDate, athensTZ)
		tj := parseYMD(calls[j].LastCommitDate, athensTZ)

		if ti.IsZero() && tj.IsZero() { // both missing → tie-break by login
			return calls[i].Login < calls[j].Login
		}
		if ti.IsZero() { // missing last push → goes first (oldest)
			return true
		}
		if tj.IsZero() {
			return false
		}
		return ti.After(tj) // older first
	})

	for _, r := range calls {
		fmt.Printf("%-14s | %-22s | %8d | %9d | %6d | %8.1f | %5d | %-10s | %-18s | %-3s | %-3s | %-5s\n",
			r.Login, truncate(r.Name, 22), r.AttendanceCount, r.TotalXP, r.Level, r.ExpectedLevel, r.TotalProjects,
			emptyDash(r.LastCommitDate), emptyDash(r.GoReloadedCreatedAt),
			boolFlag(r.LvlOK), boolFlag(r.AttOK), boolFlag(r.PushOK))
	}

	// Save JSON + CSV
	if err := saveJSON("aggregated.json", results); err != nil {
		fmt.Fprintf(os.Stderr, "warn: saveJSON: %v\n", err)
	}
	if err := saveCSV("aggregated.csv", results); err != nil {
		fmt.Fprintf(os.Stderr, "warn: saveCSV: %v\n", err)
	}

	fmt.Println()
	fmt.Println(Yellow + "Wrote aggregated.json and aggregated.csv" + Reset)
}

func truncate(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n-1]) + "…"
}
func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func saveJSON(path string, rows []AggUser) error {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
func saveCSV(path string, rows []AggUser) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"login", "name", "attendance_count",
		"total_xp", "total_projects", "level", "level_progress",
		"last_git", "go_reloaded_created",
		"lvl", "att", "push", "expected_level", "status",
	})

	for _, r := range rows {
		_ = w.Write([]string{
			r.Login, r.Name, strconv.Itoa(r.AttendanceCount),
			strconv.Itoa(r.TotalXP), strconv.Itoa(r.TotalProjects), strconv.Itoa(r.Level),
			fmt.Sprintf("%.4f", r.LevelProgress),
			r.LastCommitDate, r.GoReloadedCreatedAt,
			strconv.FormatBool(r.LvlOK), strconv.FormatBool(r.AttOK), strconv.FormatBool(r.PushOK),
			fmt.Sprintf("%.1f", r.ExpectedLevel), r.Status,
		})

	}
	return w.Error()
}
