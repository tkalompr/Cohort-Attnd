package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// ---------------------------- FORMATING ----------------------------------------//
const (
	BoldRed    = "\033[1;31m" // bold red
	BoldYellow = "\033[1;33m" // bold yellow
	Reset      = "\033[0m"
	Yellow     = "\033[0;33m"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, BoldRed+"USAGE"+Reset+`:
`+BoldYellow+` 
program -from "2025-10-01" -to "2025-10-07" -csv "/path/ttlock.csv"
`+Yellow+`
Flags:
  -from   initial day (YYYY-MM-DD)
  -to     last day (YYYY-MM-DD)
  -csv    path of csv file
`+Reset)
}

// ---------------------------- Record Types ------------------------------------//
type RecordType int

const (
	UnlockWithApp RecordType = iota
	Locked
	UnlockWithPassword
)

// Από string σε enum (για CSV parsing)
func ParseRecordType(s string) RecordType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "unlock with app":
		return UnlockWithApp
	case "locked":
		return Locked
	case "unlock with password":
		return UnlockWithPassword
	default:
		return -1 // ή φτιάξε RecordTypeUnknown
	}
}

// ------------------------------- USER STRUCT ----------------------------//

// This is the action model and the data that we have from ttLock
type Record struct {
	Login  string
	Name   string
	Type   string
	Stamps []time.Time // raw timestamps εισόδου/εξόδου (θα τα φιλτράρεις/ζευγαρώσεις)
}

type Action struct {
	Username string
	RecordType
	Timestamp time.Time
}

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
	Days         []time.Time
}

// ---------------------------- Functions - methods ----------------------------//
func Reader(path string) ([]User, error) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, BoldRed+"Failed to open users file"+Reset, ":", err)
		return nil, err
	}
	defer f.Close()

	scanner := bufio.Newscanner(file)
	var users []User
	var cur *User
	state := 0 // 0: περιμένω Login, 1: περιμένω Name

	for scanner.scanner() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == "---" { // προαιρετικός διαχωριστής
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

	// Αν το αρχείο τελειώνει “στη μέση” (π.χ. λείπει Name), μπορείς να το ελέγξεις:
	if state == 1 && cur != nil {
		fmt.Fprintln(os.Stderr, Yellow+"Warning:"+Reset, "last user is missing a Name line; skipping")
	}

	return users, nil
}

func LoadUsers(names string) []User {
	var users []User

	return users
}

// ============================ MAIN FUNCTION ================================= //

func main() {
	// read users fille
	users, err := Reader("./USERS.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: reader Cannot read")
		return
	}

	fmt.Println(users)

	// flag variables init
	// fromStr := flag.String("from", "", "start date (YYYY-MM-DD)")
	// toStr := flag.String("to", "", "end date (YYYY-MM-DD)")
	csvPath := flag.String("csv", "", "path to TTLock CSV")
	flag.Parse()

	if *csvPath == "" {
		printUsage()
		return
	}

	fmt.Println(BoldYellow + "...Calculating..." + Reset)

	// 1) Parse dates σε Europe/Athens

	// 2) Διάβασε CSV (θα βάλεις εδώ τον reader σου)

	// 3) Παράδειγμα χρήσης:

}
