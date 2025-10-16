package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
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
type ActionsOpps interface {
	SelectPeriod(from, to string) ([]Action, error)
	DublicateRemover() ([]Action, error)
}

type ActionList []Action

// Data from every day key usage
type Action struct {
	Username string
	RecordType
	Timestamp string
}

// Data for all the selected from user session
type InputSession struct {
	MonthsOfSession []int
	Count           int
}

// Data for every month inside the session
type SessionPerMonth struct {
	WeeksOfSession []int
	Count          int
}

// User data
type User struct {
	Login string
	Name  string
	InputSession
	SessionPerMonth
	CountPerWeek int
	Days         string
}

// ---------------------------- Functions - methods ----------------------------//

// Read the users file from the funel and standarize the length of the [] of users.
// It also keeps the username and the full name of the user.
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
	state := 0 // 0: waiting Login, 1: wating for full name

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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

	// Unreaded document or corrupted (no name, no username, etc)
	if state == 1 && cur != nil {
		fmt.Fprintln(os.Stderr, Yellow+"Warning:"+Reset, "last user is missing a Name line; skipping")
	}

	return users, nil
}

func CSVReader(path string) ([]Action, error) {
	// This function takes the csv file it transforms the data to []Actions.
	// Also two helpers inside :
	// 1) Selecting the input-given period only
	// 2) Cleanning of dublicates per day
	return nil, nil
}

// ============================ METHODS ======================================= //

func (a ActionList) SelectPeriod(from, to string) ([]Action, error) {
	//Select a piece of the []Actions depending on the given dates
	return nil, nil
}
func (a ActionList) DublicateRemover() ([]Action, error) {
	//Keeps 1 action for a user per day from []Actions
	return nil, nil
}

// ============================ MAIN FUNCTION ================================= //

func main() {
	// read users file
	users, err := Reader("./USERS.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:Users.txt cannot be red")
		return
	}

	fmt.Println(users)

	actions, err := CSVReader("./ttlockResponse.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:CSV cannot be red")
		return
	}

	fmt.Println(actions)

	// // Flag variables parsing
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
