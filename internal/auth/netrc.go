package auth

import (
	"bufio"
	"fmt"
	"os"
)

// credential is a login/password pair for one netrc "machine" entry.
type credential struct {
	login    string
	password string
}

// parseNetrc reads a netrc(5)-format file: whitespace-separated
// "machine HOST login USER password PASS" entries. Only machine, login, and
// password tokens are recognized; default, macdef, and account are not.
func parseNetrc(path string) (map[string]credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	creds := make(map[string]credential)
	var host string
	var cur credential
	flush := func() {
		if host != "" {
			creds[host] = cur
		}
		host, cur = "", credential{}
	}

	sc := bufio.NewScanner(f)
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		switch sc.Text() {
		case "machine":
			flush()
			if !sc.Scan() {
				return nil, fmt.Errorf("netrc: %s: machine with no value", path)
			}
			host = sc.Text()
		case "login":
			if !sc.Scan() {
				return nil, fmt.Errorf("netrc: %s: login with no value", path)
			}
			cur.login = sc.Text()
		case "password":
			if !sc.Scan() {
				return nil, fmt.Errorf("netrc: %s: password with no value", path)
			}
			cur.password = sc.Text()
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return creds, nil
}
