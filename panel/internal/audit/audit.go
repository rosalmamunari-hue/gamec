// Package audit is an append-only log of everything done through the panel. Each entry carries the hash of
// the one before it, so deleting, changing or reordering an entry breaks the chain and Verify reports it.
// (Someone who can rewrite the whole file can rebuild a valid chain; ship the log elsewhere for that.)
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip,omitempty"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
	OK     bool      `json:"ok"`
	Prev   string    `json:"prev"`
	Hash   string    `json:"hash"`
}

func sum(prev string, e Entry) string {
	e.Hash = ""
	e.Prev = prev
	b, _ := json.Marshal(e)
	h := sha256.Sum256(append([]byte(prev+"|"), b...))
	return hex.EncodeToString(h[:])
}

type Log struct {
	mu   sync.Mutex
	path string
	last string
}

// Open continues an existing log, or starts one. A log whose chain is already broken is refused so that
// new entries are not silently appended to a tampered history.
func Open(path string) (*Log, error) {
	l := &Log{path: path}
	if _, err := os.Stat(path); err == nil {
		_, last, err := verify(path)
		if err != nil {
			return nil, fmt.Errorf("audit log is damaged: %w", err)
		}
		l.last = last
	}
	return l, nil
}

func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.Prev = l.last
	e.Hash = sum(l.last, e)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	l.last = e.Hash
	return nil
}

func verify(path string) (n int, last string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	prev := ""
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, prev, fmt.Errorf("line %d is not valid: %w", n+1, err)
		}
		if e.Prev != prev {
			return n, prev, fmt.Errorf("line %d: the chain is broken (an entry was removed, changed or reordered)", n+1)
		}
		if sum(prev, e) != e.Hash {
			return n, prev, fmt.Errorf("line %d: the entry was modified", n+1)
		}
		prev = e.Hash
		n++
	}
	return n, prev, sc.Err()
}

// Verify checks the whole chain and returns the number of entries.
func Verify(path string) (int, error) {
	n, _, err := verify(path)
	return n, err
}

// Tail returns the newest n entries, newest first.
func Tail(path string, n int) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, sc.Err()
}
