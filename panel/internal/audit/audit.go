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
	"io"
	"os"
	"sync"
	"time"

	"gamec/panel/internal/flock"
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
	size int64 // file size after our last append; more means another process (a panel command) appended
}

// Open continues an existing log, or starts one. A log whose chain is already broken is refused so that
// new entries are not silently appended to a tampered history.
func Open(path string) (*Log, error) {
	l := &Log{path: path}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Under the lock, so the hash and the size describe the same entries even if the server (or a
	// command) appends at this moment.
	if err := flock.Lock(f); err != nil {
		return nil, err
	}
	_, last, err := verifyFrom(f)
	if err != nil {
		return nil, fmt.Errorf("audit log is damaged: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	l.last, l.size = last, fi.Size()
	return l, nil
}

func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	// The server and the command-line tools both append; the lock and the catch-up keep one chain.
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := flock.Lock(f); err != nil {
		return err
	}
	last, size, err := catchUp(f, l.last, l.size)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	e.Prev = last
	e.Hash = sum(last, e)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		f.Truncate(size) // a half-written line would make the next start refuse the log
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	l.last, l.size = e.Hash, size+int64(len(b))
	return nil
}

// catchUp checks the entries appended after offset by someone else and returns the newest hash and the size.
func catchUp(f *os.File, last string, offset int64) (string, int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if fi.Size() == offset {
		return last, offset, nil
	}
	if fi.Size() < offset {
		return "", 0, errors.New("the file got shorter: entries were removed")
	}
	sc := bufio.NewScanner(io.NewSectionReader(f, offset, fi.Size()-offset))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return "", 0, fmt.Errorf("an entry added by another process is not valid: %w", err)
		}
		if e.Prev != last || sum(last, e) != e.Hash {
			return "", 0, errors.New("an entry added by another process does not continue the chain")
		}
		last = e.Hash
	}
	return last, fi.Size(), sc.Err()
}

func verify(path string) (n int, last string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	return verifyFrom(f)
}

func verifyFrom(r io.Reader) (n int, last string, err error) {
	sc := bufio.NewScanner(r)
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
