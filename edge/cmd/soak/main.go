// soak: load and long-connection test for an edge node.
//
//	soak -echo 127.0.0.1:9100                         run a TCP echo server (use it as the node's origin)
//	soak -addr H:P -pin PIN -secret S -mode hold ...  keep N connections open, ping each one regularly
//	soak ... -mode burst                              few connections, many small messages per second
//	soak ... -mode bulk -bulk-mb 100                  one connection, lots of data, verified end to end
//
// The node must forward to an echo server. Every message carries a sequence number and a send time, so a
// reply that is lost, late, duplicated or from another message is detected.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	echoAddr = flag.String("echo", "", "run an echo server on this address instead of testing")
	addr     = flag.String("addr", "", "node host:port")
	pin      = flag.String("pin", "", "node public key pin")
	secret   = flag.String("secret", "", "token secret")
	mode     = flag.String("mode", "hold", "hold | burst | bulk")
	conns    = flag.Int("conns", 50, "number of connections")
	duration = flag.Duration("duration", 5*time.Minute, "how long to run")
	interval = flag.Duration("interval", 20*time.Second, "hold: time between messages on each connection")
	size     = flag.Int("size", 64, "message size in bytes (at least 16)")
	rate     = flag.Int("rate", 100, "burst: messages per second per connection")
	bulkMB   = flag.Int("bulk-mb", 100, "bulk: megabytes to send")
	ramp     = flag.Duration("ramp", 20*time.Millisecond, "delay between opening connections")
	report   = flag.Duration("report", 30*time.Second, "progress line interval")
	plain    = flag.Bool("plain", false, "plain TCP to an echo server (no TLS, no token): a baseline of the network path")
)

// ---------------------------------------------------------------- echo server

func runEcho(listen string) {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("echo server on", listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			io.Copy(c, c)
		}()
	}
}

// ---------------------------------------------------------------- connecting

func token() string {
	body := "soak." + strconv.FormatInt(time.Now().Unix(), 10)
	m := hmac.New(sha256.New, []byte(*secret))
	m.Write([]byte(body))
	return body + "." + hex.EncodeToString(m.Sum(nil))
}

func connect() (net.Conn, time.Duration, error) {
	t0 := time.Now()
	if *plain {
		c, err := net.DialTimeout("tcp", *addr, 10*time.Second)
		if err != nil {
			return nil, 0, err
		}
		return c, time.Since(t0), nil
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", *addr, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // trust is the pin below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			spki, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
			sum := sha256.Sum256(spki)
			if base64.StdEncoding.EncodeToString(sum[:]) != *pin {
				return fmt.Errorf("pin mismatch")
			}
			return nil
		},
	})
	if err != nil {
		return nil, 0, err
	}
	hs := time.Since(t0)
	tok := token()
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(tok)))
	if _, err := c.Write(append(h[:], tok...)); err != nil {
		c.Close()
		return nil, 0, err
	}
	return c, hs, nil
}

// ---------------------------------------------------------------- statistics

type recorder struct {
	mu        sync.Mutex
	window    []time.Duration
	all       []time.Duration
	handshake []time.Duration
	reasons   map[string]int

	started    int64
	connFail   int64
	alive      int64
	lost       int64
	sent       int64
	received   int64
	timeouts   int64
	mismatches int64
}

func newRecorder() *recorder { return &recorder{reasons: map[string]int{}} }

func (r *recorder) addRTT(d time.Duration) {
	r.mu.Lock()
	r.window = append(r.window, d)
	r.all = append(r.all, d)
	r.mu.Unlock()
}

func (r *recorder) addHandshake(d time.Duration) {
	r.mu.Lock()
	r.handshake = append(r.handshake, d)
	r.mu.Unlock()
}

func (r *recorder) reason(kind string) {
	r.mu.Lock()
	r.reasons[kind]++
	r.mu.Unlock()
}

func pct(v []time.Duration, p float64) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(float64(len(s)-1) * p)
	return s[i]
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

func (r *recorder) line(prefix string) string {
	r.mu.Lock()
	w := r.window
	r.window = nil
	r.mu.Unlock()
	return fmt.Sprintf("%s alive=%d lost=%d sent=%d recv=%d timeouts=%d mismatch=%d | window n=%d p50=%s p95=%s p99=%s max=%s",
		prefix, atomic.LoadInt64(&r.alive), atomic.LoadInt64(&r.lost), atomic.LoadInt64(&r.sent),
		atomic.LoadInt64(&r.received), atomic.LoadInt64(&r.timeouts), atomic.LoadInt64(&r.mismatches),
		len(w), ms(pct(w, .5)), ms(pct(w, .95)), ms(pct(w, .99)), ms(pct(w, 1)))
}

// ---------------------------------------------------------------- hold / burst

// echoLoop sends one message every `gap` until `end`; it returns why it stopped ("" = ran to the end).
func echoLoop(c net.Conn, end time.Time, gap time.Duration, r *recorder) string {
	n := *size
	if n < 16 {
		n = 16
	}
	out := make([]byte, n)
	in := make([]byte, n)
	var seq uint64
	for time.Now().Before(end) {
		seq++
		binary.BigEndian.PutUint64(out, seq)
		sentAt := time.Now()
		binary.BigEndian.PutUint64(out[8:], uint64(sentAt.UnixNano()))

		c.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := c.Write(out); err != nil {
			return "write: " + short(err)
		}
		atomic.AddInt64(&r.sent, 1)
		if _, err := io.ReadFull(c, in); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				atomic.AddInt64(&r.timeouts, 1)
				return "no reply within 15s"
			}
			return "read: " + short(err)
		}
		if binary.BigEndian.Uint64(in) != seq {
			atomic.AddInt64(&r.mismatches, 1)
			return "reply out of sequence"
		}
		atomic.AddInt64(&r.received, 1)
		r.addRTT(time.Since(sentAt))

		wait := gap
		if gap > 0 {
			wait = gap - time.Duration(rand.Int63n(int64(gap)/5+1)) // jitter, never longer than gap
		}
		if left := time.Until(end); wait > left {
			wait = left
		}
		if wait > 0 {
			time.Sleep(wait)
		}
	}
	return ""
}

func short(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	return s
}

func runEchoMode(gap time.Duration) {
	r := newRecorder()
	end := time.Now().Add(*duration)
	var wg sync.WaitGroup

	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(*report)
		defer t.Stop()
		start := time.Now()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				fmt.Println(r.line(fmt.Sprintf("[%5.0fs]", time.Since(start).Seconds())))
			}
		}
	}()

	for i := 0; i < *conns; i++ {
		wg.Add(1)
		atomic.AddInt64(&r.started, 1)
		go func() {
			defer wg.Done()
			c, hs, err := connect()
			if err != nil {
				atomic.AddInt64(&r.connFail, 1)
				r.reason("connect: " + short(err))
				return
			}
			defer c.Close()
			r.addHandshake(hs)
			atomic.AddInt64(&r.alive, 1)
			why := echoLoop(c, end, gap, r)
			atomic.AddInt64(&r.alive, -1)
			if why != "" {
				atomic.AddInt64(&r.lost, 1)
				r.reason(why)
			}
		}()
		time.Sleep(*ramp)
	}
	wg.Wait()
	close(stop)

	fmt.Println()
	fmt.Println(r.line("[final] "))
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Printf("connections: started=%d connect-failed=%d lost-before-end=%d\n", r.started, r.connFail, r.lost)
	fmt.Printf("handshake:   n=%d p50=%s p95=%s max=%s\n", len(r.handshake), ms(pct(r.handshake, .5)), ms(pct(r.handshake, .95)), ms(pct(r.handshake, 1)))
	fmt.Printf("round trip:  n=%d p50=%s p95=%s p99=%s max=%s\n", len(r.all), ms(pct(r.all, .5)), ms(pct(r.all, .95)), ms(pct(r.all, .99)), ms(pct(r.all, 1)))
	for k, v := range r.reasons {
		fmt.Printf("  %dx %s\n", v, k)
	}
	if r.lost > 0 || r.connFail > 0 || r.mismatches > 0 {
		fmt.Println("RESULT: PROBLEMS")
		os.Exit(1)
	}
	fmt.Println("RESULT: OK")
}

// ---------------------------------------------------------------- bulk

func runBulk() {
	c, hs, err := connect()
	if err != nil {
		log.Fatal("connect: ", err)
	}
	defer c.Close()
	total := int64(*bulkMB) << 20
	fmt.Printf("bulk: %d MB each way, handshake %s\n", *bulkMB, ms(hs))

	sentHash := sha256.New()
	gotHash := sha256.New()
	rng := rand.New(rand.NewSource(42))
	start := time.Now()

	werr := make(chan error, 1)
	go func() {
		buf := make([]byte, 32<<10)
		var n int64
		for n < total {
			chunk := buf
			if left := total - n; left < int64(len(chunk)) {
				chunk = buf[:left]
			}
			rng.Read(chunk)
			sentHash.Write(chunk)
			c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := c.Write(chunk); err != nil {
				werr <- err
				return
			}
			n += int64(len(chunk))
		}
		werr <- nil
	}()

	buf := make([]byte, 64<<10)
	var got int64
	last := time.Now()
	for got < total {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := c.Read(buf)
		if n > 0 {
			gotHash.Write(buf[:n])
			got += int64(n)
		}
		if err != nil {
			break
		}
		if time.Since(last) > 5*time.Second {
			fmt.Printf("  %d / %d MB\n", got>>20, total>>20)
			last = time.Now()
		}
	}
	elapsed := time.Since(start)
	if err := <-werr; err != nil {
		fmt.Println("write error:", err)
	}
	ok := got == total && hex.EncodeToString(sentHash.Sum(nil)) == hex.EncodeToString(gotHash.Sum(nil))
	fmt.Printf("received %d of %d bytes in %.1fs = %.1f MB/s each way, data intact: %v\n",
		got, total, elapsed.Seconds(), float64(total)/1048576/elapsed.Seconds(), ok)
	if !ok {
		fmt.Println("RESULT: PROBLEMS")
		os.Exit(1)
	}
	fmt.Println("RESULT: OK")
}

func main() {
	flag.Parse()
	if *echoAddr != "" {
		runEcho(*echoAddr)
		return
	}
	if *addr == "" || (!*plain && (*pin == "" || *secret == "")) {
		log.Fatal("-addr is required, and -pin and -secret unless -plain")
	}
	switch *mode {
	case "hold":
		runEchoMode(*interval)
	case "burst":
		runEchoMode(time.Second / time.Duration(*rate))
	case "bulk":
		runBulk()
	default:
		log.Fatal("unknown -mode ", *mode)
	}
}
