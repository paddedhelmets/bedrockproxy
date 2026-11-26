// Command landial performs full NetherNet LAN signaling dials to a discovery
// host and reports the answer's ICE candidates and connection results.
//
// With -dials N it attempts N concurrent dials, in one of two modes:
//
//	-mode shared   all dials signal through ONE shared listener, so the host
//	               sees N simultaneous connections from a single network ID
//	               (how a naive signaling tunnel collapses many clients).
//	-mode direct   each dial uses its own listener, so the host sees N peers
//	               (how consoles connect without a proxy).
//
// Comparing the two isolates whether the host accepts multiple concurrent
// sessions per network ID.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

type sniffer struct{ verbose bool }

func (s sniffer) NotifySignal(sig *nethernet.Signal) bool {
	if !s.verbose {
		return false
	}
	switch sig.Type {
	case nethernet.SignalTypeAnswer:
		fmt.Println("ANSWER signal received; candidate lines:")
		printCandidates(sig.Data)
	case nethernet.SignalTypeCandidate:
		fmt.Printf("TRICKLED candidate: %s\n", strings.TrimSpace(sig.Data))
	case nethernet.SignalTypeError:
		fmt.Printf("ERROR signal: %s\n", strings.TrimSpace(sig.Data))
	}
	return false
}

func printCandidates(sdp string) {
	found := false
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=candidate:") || strings.HasPrefix(line, "c=IN IP") {
			fmt.Printf("  %s\n", line)
			found = true
		}
	}
	if !found {
		fmt.Println("  (no inline candidate lines)")
	}
}

func listen(target *net.UDPAddr, verbose bool) (*discovery.Listener, error) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	l, err := (discovery.ListenConfig{BroadcastAddress: target, Log: quiet}).Listen("0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	l.Notify(sniffer{verbose: verbose})
	return l, nil
}

// awaitDiscovery waits for the target's discovery response and returns its ID.
func awaitDiscovery(l *discovery.Listener, wait time.Duration) (uint64, bool) {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		for id := range l.Responses() {
			return id, true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, false
}

func main() {
	var target string
	var waitSeconds int
	var allowIdentityless bool
	var dials int
	var mode string
	flag.StringVar(&target, "target", "127.0.0.1:7551", "UDP address of the NetherNet LAN host to dial")
	flag.IntVar(&waitSeconds, "wait", 5, "seconds to wait for discovery before dialing")
	flag.BoolVar(&allowIdentityless, "allow-identityless", false, "accept answers without an a=identity assertion")
	flag.IntVar(&dials, "dials", 1, "number of concurrent dials")
	flag.StringVar(&mode, "mode", "direct", "direct: one listener per dial; shared: one listener for all dials")
	flag.Parse()
	if mode != "direct" && mode != "shared" {
		fmt.Fprintln(os.Stderr, "-mode must be direct or shared")
		os.Exit(2)
	}

	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve:", err)
		os.Exit(1)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	wait := time.Duration(waitSeconds) * time.Second
	verbose := dials == 1

	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []*nethernet.Conn
	results := make(chan string, dials)

	attempt := func(label string, signaling *discovery.Listener, id uint64) {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d := nethernet.Dialer{
			Log: quiet, AllowIdentitylessServer: allowIdentityless,
			ConnectionID: rand.Uint64(),
		}
		started := time.Now()
		conn, err := d.DialContext(ctx, strconv.FormatUint(id, 10), signaling)
		if err != nil {
			results <- fmt.Sprintf("%-8s FAILED after %6.1fs: %v", label, time.Since(started).Seconds(), err)
			return
		}
		mu.Lock()
		conns = append(conns, conn)
		mu.Unlock()
		results <- fmt.Sprintf("%-8s CONNECTED in %6.1fs", label, time.Since(started).Seconds())
	}

	switch mode {
	case "shared":
		shared, err := listen(addr, verbose)
		if err != nil {
			fmt.Println("listen:", err)
			os.Exit(1)
		}
		defer shared.Close()
		id, ok := awaitDiscovery(shared, wait)
		if !ok {
			fmt.Println("no discovery responses")
			os.Exit(1)
		}
		fmt.Printf("mode=shared: %d concurrent dials to network ID %d through ONE listener (network ID %s)\n",
			dials, id, shared.NetworkID())
		for i := 0; i < dials; i++ {
			wg.Add(1)
			go attempt(fmt.Sprintf("dial %d", i+1), shared, id)
		}
	case "direct":
		// Prepare every listener first so all dials start together.
		type peer struct {
			l  *discovery.Listener
			id uint64
		}
		var peers []peer
		for i := 0; i < dials; i++ {
			l, err := listen(addr, verbose)
			if err != nil {
				fmt.Println("listen:", err)
				os.Exit(1)
			}
			defer l.Close()
			peers = append(peers, peer{l: l})
		}
		deadline := time.Now().Add(wait)
		for i := range peers {
			found := false
			for time.Now().Before(deadline) {
				if id, ok := awaitDiscovery(peers[i].l, 200*time.Millisecond); ok {
					peers[i].id = id
					found = true
					break
				}
			}
			if !found {
				fmt.Println("no discovery responses")
				os.Exit(1)
			}
		}
		fmt.Printf("mode=direct: %d concurrent dials, each through its own listener\n", dials)
		for i, p := range peers {
			wg.Add(1)
			go attempt(fmt.Sprintf("dial %d", i+1), p.l, p.id)
		}
	}

	go func() { wg.Wait(); close(results) }()
	for r := range results {
		fmt.Println(" ", r)
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
