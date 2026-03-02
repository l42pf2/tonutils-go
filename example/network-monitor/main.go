package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
	"github.com/xssnick/tonutils-go/tl"
)

var flagConfig = flag.String("config", "https://ton-blockchain.github.io/global.config.json", "TON global config URL or file path")

// ─── ANSI helpers ─────────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiClear  = "\033[H\033[2J" // cursor home + clear screen
)

// ─── Status type ──────────────────────────────────────────────────────────────

type status int

const (
	statusPending status = iota
	statusOK
	statusFail
)

func (s status) label() (text, color string) {
	switch s {
	case statusOK:
		return "OK", ansiGreen
	case statusFail:
		return "FAIL", ansiRed
	default:
		return "...", ansiYellow
	}
}

// ─── Entry ────────────────────────────────────────────────────────────────────

type entry struct {
	addr     string
	keyShort string
	st       status
	latency  time.Duration
	checked  time.Time
}

// ─── Table column widths (visible characters) ─────────────────────────────────

const (
	wAddr    = 23
	wKey     = 16
	wSt      = 6
	wLat     = 10
	wCheck   = 10
	// total row width: │ +addr+ │ +key+ │ +st+ │ +lat+ │ +check+ │
	// = (1+1) + 23 + (1+1+1) + 16 + (1+1+1) + 6 + (1+1+1) + 10 + (1+1+1) + 10 + (1+1)
	// = 2 + 23 + 3 + 16 + 3 + 6 + 3 + 10 + 3 + 10 + 2 = 81
	tableInner = wAddr + wKey + wSt + wLat + wCheck + 4*3 + 2 // = 81−2 = 79
)

var hline = strings.Repeat("─", tableInner)

// ─── Shared state ─────────────────────────────────────────────────────────────

var (
	mu          sync.Mutex
	lsEntries   []entry
	dhtEntries  []entry
	lastRefresh time.Time

	checkRunning atomic.Bool
)

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	cfg, err := loadConfig(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Build initial LS entries.
	lsEntries = make([]entry, len(cfg.Liteservers))
	for i, ls := range cfg.Liteservers {
		lsEntries[i] = entry{
			addr:     fmt.Sprintf("%s:%d", ip4(int64(ls.IP)), ls.Port),
			keyShort: shortKey(ls.ID.Key),
		}
	}

	// Build initial DHT entries (one per node, first address only).
	for _, node := range cfg.DHT.StaticNodes.Nodes {
		if len(node.AddrList.Addrs) == 0 {
			continue
		}
		a := node.AddrList.Addrs[0]
		dhtEntries = append(dhtEntries, entry{
			addr:     fmt.Sprintf("%s:%d", ip4(int64(a.IP)), a.Port),
			keyShort: shortKey(node.ID.Key),
		})
	}

	// ADNL gateway for DHT pings.
	_, privKey, _ := ed25519.GenerateKey(nil)
	gw := adnl.NewGateway(privKey)
	if err = gw.StartClient(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start ADNL gateway: %v\n", err)
		os.Exit(1)
	}

	// Silence internal loggers.
	adnl.Logger = func(...any) {}

	render()

	// First check immediately.
	triggerCheck(cfg, gw)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			triggerCheck(cfg, gw)
		case <-quit:
			fmt.Print("\033[H\033[J") // clear before exit
			fmt.Println("Exiting.")
			return
		}
	}
}

// triggerCheck starts a check cycle if one is not already running.
func triggerCheck(cfg *liteclient.GlobalConfig, gw *adnl.Gateway) {
	if checkRunning.Swap(true) {
		return
	}
	go func() {
		defer checkRunning.Store(false)
		doCheck(cfg, gw)
		render()
	}()
}

// ─── Check logic ──────────────────────────────────────────────────────────────

func doCheck(cfg *liteclient.GlobalConfig, gw *adnl.Gateway) {
	var wg sync.WaitGroup

	// Liteservers.
	for i, ls := range cfg.Liteservers {
		wg.Add(1)
		go func(i int, ls liteclient.LiteserverConfig) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip4(int64(ls.IP)), ls.Port)
			st, lat := checkLS(addr, ls.ID.Key)
			mu.Lock()
			lsEntries[i].st = st
			lsEntries[i].latency = lat
			lsEntries[i].checked = time.Now()
			mu.Unlock()
		}(i, ls)
	}

	// DHT nodes.
	idx := 0
	for _, node := range cfg.DHT.StaticNodes.Nodes {
		if len(node.AddrList.Addrs) == 0 {
			continue
		}
		wg.Add(1)
		go func(i int, node liteclient.DHTNode) {
			defer wg.Done()
			a := node.AddrList.Addrs[0]
			addr := fmt.Sprintf("%s:%d", ip4(int64(a.IP)), a.Port)
			st, lat := checkDHT(gw, addr, node.ID.Key)
			mu.Lock()
			dhtEntries[i].st = st
			dhtEntries[i].latency = lat
			dhtEntries[i].checked = time.Now()
			mu.Unlock()
		}(idx, node)
		idx++
	}

	wg.Wait()

	mu.Lock()
	lastRefresh = time.Now()
	mu.Unlock()
}

// checkLS tries to establish a full liteserver TCP connection (handshake).
func checkLS(addr, key string) (status, time.Duration) {
	pool := liteclient.NewConnectionPool()
	pool.SetOnDisconnect(func(_, _ string) {}) // suppress auto-reconnect

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t := time.Now()
	err := pool.AddConnection(ctx, addr, key)
	lat := time.Since(t)
	pool.Stop()

	if err != nil {
		return statusFail, 0
	}
	return statusOK, lat
}

// checkDHT sends a dht.ping query to a DHT node and waits for dht.pong.
// The ADNL-level peer.Ping() does not work here because DHT nodes only respond
// to DHT-protocol queries, not to bare adnl.message.ping frames.
func checkDHT(gw *adnl.Gateway, addr, keyBase64 string) (status, time.Duration) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return statusFail, 0
	}

	peer, err := gw.RegisterClient(addr, ed25519.PublicKey(keyBytes))
	if err != nil {
		return statusFail, 0
	}

	pingData, err := tl.Serialize(dht.Ping{ID: time.Now().Unix()}, true)
	if err != nil {
		return statusFail, 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var res any
	t := time.Now()
	if err = peer.Query(ctx, tl.Raw(pingData), &res); err != nil {
		return statusFail, 0
	}
	lat := time.Since(t)

	if _, ok := res.(dht.Pong); !ok {
		return statusFail, 0
	}
	return statusOK, lat
}

// ─── Rendering ────────────────────────────────────────────────────────────────

func render() {
	mu.Lock()
	defer mu.Unlock()

	fmt.Print(ansiClear)

	ts := "—"
	if !lastRefresh.IsZero() {
		ts = lastRefresh.Format("15:04:05")
	}

	lsOK := countOK(lsEntries)
	dhtOK := countOK(dhtEntries)

	fmt.Printf("%sTON Network Status Monitor%s    last update: %s\n\n",
		ansiCyan, ansiReset, ts)

	printTable(fmt.Sprintf("Liteservers  %d/%d OK", lsOK, len(lsEntries)), lsEntries)
	fmt.Println()
	printTable(fmt.Sprintf("DHT Nodes    %d/%d OK", dhtOK, len(dhtEntries)), dhtEntries)

	fmt.Printf("\n%sRefreshes every 10 s  •  Ctrl+C to exit%s\n", ansiYellow, ansiReset)
}

func printTable(title string, entries []entry) {
	fmt.Printf("┌%s┐\n", hline)

	// Title row.
	titleVis := " " + title + " "
	pad := tableInner - len(titleVis)
	if pad < 0 {
		pad = 0
	}
	fmt.Printf("│%s%s│\n", titleVis, strings.Repeat(" ", pad))

	fmt.Printf("├%s┤\n", hline)

	// Header.
	fmt.Printf("│ %-*s │ %-*s │ %-*s │ %-*s │ %-*s │\n",
		wAddr, "Address",
		wKey, "Key (short)",
		wSt, "Status",
		wLat, "Latency",
		wCheck, "Last Check",
	)

	fmt.Printf("├%s┤\n", hline)

	if len(entries) == 0 {
		fmt.Printf("│%s│\n", strings.Repeat(" ", tableInner))
	}

	for _, e := range entries {
		label, color := e.st.label()
		// Status cell with color; %-*s pads to wSt visible chars before reset.
		stCell := fmt.Sprintf("%s%-*s%s", color, wSt, label, ansiReset)

		fmt.Printf("│ %-*s │ %-*s │ %s │ %-*s │ %-*s │\n",
			wAddr, trunc(e.addr, wAddr),
			wKey, trunc(e.keyShort, wKey),
			stCell,
			wLat, trunc(fmtLatency(e.st, e.latency), wLat),
			wCheck, trunc(fmtCheck(e.checked), wCheck),
		)
	}

	fmt.Printf("└%s┘\n", hline)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func countOK(entries []entry) int {
	n := 0
	for _, e := range entries {
		if e.st == statusOK {
			n++
		}
	}
	return n
}

func fmtLatency(st status, d time.Duration) string {
	if st != statusOK {
		return "—"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func fmtCheck(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("15:04:05")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func shortKey(k string) string {
	const maxVisible = 13
	if len(k) <= maxVisible {
		return k
	}
	return k[:maxVisible] + "..."
}

// loadConfig loads a GlobalConfig from a URL (http/https) or a local file path.
func loadConfig(source string) (*liteclient.GlobalConfig, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return liteclient.GetConfigFromUrl(ctx, source)
	}
	return liteclient.GetConfigFromFile(source)
}

// ip4 converts a signed 32-bit integer packed into an int64/int to a dotted
// IPv4 string.  Both LS (int64) and DHT (int) fields use this representation.
func ip4(ipInt int64) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(int32(ipInt)))
	return net.IP(b).String()
}
