package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/liteclient"
)

var (
	flagAddr    = flag.String("addr", "0.0.0.0:3278", "UDP listen address (host:port)")
	flagExtIP   = flag.String("ext-ip", "", "external IP to advertise in DHT (required when listening on 0.0.0.0)")
	flagKeyFile = flag.String("key", "dht-server.key", "path to ed25519 key file (auto-generated if not found)")
	flagConfig  = flag.String("config", "https://ton-blockchain.github.io/global.config.json", "TON global config URL or file path")
	flagVerbose = flag.Bool("v", false, "enable debug-level logging")
)

// keyStore is the on-disk format for the server's persistent ed25519 key.
type keyStore struct {
	PrivateKey string `json:"private_key"` // hex-encoded 64-byte ed25519 private key
}

func main() {
	flag.Parse()

	// ── logging ──────────────────────────────────────────────────────────────
	level := zerolog.InfoLevel
	if *flagVerbose {
		level = zerolog.DebugLevel
	}
	log.Logger = zerolog.New(zerolog.NewConsoleWriter()).
		With().Timestamp().Logger().
		Level(level)

	// Redirect internal ADNL / DHT debug loggers to zerolog.
	adnl.Logger = func(v ...any) {
		log.Debug().Msgf("%v", fmt.Sprint(v...))
	}
	dht.Logger = func(v ...any) {
		log.Debug().Msgf("%v", fmt.Sprint(v...))
	}

	// ── key ──────────────────────────────────────────────────────────────────
	privKey, created, err := loadOrGenerateKey(*flagKeyFile)
	if err != nil {
		log.Fatal().Err(err).Str("path", *flagKeyFile).Msg("failed to load key")
	}
	if created {
		log.Info().Str("path", *flagKeyFile).Msg("generated new ed25519 key")
	} else {
		log.Info().Str("path", *flagKeyFile).Msg("loaded existing ed25519 key")
	}

	// ── resolve listen address ────────────────────────────────────────────────
	host, portStr, err := net.SplitHostPort(*flagAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", *flagAddr).Msg("invalid listen address")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		log.Fatal().Err(err).Str("port", portStr).Msg("invalid port")
	}

	advertiseIP, err := resolveAdvertiseIP(host, *flagExtIP)
	if err != nil {
		log.Fatal().Err(err).Msg(err.Error())
	}

	// ── ADNL gateway ─────────────────────────────────────────────────────────
	gateway := adnl.NewGateway(privKey)

	addrList := []*address.UDP{
		{IP: advertiseIP, Port: int32(port)},
	}
	gateway.SetAddressList(addrList)

	if err = gateway.StartServer(*flagAddr); err != nil {
		log.Fatal().Err(err).Str("addr", *flagAddr).Msg("failed to start ADNL server")
	}
	log.Info().
		Str("listen", *flagAddr).
		Str("advertise", fmt.Sprintf("%s:%d", advertiseIP, port)).
		Msg("ADNL gateway started")

	// ── ADNL ID & public key ─────────────────────────────────────────────────
	pubKey := privKey.Public().(ed25519.PublicKey)
	log.Info().
		Str("adnl_id", hex.EncodeToString(gateway.GetID())).
		Str("pub_key", hex.EncodeToString(pubKey)).
		Msg("our node identity")

	// ── DHT client (bootstrap routing table) ─────────────────────────────────
	cfg, err := loadConfig(*flagConfig)
	if err != nil {
		log.Fatal().Err(err).Str("config", *flagConfig).Msg("failed to load TON config")
	}

	dhtClient, err := dht.NewClientFromConfig(gateway, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create DHT client")
	}
	log.Info().Int("bootstrap_nodes", len(cfg.DHT.StaticNodes.Nodes)).Msg("DHT client initialized")

	// ── DHT server ────────────────────────────────────────────────────────────
	dhtServer, err := dht.NewServer(gateway, dhtClient, privKey)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create DHT server")
	}
	log.Info().Msg("DHT server started — accepting queries")

	// ── periodic stats ────────────────────────────────────────────────────────
	go logStats(dhtClient)

	// ── wait for shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Info().Str("signal", sig.String()).Msg("shutting down")
	dhtServer.Close()
	log.Info().Msg("DHT server stopped")
}

// logStats periodically prints the number of peers known to the routing table.
func logStats(c *dht.Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		nodes := c.GetNodes()
		log.Info().Int("routing_table_peers", len(nodes)).Msg("stats")
	}
}

// resolveAdvertiseIP returns the IP address that will be advertised in DHT.
// If extIP is explicitly set, it is used. Otherwise, if the listen host is
// a specific (non-zero) address, that address is used. 0.0.0.0 requires extIP.
func resolveAdvertiseIP(listenHost, extIP string) (net.IP, error) {
	if extIP != "" {
		ip := net.ParseIP(extIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid -ext-ip value: %q", extIP)
		}
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return ip, nil
	}

	if listenHost == "" || listenHost == "0.0.0.0" {
		return nil, fmt.Errorf(
			"listening on 0.0.0.0 requires -ext-ip to specify the external IP address",
		)
	}

	ip := net.ParseIP(listenHost)
	if ip == nil {
		return nil, fmt.Errorf("cannot parse listen host %q as IP address", listenHost)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, nil
	}
	return ip, nil
}

// loadOrGenerateKey reads the key from path, or generates and saves a new one.
// Returns (key, wasCreated, error).
func loadOrGenerateKey(path string) (ed25519.PrivateKey, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var ks keyStore
		if err = json.Unmarshal(data, &ks); err != nil {
			return nil, false, fmt.Errorf("parse key file: %w", err)
		}
		raw, err := hex.DecodeString(ks.PrivateKey)
		if err != nil {
			return nil, false, fmt.Errorf("decode private key hex: %w", err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, false, fmt.Errorf("invalid key length %d (expected %d)", len(raw), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(raw), false, nil
	}

	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("read key file: %w", err)
	}

	// Generate new key.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, false, fmt.Errorf("generate key: %w", err)
	}

	ks := keyStore{PrivateKey: hex.EncodeToString(priv)}
	data, err = json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("marshal key: %w", err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		return nil, false, fmt.Errorf("save key file: %w", err)
	}
	return priv, true, nil
}

// loadConfig loads a GlobalConfig from a URL (http/https) or a local file path.
func loadConfig(source string) (*liteclient.GlobalConfig, error) {
	if len(source) >= 4 && source[:4] == "http" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return liteclient.GetConfigFromUrl(ctx, source)
	}
	return liteclient.GetConfigFromFile(source)
}
