package dht

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	_MaxValues  = 100000
	_MaxTTL     = int64(3600 + 60) // seconds
	_MaxValueSz = 768              // bytes
)

// ServerGateway is the subset of adnl.Gateway methods required by the DHT server.
type ServerGateway interface {
	SetConnectionHandler(handler func(client adnl.Peer) error)
	GetAddressList() address.List
	GetID() []byte
}

// storedValue holds a DHT value together with its expiry timestamp.
type storedValue struct {
	value     Value
	expiresAt int64
}

// Server is a DHT node that responds to incoming DHT queries from other peers.
// It handles Ping, FindNode, FindValue, Store and GetSignedAddressList requests.
// It reuses a Client for the routing table so that the same Gateway can act as
// both a DHT client (outgoing lookups) and a DHT server (incoming requests).
type Server struct {
	client  *Client
	gateway ServerGateway
	key     ed25519.PrivateKey
	ourNode *Node

	values   map[string]*storedValue
	valuesMx sync.RWMutex

	globalCtx       context.Context
	globalCtxCancel func()
}

// NewServer creates a DHT server that listens for incoming DHT queries via gateway.
// client is used for routing-table lookups when answering FindNode / FindValue.
// key is the server's own ed25519 private key; it is used to sign the node descriptor
// returned by GetSignedAddressList.
func NewServer(gateway ServerGateway, client *Client, key ed25519.PrivateKey) (*Server, error) {
	ourNode, err := buildSignedNode(key, gateway.GetAddressList())
	if err != nil {
		return nil, fmt.Errorf("failed to build signed node: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		client:          client,
		gateway:         gateway,
		key:             key,
		ourNode:         ourNode,
		values:          make(map[string]*storedValue),
		globalCtx:       ctx,
		globalCtxCancel: cancel,
	}

	gateway.SetConnectionHandler(func(peer adnl.Peer) error {
		peer.SetQueryHandler(func(msg *adnl.MessageQuery) error {
			return s.handleQuery(peer, msg)
		})
		return nil
	})

	go s.startPeriodicTasks()
	return s, nil
}

// buildSignedNode constructs a signed dht.Node for the given key and address list.
func buildSignedNode(key ed25519.PrivateKey, addrList address.List) (*Node, error) {
	pub := key.Public().(ed25519.PublicKey)

	node := &Node{
		ID:        keys.PublicKeyED25519{Key: pub},
		AddrList:  &addrList,
		Version:   int32(time.Now().Unix()),
		Signature: nil,
	}

	data, err := tl.Serialize(node, true)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize node: %w", err)
	}

	node.Signature = ed25519.Sign(key, data)
	return node, nil
}

// handleQuery dispatches an incoming ADNL query to the appropriate DHT handler.
func (s *Server) handleQuery(peer adnl.Peer, msg *adnl.MessageQuery) error {
	ctx := context.Background()

	switch q := msg.Data.(type) {
	case Ping:
		return peer.Answer(ctx, msg.ID, Pong{ID: q.ID})
	case FindNode:
		return s.handleFindNode(ctx, peer, msg.ID, q)
	case FindValue:
		return s.handleFindValue(ctx, peer, msg.ID, q)
	case Store:
		return s.handleStore(ctx, peer, msg.ID, q)
	case SignedAddressListQuery:
		return peer.Answer(ctx, msg.ID, s.ourNode)
	default:
		return fmt.Errorf("unsupported DHT query type: %T", msg.Data)
	}
}

// handleFindNode returns up to K nearest known nodes to the requested key.
func (s *Server) handleFindNode(ctx context.Context, peer adnl.Peer, queryID []byte, req FindNode) error {
	k := int(req.K)
	if k <= 0 || k > _K*2 {
		k = _K
	}

	nodes := s.client.GetNearestNodes(req.Key, k)
	return peer.Answer(ctx, queryID, NodesList{List: nodes})
}

// handleFindValue returns the stored value if found; otherwise the nearest nodes.
func (s *Server) handleFindValue(ctx context.Context, peer adnl.Peer, queryID []byte, req FindValue) error {
	keyID := hex.EncodeToString(req.Key)

	s.valuesMx.RLock()
	sv, ok := s.values[keyID]
	s.valuesMx.RUnlock()

	if ok && time.Now().Unix() < sv.expiresAt {
		return peer.Answer(ctx, queryID, ValueFoundResult{Value: sv.value})
	}

	k := int(req.K)
	if k <= 0 || k > _K*2 {
		k = _K
	}

	nodes := s.client.GetNearestNodes(req.Key, k)
	return peer.Answer(ctx, queryID, ValueNotFoundResult{Nodes: NodesList{List: nodes}})
}

// handleStore validates and stores the given DHT value.
func (s *Server) handleStore(ctx context.Context, peer adnl.Peer, queryID []byte, req Store) error {
	if req.Value == nil {
		return fmt.Errorf("nil value in store request")
	}

	if len(req.Value.Data) > _MaxValueSz {
		return fmt.Errorf("value data too large: %d > %d", len(req.Value.Data), _MaxValueSz)
	}

	now := time.Now().Unix()
	ttl := int64(req.Value.TTL)

	if ttl <= now {
		return fmt.Errorf("value already expired")
	}
	if ttl > now+_MaxTTL {
		return fmt.Errorf("TTL too large")
	}

	keyID, err := tl.Hash(req.Value.KeyDescription.Key)
	if err != nil {
		return fmt.Errorf("failed to hash key: %w", err)
	}

	if err := checkValue(keyID, req.Value); err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}

	keyIDStr := hex.EncodeToString(keyID)

	s.valuesMx.Lock()
	if len(s.values) < _MaxValues {
		existing, has := s.values[keyIDStr]
		if !has || s.shouldReplace(existing, req.Value) {
			s.values[keyIDStr] = &storedValue{
				value:     *req.Value,
				expiresAt: ttl,
			}
		}
	}
	s.valuesMx.Unlock()

	return peer.Answer(ctx, queryID, Stored{})
}

// shouldReplace decides whether a new value should overwrite an existing one.
// For UpdateRuleSignature, we accept only if the new TTL is higher (prevents rollback).
// For all other rules, we always accept.
func (s *Server) shouldReplace(existing *storedValue, incoming *Value) bool {
	switch existing.value.KeyDescription.UpdateRule.(type) {
	case UpdateRuleSignature:
		return int64(incoming.TTL) > existing.expiresAt
	default:
		return true
	}
}

// startPeriodicTasks runs background maintenance every second:
//   - cleanupExpiredValues: removes TTL-expired entries from the value store.
//   - fillRoutingTable: immediately on start (self-lookup), then every ~10 s with a random key.
func (s *Server) startPeriodicTasks() {
	// Kademlia bootstrap: look up our own ID first so that nearby peers learn about us
	// and we populate the routing table with nodes that are XOR-close to us.
	go s.fillRoutingTableWithID(s.gateway.GetID())

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastFill := time.Now()

	for {
		select {
		case <-s.globalCtx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredValues()

			if time.Since(lastFill) > 10*time.Second {
				lastFill = time.Now()
				go s.fillRoutingTable()
			}
		}
	}
}

// cleanupExpiredValues removes all values whose TTL has passed.
func (s *Server) cleanupExpiredValues() {
	now := time.Now().Unix()

	s.valuesMx.Lock()
	for k, v := range s.values {
		if v.expiresAt <= now {
			delete(s.values, k)
		}
	}
	s.valuesMx.Unlock()
}

// fillRoutingTable performs a lookup for a random key to discover new nodes.
func (s *Server) fillRoutingTable() {
	randID := make([]byte, 32)
	if _, err := rand.Read(randID); err != nil {
		return
	}
	s.fillRoutingTableWithID(randID)
}

// fillRoutingTableWithID performs a FindValue lookup for id.
// The lookup always "fails" (no value stored), but the iterative Kademlia search
// populates the routing table with newly discovered nodes as a side-effect.
func (s *Server) fillRoutingTableWithID(id []byte) {
	ctx, cancel := context.WithTimeout(s.globalCtx, 5*time.Second)
	defer cancel()

	_, _, _ = s.client.FindValue(ctx, &Key{
		ID:    id,
		Name:  []byte("address"),
		Index: 0,
	})
}

// Close stops the server's background goroutines.
func (s *Server) Close() {
	s.globalCtxCancel()
}
