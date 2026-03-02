package dht

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
)

const (
	_MaxValues      = 100000
	_MaxTTL         = int64(3600 + 60) // seconds
	_MaxValueSz     = 768              // bytes
	_MaxRevConns    = 100000
	_MaxRevConnTTL  = int64(300) // seconds (from C++ implementation)
	_PingInterval   = 60 * time.Second
	_RepublishEvery = 10 * time.Second
	_FillEvery      = 10 * time.Second
)

// ServerGateway is the subset of adnl.Gateway methods required by the DHT server.
type ServerGateway interface {
	SetConnectionHandler(handler func(client adnl.Peer) error)
	GetAddressList() address.List
	GetID() []byte
	RegisterClient(addr string, key ed25519.PublicKey) (adnl.Peer, error)
}

// storedValue holds a DHT value together with its expiry timestamp.
type storedValue struct {
	value     Value
	expiresAt int64
}

// reverseConn is an entry in the reverse-connection table. It records which
// ADNL peer registered a client for reverse-ping forwarding and when it expires.
type reverseConn struct {
	peerAddr  string
	peerKey   ed25519.PublicKey
	expiresAt int64
}

// Server is a DHT node that responds to incoming DHT queries from other peers.
// It handles Ping, FindNode, FindValue, Store, GetSignedAddressList,
// RegisterReverseConnection and RequestReversePing requests.
// It reuses a Client for the routing table so that the same Gateway can act as
// both a DHT client (outgoing lookups) and a DHT server (incoming requests).
type Server struct {
	client    *Client
	gateway   ServerGateway
	key       ed25519.PrivateKey
	ourNode   *Node
	networkID int32 // -1 = any network (default mainnet behaviour)

	values   map[string]*storedValue
	valuesMx sync.RWMutex

	// ourValues holds values this server wants to keep alive in the DHT.
	// They are republished periodically even if their TTL is not renewed externally.
	ourValues   map[string]*Value
	ourValuesMx sync.RWMutex

	// reverseConns maps hex(clientID) → connection info for registered reverse peers.
	reverseConns   map[string]*reverseConn
	reverseConnsMx sync.RWMutex

	// ourReverseConns is the set of clientIDs for which THIS server acts as the
	// NAT-traversal client (registered via RegisterAsReverseConnection).
	ourReverseConns   map[string]struct{}
	ourReverseConnsMx sync.RWMutex

	globalCtx       context.Context
	globalCtxCancel func()
}

// NewServer creates a DHT server that listens for incoming DHT queries via gateway.
// client is used for routing-table lookups when answering FindNode / FindValue.
// key is the server's own ed25519 private key used to sign the node descriptor.
// networkID distinguishes private networks; use -1 for the default public network.
func NewServer(gateway ServerGateway, client *Client, key ed25519.PrivateKey, networkID int32) (*Server, error) {
	ourNode, err := buildSignedNode(key, gateway.GetAddressList(), networkID)
	if err != nil {
		return nil, fmt.Errorf("failed to build signed node: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		client:          client,
		gateway:         gateway,
		key:             key,
		ourNode:         ourNode,
		networkID:       networkID,
		values:          make(map[string]*storedValue),
		ourValues:       make(map[string]*Value),
		reverseConns:    make(map[string]*reverseConn),
		ourReverseConns: make(map[string]struct{}),
		globalCtx:       ctx,
		globalCtxCancel: cancel,
	}

	gateway.SetConnectionHandler(func(peer adnl.Peer) error {
		peer.SetQueryHandler(func(msg *adnl.MessageQuery) error {
			return s.handleQuery(peer, msg)
		})
		peer.SetCustomMessageHandler(func(msg *adnl.MessageCustom) error {
			return s.handleCustomMessage(msg)
		})
		return nil
	})

	logNodeDescriptor(ourNode)
	go s.startPeriodicTasks()
	return s, nil
}

// buildSignedNode constructs a signed dht.Node for the given key, address list and network ID.
// When networkID != -1 the signature is extended with a 4-byte LE network_id prefix so that
// nodes from different networks cannot impersonate each other (matches C++ dht-node.cpp).
func buildSignedNode(key ed25519.PrivateKey, addrList address.List, networkID int32) (*Node, error) {
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

	sig := ed25519.Sign(key, data)
	if networkID != -1 {
		// Extended format: [4 bytes network_id LE][64 bytes ed25519 sig]
		extended := make([]byte, 68)
		binary.LittleEndian.PutUint32(extended[:4], uint32(networkID))
		copy(extended[4:], sig)
		node.Signature = extended
	} else {
		node.Signature = sig
	}

	return node, nil
}

// logNodeDescriptor prints the node descriptor in the global.config.json dht.staticNodes format
// so operators can copy-paste it into the network configuration file.
func logNodeDescriptor(node *Node) {
	pub, ok := node.ID.(keys.PublicKeyED25519)
	if !ok {
		return
	}

	type addrJSON struct {
		Type string `json:"@type"`
		IP   int32  `json:"ip"`
		Port int32  `json:"port"`
	}
	type addrListJSON struct {
		Type       string     `json:"@type"`
		Addrs      []addrJSON `json:"addrs"`
		Version    int32      `json:"version"`
		ReinitDate int32      `json:"reinit_date"`
		Priority   int32      `json:"priority"`
		ExpireAt   int32      `json:"expire_at"`
	}
	type idJSON struct {
		Type string `json:"@type"`
		Key  string `json:"key"`
	}
	type nodeJSON struct {
		Type      string       `json:"@type"`
		ID        idJSON       `json:"id"`
		AddrList  addrListJSON `json:"addr_list"`
		Version   int32        `json:"version"`
		Signature string       `json:"signature"`
	}

	var addrs []addrJSON
	for _, udp := range node.AddrList.Addresses {
		if udp == nil {
			continue
		}
		ip4 := udp.IP.To4()
		if ip4 == nil {
			continue
		}
		// TON global.config.json stores IP as a signed 32-bit big-endian integer.
		ipInt := int32(binary.BigEndian.Uint32(ip4))
		addrs = append(addrs, addrJSON{
			Type: "adnl.address.udp",
			IP:   ipInt,
			Port: udp.Port,
		})
	}

	n := nodeJSON{
		Type: "dht.node",
		ID: idJSON{
			Type: "pub.ed25519",
			Key:  base64.StdEncoding.EncodeToString(pub.Key),
		},
		AddrList: addrListJSON{
			Type:       "adnl.addressList",
			Addrs:      addrs,
			Version:    node.AddrList.Version,
			ReinitDate: node.AddrList.ReinitDate,
			Priority:   node.AddrList.Priority,
			ExpireAt:   node.AddrList.ExpireAt,
		},
		Version:   node.Version,
		Signature: base64.StdEncoding.EncodeToString(node.Signature),
	}

	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		Logger("DHT server: failed to marshal node descriptor:", err)
		return
	}
	Logger("DHT server started. Node descriptor for global.config.json (dht.staticNodes.nodes entry):\n" + string(data))
}

// RegisterValue registers a DHT value that this server should keep alive by
// republishing it to the network every ~10 seconds.
func (s *Server) RegisterValue(val *Value) error {
	keyID, err := tl.Hash(val.KeyDescription.Key)
	if err != nil {
		return fmt.Errorf("failed to hash key: %w", err)
	}
	if err := checkValue(keyID, val); err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}
	s.ourValuesMx.Lock()
	s.ourValues[hex.EncodeToString(keyID)] = val
	s.ourValuesMx.Unlock()
	return nil
}

// RegisterAsReverseConnection publishes a reverse-connection registration to
// nearby DHT nodes so that third parties can ask those nodes to relay a ping
// to this server (NAT traversal). clientKey is the ed25519 key identifying
// this server in the DHT; ttl should be ≤ 300 seconds.
func (s *Server) RegisterAsReverseConnection(clientKey ed25519.PrivateKey, ttl time.Duration) error {
	pub := clientKey.Public().(ed25519.PublicKey)
	clientID, err := tl.Hash(keys.PublicKeyED25519{Key: pub})
	if err != nil {
		return fmt.Errorf("failed to compute client ID: %w", err)
	}

	clientIDStr := hex.EncodeToString(clientID)
	s.ourReverseConnsMx.Lock()
	s.ourReverseConns[clientIDStr] = struct{}{}
	s.ourReverseConnsMx.Unlock()

	ttlUnix := int32(time.Now().Add(ttl).Unix())

	// to_sign: clientID (32) + serverID (32) + ttl (4 bytes LE)
	toSign := make([]byte, 68)
	copy(toSign[:32], clientID)
	copy(toSign[32:64], s.gateway.GetID())
	binary.LittleEndian.PutUint32(toSign[64:68], uint32(ttlUnix))

	sig := ed25519.Sign(clientKey, toSign)
	req, err := tl.Serialize(RegisterReverseConnection{
		Node:      keys.PublicKeyED25519{Key: pub},
		TTL:       ttlUnix,
		Signature: sig,
	}, true)
	if err != nil {
		return fmt.Errorf("failed to serialize register request: %w", err)
	}

	reverseKeyID, err := reverseConnectionKeyID(clientID)
	if err != nil {
		return fmt.Errorf("failed to compute reverse key ID: %w", err)
	}

	plist := s.client.buildPriorityList(reverseKeyID)
	sent := 0
	for {
		node, _ := plist.Get()
		if node == nil || sent >= _K {
			break
		}
		sent++
		n := node
		go func() {
			ctx, cancel := context.WithTimeout(s.globalCtx, queryTimeout)
			defer cancel()
			var res any
			_ = n.query(ctx, tl.Raw(req), &res)
		}()
	}
	return nil
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
	case RegisterReverseConnection:
		return s.handleRegisterReverseConnection(ctx, peer, msg.ID, q)
	case RequestReversePing:
		return s.handleRequestReversePing(ctx, peer, msg.ID, q)
	default:
		return fmt.Errorf("unsupported DHT query type: %T", msg.Data)
	}
}

// handleCustomMessage processes incoming ADNL custom (non-query) messages.
// msg.Data is already parsed by the TL layer into a Go value; we just type-assert.
// Currently only RequestReversePingCont is handled; everything else is ignored.
func (s *Server) handleCustomMessage(msg *adnl.MessageCustom) error {
	cont, ok := msg.Data.(RequestReversePingCont)
	if !ok {
		return nil // not a recognised message; ignore silently
	}
	return s.handleRequestReversePingCont(cont)
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
// For UpdateRuleSignature we only accept a higher TTL (prevents rollback attacks).
func (s *Server) shouldReplace(existing *storedValue, incoming *Value) bool {
	switch existing.value.KeyDescription.UpdateRule.(type) {
	case UpdateRuleSignature:
		return int64(incoming.TTL) > existing.expiresAt
	default:
		return true
	}
}

// handleRegisterReverseConnection stores a reverse-connection entry so that
// future requestReversePing queries can be forwarded to the registering peer.
//
// The request must carry a valid signature over:
//
//	clientID (32 bytes) + thisServerID (32 bytes) + TTL (4 bytes LE)
func (s *Server) handleRegisterReverseConnection(ctx context.Context, peer adnl.Peer, queryID []byte, req RegisterReverseConnection) error {
	pub, ok := req.Node.(keys.PublicKeyED25519)
	if !ok {
		return fmt.Errorf("unsupported key type in registerReverseConnection")
	}

	clientID, err := tl.Hash(pub)
	if err != nil {
		return fmt.Errorf("failed to hash client key: %w", err)
	}

	now := time.Now().Unix()
	ttl := int64(req.TTL)
	if ttl <= now {
		return fmt.Errorf("reverse connection TTL already expired")
	}
	if ttl > now+_MaxRevConnTTL {
		ttl = now + _MaxRevConnTTL
	}

	// Verify: clientID (32) + peerID (32) + ttl (4 LE) signed with client's key.
	// "peerID" is the ADNL ID of the sender as seen by us (= peer.GetID()),
	// matching the C++ `src` parameter in register_reverse_connection_to_sign().
	toSign := make([]byte, 68)
	copy(toSign[:32], clientID)
	copy(toSign[32:64], peer.GetID())
	binary.LittleEndian.PutUint32(toSign[64:68], uint32(req.TTL))

	if !ed25519.Verify(pub.Key, toSign, req.Signature) {
		return fmt.Errorf("invalid reverse connection signature")
	}

	clientIDStr := hex.EncodeToString(clientID)
	s.reverseConnsMx.Lock()
	if len(s.reverseConns) < _MaxRevConns {
		s.reverseConns[clientIDStr] = &reverseConn{
			peerAddr:  peer.RemoteAddr(),
			peerKey:   peer.GetPubKey(),
			expiresAt: ttl,
		}
	}
	s.reverseConnsMx.Unlock()

	return peer.Answer(ctx, queryID, Stored{})
}

// handleRequestReversePing either forwards a reverse-ping continuation to the
// registered proxy peer, or returns the nearest known nodes to the client's key.
func (s *Server) handleRequestReversePing(ctx context.Context, peer adnl.Peer, queryID []byte, req RequestReversePing) error {
	clientIDStr := hex.EncodeToString(req.Client)

	s.reverseConnsMx.RLock()
	rc, found := s.reverseConns[clientIDStr]
	s.reverseConnsMx.RUnlock()

	if found && time.Now().Unix() < rc.expiresAt {
		// Verify that the target signed its own adnl.node descriptor.
		targetData, err := tl.Serialize(req.Target, true)
		if err != nil {
			return fmt.Errorf("failed to serialize target: %w", err)
		}
		targetNode, ok := req.Target.(AdnlNode)
		if !ok {
			return fmt.Errorf("unexpected target type %T", req.Target)
		}
		targetPub, ok := targetNode.ID.(keys.PublicKeyED25519)
		if !ok {
			return fmt.Errorf("unsupported target key type")
		}
		if !ed25519.Verify(targetPub.Key, targetData, req.Signature) {
			return fmt.Errorf("invalid target signature in requestReversePing")
		}

		// Answer OK immediately, then forward asynchronously.
		if err := peer.Answer(ctx, queryID, ReversePingOk{}); err != nil {
			return err
		}

		go s.forwardReversePingCont(rc, req)
		return nil
	}

	// Client not found locally — return the nearest nodes to its reverse-slot key.
	reverseKeyID, err := reverseConnectionKeyID(req.Client)
	if err != nil {
		return fmt.Errorf("failed to compute reverse key ID: %w", err)
	}
	k := int(req.K)
	if k <= 0 || k > _K*2 {
		k = _K
	}
	nodes := s.client.GetNearestNodes(reverseKeyID, k)
	return peer.Answer(ctx, queryID, ClientNotFound{Nodes: NodesList{List: nodes}})
}

// forwardReversePingCont connects to the registered proxy peer and sends it a
// RequestReversePingCont custom message so it can punch a hole to the target.
func (s *Server) forwardReversePingCont(rc *reverseConn, req RequestReversePing) {
	conn, err := s.gateway.RegisterClient(rc.peerAddr, rc.peerKey)
	if err != nil {
		Logger("DHT server: requestReversePing: failed to connect to proxy peer:", err)
		return
	}

	cont := RequestReversePingCont{
		Target:    req.Target,
		Signature: req.Signature,
		Client:    req.Client,
	}
	sendCtx, cancel := context.WithTimeout(s.globalCtx, 3*time.Second)
	defer cancel()
	if err := conn.SendCustomMessage(sendCtx, cont); err != nil {
		Logger("DHT server: requestReversePing: failed to forward cont:", err)
	}
}

// handleRequestReversePingCont is called when we receive a forwarded reverse-ping
// continuation message. We verify the target's signature and then connect to it,
// triggering the UDP hole-punch from our side.
func (s *Server) handleRequestReversePingCont(cont RequestReversePingCont) error {
	clientIDStr := hex.EncodeToString(cont.Client)

	s.ourReverseConnsMx.RLock()
	_, isOurs := s.ourReverseConns[clientIDStr]
	s.ourReverseConnsMx.RUnlock()

	if !isOurs {
		Logger("DHT server: requestReversePingCont: unknown client ID:", clientIDStr)
		return nil
	}

	targetNode, ok := cont.Target.(AdnlNode)
	if !ok {
		return nil
	}
	targetPub, ok := targetNode.ID.(keys.PublicKeyED25519)
	if !ok {
		return nil
	}

	// Verify the target signed its own adnl.node descriptor.
	targetData, err := tl.Serialize(cont.Target, true)
	if err != nil {
		return nil
	}
	if !ed25519.Verify(targetPub.Key, targetData, cont.Signature) {
		Logger("DHT server: requestReversePingCont: invalid target signature")
		return nil
	}

	if targetNode.AddrList == nil || len(targetNode.AddrList.Addresses) == 0 {
		return nil
	}
	var targetAddr string
	for _, udp := range targetNode.AddrList.Addresses {
		if udp == nil {
			continue
		}
		targetAddr = fmt.Sprintf("%s:%d", udp.IP.String(), udp.Port)
		break
	}
	if targetAddr == "" {
		return nil
	}

	// Connect and send an empty message to trigger the UDP hole-punch.
	go func() {
		conn, err := s.client.gateway.RegisterClient(targetAddr, targetPub.Key)
		if err != nil {
			Logger("DHT server: requestReversePingCont: failed to connect to target:", err)
			return
		}
		pingCtx, cancel := context.WithTimeout(s.globalCtx, 3*time.Second)
		defer cancel()
		_ = conn.SendCustomMessage(pingCtx, tl.Raw([]byte{}))
	}()

	return nil
}

// startPeriodicTasks runs background maintenance:
//   - cleanupExpiredValues: removes TTL-expired entries from the value store.
//   - cleanupExpiredReverseConns: removes expired reverse-connection entries.
//   - republishOurValues: re-stores values this server owns (~10 s interval).
//   - fillRoutingTable: Kademlia random-key lookups to keep buckets full (~10 s).
//   - pingKnownNodes: active pings to maintain routing-table health (~60 s).
func (s *Server) startPeriodicTasks() {
	// Bootstrap: look up our own ID first so nearby peers learn about us.
	go s.fillRoutingTableWithID(s.gateway.GetID())

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastFill := time.Now()
	lastRepublish := time.Now()
	lastPing := time.Now()

	for {
		select {
		case <-s.globalCtx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredValues()
			s.cleanupExpiredReverseConns()

			if time.Since(lastFill) > _FillEvery {
				lastFill = time.Now()
				go s.fillRoutingTable()
			}
			if time.Since(lastRepublish) > _RepublishEvery {
				lastRepublish = time.Now()
				go s.republishOurValues()
			}
			if time.Since(lastPing) > _PingInterval {
				lastPing = time.Now()
				go s.pingKnownNodes()
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

// cleanupExpiredReverseConns removes all reverse-connection entries that have expired.
func (s *Server) cleanupExpiredReverseConns() {
	now := time.Now().Unix()
	s.reverseConnsMx.Lock()
	for k, v := range s.reverseConns {
		if v.expiresAt <= now {
			delete(s.reverseConns, k)
		}
	}
	s.reverseConnsMx.Unlock()
}

// republishOurValues sends each registered "our value" to the nearest DHT nodes,
// keeping those values alive in the network even as their TTL approaches.
// Only values with more than 60 seconds remaining are republished (matching C++).
func (s *Server) republishOurValues() {
	now := time.Now().Unix()

	s.ourValuesMx.RLock()
	vals := make([]*Value, 0, len(s.ourValues))
	for _, v := range s.ourValues {
		if int64(v.TTL) > now+60 {
			vals = append(vals, v)
		}
	}
	s.ourValuesMx.RUnlock()

	for _, v := range vals {
		val := v
		go s.republishValue(val)
	}
}

// republishValue stores a single value on the nearest known DHT nodes.
func (s *Server) republishValue(val *Value) {
	keyID, err := tl.Hash(val.KeyDescription.Key)
	if err != nil {
		return
	}
	plist := s.client.buildPriorityList(keyID)
	var wg sync.WaitGroup
	for {
		node, _ := plist.Get()
		if node == nil {
			break
		}
		wg.Add(1)
		n := node
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(s.globalCtx, queryTimeout)
			defer cancel()
			_ = n.storeValue(ctx, keyID, val)
		}()
	}
	wg.Wait()
}

// pingKnownNodes sends a DHT ping to the top-K nodes in every Kademlia bucket.
// This keeps the routing table healthy by detecting failed nodes early.
func (s *Server) pingKnownNodes() {
	var wg sync.WaitGroup
	for _, bucket := range s.client.buckets {
		nodes := bucket.getNodes()
		limit := _K
		if limit > len(nodes) {
			limit = len(nodes)
		}
		for _, node := range nodes[:limit] {
			if node == nil {
				continue
			}
			wg.Add(1)
			n := node
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(s.globalCtx, queryTimeout)
				defer cancel()
				_ = n.doPing(ctx)
			}()
		}
	}
	wg.Wait()
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

// reverseConnectionKeyID computes the DHT key ID used to locate reverse-connection
// entries in the DHT. Matches C++ get_reverse_connection_key(client_id).compute_key_id().
func reverseConnectionKeyID(clientID []byte) ([]byte, error) {
	return tl.Hash(Key{
		ID:    clientID,
		Name:  []byte("reverse"),
		Index: 0,
	})
}

// Close stops the server's background goroutines.
func (s *Server) Close() {
	s.globalCtxCancel()
}
