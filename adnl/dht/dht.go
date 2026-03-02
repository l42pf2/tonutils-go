package dht

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/keys"
	"github.com/xssnick/tonutils-go/tl"
	"reflect"
)

func init() {
	tl.Register(FindNode{}, "dht.findNode key:int256 k:int = dht.Nodes")
	tl.Register(FindValue{}, "dht.findValue key:int256 k:int = dht.ValueResult")
	tl.Register(SignedAddressListQuery{}, "dht.getSignedAddressList = dht.Node")
	tl.Register(Node{}, "dht.node id:PublicKey addr_list:adnl.addressList version:int signature:bytes = dht.Node")
	tl.Register(NodesList{}, "dht.nodes nodes:(vector dht.node) = dht.Nodes")
	tl.Register(ValueFoundResult{}, "dht.valueFound value:dht.Value = dht.ValueResult")
	tl.Register(ValueNotFoundResult{}, "dht.valueNotFound nodes:dht.nodes = dht.ValueResult")
	tl.Register(Value{}, "dht.value key:dht.keyDescription value:bytes ttl:int signature:bytes = dht.Value")
	tl.Register(Key{}, "dht.key id:int256 name:bytes idx:int = dht.Key")
	tl.Register(KeyDescription{}, "dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes = dht.KeyDescription")
	tl.Register(UpdateRuleSignature{}, "dht.updateRule.signature = dht.UpdateRule")
	tl.Register(UpdateRuleAnybody{}, "dht.updateRule.anybody = dht.UpdateRule")
	tl.Register(UpdateRuleOverlayNodes{}, "dht.updateRule.overlayNodes = dht.UpdateRule")
	tl.Register(Query{}, "dht.query node:dht.node = True")
	tl.Register(Store{}, "dht.store value:dht.value = dht.Stored")
	tl.Register(Stored{}, "dht.stored = dht.Stored")
	tl.Register(Ping{}, "dht.ping random_id:long = dht.Pong")
	tl.Register(Pong{}, "dht.pong random_id:long = dht.Pong")
	// adnl.node (no version/signature — distinct from dht.node)
	tl.Register(AdnlNode{}, "adnl.node id:PublicKey addr_list:adnl.addressList = adnl.Node")
	// Reverse connection messages
	tl.Register(RegisterReverseConnection{}, "dht.registerReverseConnection node:PublicKey ttl:int signature:bytes = dht.Stored")
	tl.Register(RequestReversePing{}, "dht.requestReversePing target:adnl.Node signature:bytes client:int256 k:int = dht.ReversePingResult")
	tl.Register(ReversePingOk{}, "dht.reversePingOk = dht.ReversePingResult")
	tl.Register(ClientNotFound{}, "dht.clientNotFound nodes:dht.nodes = dht.ReversePingResult")
	tl.Register(RequestReversePingCont{}, "dht.requestReversePingCont target:adnl.Node signature:bytes client:int256 = dht.RequestReversePingCont")
}

type FindNode struct {
	Key []byte `tl:"int256"`
	K   int32  `tl:"int"`
}

type FindValue struct {
	Key []byte `tl:"int256"`
	K   int32  `tl:"int"`
}

type ValueFoundResult struct {
	Value Value `tl:"struct boxed"`
}

type ValueNotFoundResult struct {
	Nodes NodesList `tl:"struct"`
}

type Value struct {
	KeyDescription KeyDescription `tl:"struct"`
	Data           []byte         `tl:"bytes"`
	TTL            int32          `tl:"int"`
	Signature      []byte         `tl:"bytes"`
}

type Key struct {
	ID    []byte `tl:"int256"`
	Name  []byte `tl:"bytes"`
	Index int32  `tl:"int"`
}

type KeyDescription struct {
	Key        Key    `tl:"struct"`
	ID         any    `tl:"struct boxed [pub.ed25519,pub.aes,pub.unenc,pub.overlay]"`
	UpdateRule any    `tl:"struct boxed [dht.updateRule.signature,dht.updateRule.anybody,dht.updateRule.overlayNodes]"`
	Signature  []byte `tl:"bytes"`
}

type SignedAddressListQuery struct{}

type Node struct {
	ID        any           `tl:"struct boxed [pub.ed25519,pub.aes]"`
	AddrList  *address.List `tl:"struct"`
	Version   int32         `tl:"int"`
	Signature []byte        `tl:"bytes"`
}

type NodesList struct {
	List []*Node `tl:"vector struct"`
}

type UpdateRuleSignature struct{}
type UpdateRuleAnybody struct{}
type UpdateRuleOverlayNodes struct{}

type Query struct {
	Node *Node `tl:"struct"`
}

type Store struct {
	Value *Value `tl:"struct"`
}

type Stored struct{}

type Ping struct {
	ID int64 `tl:"long"`
}

type Pong struct {
	ID int64 `tl:"long"`
}

// AdnlNode is adnl.node — a bare ADNL peer descriptor (no version/signature).
// Used as the target field in reverse-ping messages.
type AdnlNode struct {
	ID       any           `tl:"struct boxed [pub.ed25519,pub.aes]"`
	AddrList *address.List `tl:"struct"`
}

// RegisterReverseConnection asks a DHT node to store a reverse-connection entry
// so that third parties can ask it to relay a ping back to the registering client.
// Signature = ed25519.Sign(clientKey, clientID(32) + dhtServerID(32) + ttl(4 LE))
type RegisterReverseConnection struct {
	Node      any    `tl:"struct boxed [pub.ed25519,pub.aes]"`
	TTL       int32  `tl:"int"`
	Signature []byte `tl:"bytes"`
}

// RequestReversePing asks the DHT node that holds a reverse-connection entry for
// `client` to forward a ping from `target` to that client.
// Signature = ed25519.Sign(targetKey, TL-serialize(target, boxed))
type RequestReversePing struct {
	Target    any    `tl:"struct boxed [adnl.node]"`
	Signature []byte `tl:"bytes"`
	Client    []byte `tl:"int256"`
	K         int32  `tl:"int"`
}

// ReversePingOk is returned when requestReversePing forwarding succeeded.
type ReversePingOk struct{}

// ClientNotFound is returned when no reverse-connection entry is found for the
// requested client; the caller should try the returned nearest nodes instead.
type ClientNotFound struct {
	Nodes NodesList `tl:"struct"`
}

// RequestReversePingCont is an ADNL custom message (not a query) forwarded by
// the DHT relay node to the registered client, asking it to connect to target.
type RequestReversePingCont struct {
	Target    any    `tl:"struct boxed [adnl.node]"`
	Signature []byte `tl:"bytes"`
	Client    []byte `tl:"int256"`
}

func (n *Node) CheckSignature() error {
	pub, ok := n.ID.(keys.PublicKeyED25519)
	if !ok {
		return fmt.Errorf("unsupported id type %s", reflect.TypeOf(n.ID).String())
	}

	rawSig := n.Signature
	// Extended format: [4 bytes network_id LE][64 bytes ed25519 sig] = 68 bytes total.
	// Standard format: 64 bytes (network_id == -1, i.e. any network).
	var sig []byte
	switch len(rawSig) {
	case 64:
		sig = rawSig
	case 68:
		sig = rawSig[4:] // strip 4-byte network_id prefix
	default:
		return fmt.Errorf("invalid signature length %d (expected 64 or 68)", len(rawSig))
	}

	n.Signature = nil
	toVerify, err := tl.Serialize(n, true)
	n.Signature = rawSig // always restore before returning
	if err != nil {
		return fmt.Errorf("failed to serialize node: %w", err)
	}
	if !ed25519.Verify(pub.Key, toVerify, sig) {
		return fmt.Errorf("bad signature for node: %s", hex.EncodeToString(pub.Key))
	}
	return nil
}
